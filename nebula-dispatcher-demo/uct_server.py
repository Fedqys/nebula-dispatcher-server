#!/usr/bin/env python3
"""
Nebula Dispatcher - Ubuntu CVE Tracker Visualizer

Serves a single interactive HTML page with tabs for main/universe/multiverse/restricted.
Computes 3D spring layout positions server-side with NetworkX.
Renders with Plotly.js on the client.
Watches UCT active/ for changes and auto-refreshes.

Usage:
    python3 uct_server.py [--uct-path /path/to/uct] [--port 8765]
"""

import argparse
import gzip
import json
import math
import multiprocessing
import os
import random
import re
import sys
import time
import threading
import urllib.request as urllibreq
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

import networkx as nx

PRIORITY_SCORES = {
    "critical": 5, "high": 4, "medium": 3,
    "low": 2, "negligible": 1, "untriaged": 3,
}
PRIORITY_COLORS = {
    "critical": "#ff1744", "high": "#ff6d00", "medium": "#ffd600",
    "low": "#00e676", "negligible": "#b0bec5", "untriaged": "#448aff",
}
SEVERITY_COLORS = {
    "critical": "#ff1744", "high": "#ff6d00", "medium": "#ffd600",
    "low": "#00e676", "negligible": "#b0bec5",
}
SEVERITY_THRESHOLDS = [
    (0.75, "critical"),
    (0.55, "high"),
    (0.35, "medium"),
    (0.20, "low"),
    (0.0,  "negligible"),
]
STATUS_OPEN = frozenset({"needs-triage", "needed", "in-progress", "pending", "deferred"})
COMPONENTS = ["main", "universe", "multiverse", "restricted", "esm-apps", "esm-infra"]

LINUX_PFX = ("linux-", "linux_")
LINUX_EXACT = frozenset({
    "linux", "linux-lts-xenial", "linux-lts-wily", "linux-lts-utopic",
    "linux-lts-trusty", "linux-lts-quantal", "linux-lts-raring",
    "linux-lts-saucy", "linux-source-2.6.15", "linux-ti-omap",
    "linux-linaro", "linux-qcm-msm", "linux-ec2",
    "linux-fsl-imx51", "linux-mvl-dove",
})


_CVSS_RE = re.compile(r"(.+?):\s+(\S+)(?:\s+\[(\S+)\s+(\S+)\])?")


# ── CVE file parser ───────────────────────────────────────────────────────
def _load_cve_file(cve_path):
    """Parse a UCT active/CVE-* file, returning a dict compatible with
    what cve_lib.load_cve() used to produce."""
    with open(cve_path, encoding="utf-8") as fh:
        lines = fh.readlines()

    data = {"tags": {}, "pkgs": {}, "patches": {}}
    cvss_entries = []
    priority_reason = {}
    last_field = ""
    pkg = None

    for line in lines:
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue

        if line.startswith(" "):
            stripped = line[1:]
            if last_field.startswith("Priority"):
                key = last_field.split("_", 1)[1] if "_" in last_field else None
                priority_reason.setdefault(key, []).append(stripped)
            elif last_field == "CVSS":
                m = _CVSS_RE.match(stripped)
                if m:
                    cvss = {"source": m.group(1).strip(),
                            "vector": m.group(2).strip()}
                    if m.group(3):
                        cvss["baseScore"] = m.group(3)
                        cvss["baseSeverity"] = m.group(4)
                    cvss_entries.append(cvss)
            elif last_field.startswith("Patches_"):
                try:
                    ptype, entry = stripped.split(":", 1)
                    data["patches"].setdefault(pkg, []).append((ptype.strip(), entry.strip()))
                except ValueError:
                    pass
            else:
                data[last_field] = data.get(last_field, "") + "\n" + stripped
            continue

        try:
            key, value = line.split(":", 1)
        except ValueError:
            continue

        key = key.strip()
        value = value.strip()
        last_field = key

        if key == "Candidate":
            data["Candidate"] = value
        elif key == "Priority":
            data["Priority"] = [value, ""]
        elif key.startswith("Priority_"):
            data[key] = [value, ""]
        elif key == "CVSS":
            data["CVSS"] = None
        elif key.startswith("Patches_"):
            _, pkg = key.split("_", 1)
            data["patches"].setdefault(pkg, [])
        elif key.startswith("Tags"):
            tag_key = "*"
            if "_" in key:
                _, tag_key = key.split("_", 1)
            data["tags"].setdefault(tag_key, set())
            for word in value.split():
                data["tags"][tag_key].add(word)
        elif "_" in key:
            # release_pkgname: state (details)
            release, pkg_name = key.split("_", 1)
            info = value.split(" ", 1)
            state = info[0] if info[0] else "needs-triage"
            details = info[1].strip("()") if len(info) > 1 else ""
            data["pkgs"].setdefault(pkg_name, {})[release] = [state, details]
        else:
            data[key] = value

    data["CVSS"] = cvss_entries
    if "Priority" in data and isinstance(data["Priority"], list):
        reason_lines = priority_reason.get(None)
        if reason_lines:
            data["Priority"][1] = "\n".join(reason_lines)
    return data


# ── subprojects.json → active releases ────────────────────────────────────
def _active_releases_from_subprojects(uct_path):
    """Read UCT subprojects.json and return the set of active release names."""
    sp_path = os.path.join(uct_path, "meta_lists", "subprojects.json")
    with open(sp_path, encoding="utf-8") as fh:
        subprojects = json.load(fh)

    active = set()
    for key, info in subprojects.items():
        if info.get("eol", True):
            continue
        active.add(key)
        # Bare codename for entries like "ubuntu/jammy"
        if "/" in key:
            active.add(key.split("/")[-1])
        # Alias
        alias = info.get("alias", "")
        if alias:
            active.add(alias)
            if "/" in alias:
                active.add(alias.split("/")[-1])
    return active


# ── Sources.gz → package → component mapping ────────────────────────────
def _sources_gz_url(release, component, archive=None):
    """Return the URL for a given release+component Sources.gz file.
    archive overrides the default archive.ubuntu.com host."""
    if archive == "esm-infra":
        return (
            f"https://esm.ubuntu.com/infra/ubuntu/dists/{release}-infra-security"
            f"/{component}/source/Sources.gz"
        )
    if archive == "esm-apps":
        return (
            f"https://esm.ubuntu.com/apps/ubuntu/dists/{release}-apps-security"
            f"/{component}/source/Sources.gz"
        )
    return (
        f"http://archive.ubuntu.com/ubuntu/dists/{release}"
        f"/{component}/source/Sources.gz"
    )


def _fetch_sources_gz(url, timeout=60):
    """Download a Sources.gz and return its decompressed text.
    Returns None on any failure (including 401/403 for auth-required ESM repos)."""
    try:
        with urllibreq.urlopen(url, timeout=timeout) as resp:
            return gzip.decompress(resp.read()).decode("utf-8", errors="replace")
    except Exception:
        return None


def _parse_sources_gz(content):
    """Extract Package names from a Sources.gz (Debian RFC-822) text."""
    packages = set()
    if not content:
        return packages
    for line in content.splitlines():
        if line.startswith("Package: "):
            packages.add(line[9:].strip())
    return packages


def _progress_bar(current, total, bar_length=40, prefix=""):
    """Print a simple terminal progress bar."""
    if total == 0:
        return
    filled = int(bar_length * current / total)
    bar = "█" * filled + "░" * (bar_length - filled)
    pct = 100 * current / total
    print(f"\r{prefix}[{bar}] {current}/{total} ({pct:.1f}%)", end="", flush=True)


def _build_pkg_component_map(uct_path):
    """Download Sources.gz for standard and ESM Ubuntu releases, parse them,
    and return a dict mapping source package name → set of components.
    Results are cached in the project directory so repeated runs are fast."""
    nebula_dir = os.path.dirname(os.path.abspath(__file__))
    cache_dir = os.path.join(nebula_dir, ".cache", "sources_gz")
    os.makedirs(cache_dir, exist_ok=True)

    sp_path = os.path.join(uct_path, "meta_lists", "subprojects.json")
    with open(sp_path, encoding="utf-8") as fh:
        subprojects = json.load(fh)

    ARCHIVE_COMPONENTS = ["main", "universe", "multiverse", "restricted"]
    pkg_sec = defaultdict(Counter)

    # Count total fetches for progress bar
    to_fetch = []
    for key, info in subprojects.items():
        if info.get("eol", True):
            continue
        parts = key.split("/")
        if len(parts) != 2:
            continue
        kind, release = parts
        if kind not in ("ubuntu", "esm-infra", "esm-apps"):
            continue
        comps = ["main"] if kind != "ubuntu" else ARCHIVE_COMPONENTS
        for comp in comps:
            to_fetch.append((key, release, kind, comp))

    print("[UCT] Mapping packages to components from Sources.gz...")
    for i, (key, release, kind, comp) in enumerate(to_fetch):
        _progress_bar(i + 1, len(to_fetch), prefix="  Sources.gz:         ")
        archive = None if kind == "ubuntu" else kind
        forced_comp = None if kind == "ubuntu" else kind
        cache_file = os.path.join(cache_dir, f"{key.replace('/', '_')}_{comp}.json")
        if os.path.exists(cache_file):
            with open(cache_file, encoding="utf-8") as fh:
                pkgs = set(json.load(fh))
        else:
            url = _sources_gz_url(release, comp, archive)
            text = _fetch_sources_gz(url)
            pkgs = _parse_sources_gz(text) if text else set()
            with open(cache_file, "w", encoding="utf-8") as fh:
                json.dump(sorted(pkgs), fh)
        for pkg in pkgs:
            tag = forced_comp if forced_comp else comp
            pkg_sec[_norm_pkg(pkg)][tag] += 1
    print()

    # Convert Counter to set of components
    result = {}
    for pkg, counts in pkg_sec.items():
        comps = set(counts.keys())
        if "esm-infra" in comps and "esm-apps" in comps:
            comps.discard("esm-infra")
        result[pkg] = comps
    return result


def _norm_pkg(pkg):
    if pkg.startswith(LINUX_PFX) or pkg in LINUX_EXACT:
        return "linux"
    return pkg


def _cvss_score(cvss_list):
    if not cvss_list or not isinstance(cvss_list, list):
        return 0.5
    for pref in ["nvd", "cisa-adp", "kernel.org", "redhat", "google", "github"]:
        for e in cvss_list:
            if e.get("source", "").lower().startswith(pref):
                try:
                    return float(e["baseScore"])
                except (ValueError, TypeError, KeyError):
                    continue
    for e in cvss_list:
        try:
            return float(e["baseScore"])
        except (ValueError, TypeError, KeyError):
            continue
    return 0.5


def _composite(priority, cvss, kev, pub_date_str):
    p = PRIORITY_SCORES.get(priority, 3) / 5.0
    c = cvss / 10.0
    k = 1.0 if kev else 0.0
    r = 0.0
    if pub_date_str and pub_date_str not in ("unknown", ""):
        try:
            d = datetime.strptime(pub_date_str.split()[0], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days = max((datetime.now(timezone.utc) - d).days, 0)
            r = math.exp(-math.log(2) * days / 180.0)
        except (ValueError, IndexError):
            r = 0.3
    return round(p * 0.30 + c * 0.35 + k * 0.20 + r * 0.15, 4)


def _severity_tier(composite_score):
    for threshold, tier in SEVERITY_THRESHOLDS:
        if composite_score >= threshold:
            return tier
    return "negligible"


def _load_one(args):
    cve_path, active_releases = args
    try:
        data = _load_cve_file(cve_path)
    except Exception:
        return None
    if not data or not data.get("Candidate"):
        return None

    cand = data["Candidate"]
    pri = data.get("Priority", ["untriaged"])
    pri_level = pri[0] if isinstance(pri, list) and pri else str(pri)

    cvss = _cvss_score(data.get("CVSS", []))
    tags = data.get("tags", {})
    kev = "*" in tags and "cisa-kev" in tags.get("*", set())
    pub = data.get("PublicDate", "")

    pkgs_data = data.get("pkgs", {})
    affected = set()
    states = {}
    for pkg, rels in pkgs_data.items():
        np = _norm_pkg(pkg)
        for rel, si in rels.items():
            if not isinstance(si, (list, tuple)) or not si:
                continue
            st = si[0]
            if st in STATUS_OPEN and rel in active_releases:
                affected.add(np)
                states.setdefault(np, {})[rel] = st

    if not affected:
        return None

    comp = _composite(pri_level, cvss, kev, pub)
    rels_list = list({r for ps in states.values() for r in ps})

    return {
        "candidate": cand,
        "priority": pri_level,
        "cvss": cvss,
        "cisa_kev": kev,
        "public_date": pub,
        "composite": comp,
        "affected_pkgs": sorted(affected),
        "affected_releases": sorted(rels_list),
        "pkg_states": states,
    }


class UCTDataSource:
    def __init__(self, uct_path):
        self.uct_path = uct_path
        self.active_dir = os.path.join(uct_path, "active")
        self.cves = {}
        self.pkg_comp = {}
        self.mtimes = {}
        self.version = 0
        self.last_sync = None
        self.ready = False
        self._lock = threading.RLock()
        self._graph_cache = {}
        self._graph_ver = -1

    def initial_load(self):
        print("[UCT] Starting initial data load...")
        self._map_components()
        self._parse_all()
        self.version = 1
        self.last_sync = datetime.now(timezone.utc).isoformat()
        self.ready = True
        print(f"[UCT] Initial load complete: {len(self.cves)} active CVEs, version={self.version}")

    def _map_components(self):
        self.pkg_comp = _build_pkg_component_map(self.uct_path)

    def _parse_all(self):
        active_releases = _active_releases_from_subprojects(self.uct_path)
        paths = [os.path.join(self.active_dir, f)
                 for f in os.listdir(self.active_dir) if f.startswith("CVE-")]
        workers = min(multiprocessing.cpu_count(), 8)
        args = [(p, active_releases) for p in paths]
        chunk = max(1, len(args) // (workers * 4))
        self.cves = {}
        print(f"[UCT] Parsing {len(paths)} CVE files...")
        with multiprocessing.Pool(processes=workers) as pool:
            for i, result in enumerate(pool.imap_unordered(_load_one, args, chunksize=chunk)):
                if result:
                    self.cves[result["candidate"]] = result
                if (i + 1) % 1000 == 0 or (i + 1) == len(paths):
                    _progress_bar(i + 1, len(paths), prefix="  CVE files:          ")
        print()
        for p in paths:
            try:
                self.mtimes[p] = os.path.getmtime(p)
            except OSError:
                pass

    def check_updates(self):
        current = {}
        try:
            entries = os.listdir(self.active_dir)
        except OSError:
            return
        for f in entries:
            if not f.startswith("CVE-"):
                continue
            p = os.path.join(self.active_dir, f)
            try:
                current[p] = os.path.getmtime(p)
            except OSError:
                continue
        cur_set = set(current.keys())
        old_set = set(self.mtimes.keys())
        added = cur_set - old_set
        removed = old_set - cur_set
        modified = {p for p in cur_set & old_set if current[p] != self.mtimes[p]}
        if not (added or removed or modified):
            return
        active_releases = _active_releases_from_subprojects(self.uct_path)
        changed = False
        with self._lock:
            for p in removed:
                self.cves.pop(os.path.basename(p), None)
                changed = True
            for p in added | modified:
                result = _load_one((p, active_releases))
                if result:
                    self.cves[result["candidate"]] = result
                    changed = True
                else:
                    self.cves.pop(os.path.basename(p), None)
            self.mtimes = current
            if changed:
                self.version += 1
                self.last_sync = datetime.now(timezone.utc).isoformat()
                print(f"[UCT] Data updated: {len(added)} added, {len(removed)} removed, "
                      f"{len(modified)} modified -> version={self.version}")

    def get_graph(self, component):
        with self._lock:
            if self._graph_ver != self.version:
                self._graph_cache.clear()
                self._graph_ver = self.version
            if component not in self._graph_cache:
                self._graph_cache[component] = self._build(component)
            return self._graph_cache[component]

    def _build(self, component):
        pkg_cves = defaultdict(list)
        for cve in self.cves.values():
            for pkg in cve["affected_pkgs"]:
                if component in self.pkg_comp.get(pkg, set()):
                    pkg_cves[pkg].append(cve)

        pri_order = {"negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        packages = []
        cves_out = {}

        for pkg, cve_list in pkg_cves.items():
            mx = "negligible"
            vload = 0.0
            kc = 0
            max_composite = 0.0
            max_cvss = 0.0
            for c in cve_list:
                if pri_order.get(c["priority"], 2) > pri_order.get(mx, 0):
                    mx = c["priority"]
                vload += c["composite"]
                if c["composite"] > max_composite:
                    max_composite = c["composite"]
                if c["cvss"] > max_cvss:
                    max_cvss = c["cvss"]
                if c["cisa_kev"]:
                    kc += 1
            severity = _severity_tier(max_composite)
            sz = max(6, min(50, 6 + len(cve_list) * 1.2))
            packages.append({
                "name": pkg,
                "cveCount": len(cve_list),
                "maxPriority": mx,
                "severity": severity,
                "maxComposite": round(max_composite, 4),
                "maxCvss": round(max_cvss, 1),
                "vulnLoad": round(vload, 2),
                "kevCount": kc,
                "color": SEVERITY_COLORS.get(severity, "#448aff"),
                "size": round(sz, 1),
            })
            comp_pkgs = [p for p in c["affected_pkgs"] if self.pkg_comp.get(p) == component]
            comp_states = {p: st for p, st in c["pkg_states"].items() if self.pkg_comp.get(p) == component}
            cves_out[pkg] = [{
                "candidate": c["candidate"],
                "priority": c["priority"],
                "cvss": c["cvss"],
                "cisaKev": c["cisa_kev"],
                "publicDate": c["public_date"],
                "composite": c["composite"],
                "severity": _severity_tier(c["composite"]),
                "affectedReleases": c["affected_releases"],
                "pkgStates": c["pkg_states"].get(pkg, {}),
                "affectedPackages": comp_pkgs,
                "pkgStatesAll": comp_states,
                "color": SEVERITY_COLORS.get(_severity_tier(c["composite"]), "#448aff"),
                "size": round(max(3, min(16, 3 + c["composite"] * 10)), 1),
            } for c in cve_list]

        cve_pkgsets = defaultdict(set)
        for pkg, cve_list in pkg_cves.items():
            for c in cve_list:
                cve_pkgsets[c["candidate"]].add(pkg)

        link_w = defaultdict(float)
        link_n = defaultdict(int)
        for cid, pset in cve_pkgsets.items():
            if len(pset) < 2:
                continue
            plist = sorted(pset)
            for i in range(len(plist)):
                for j in range(i + 1, len(plist)):
                    key = (plist[i], plist[j])
                    c = next(c for c in pkg_cves[plist[i]] if c["candidate"] == cid)
                    link_w[key] += c["composite"]
                    link_n[key] += 1

        pkg_links = []
        for (p1, p2), w in link_w.items():
            pkg_links.append({
                "source": p1, "target": p2,
                "weight": round(w, 2),
                "sharedCount": link_n[(p1, p2)],
            })

        positions, spiral_links = self._compute_positions(packages, pkg_links)
        for pkg in packages:
            pos = positions.get(pkg["name"], (0, 0, 0))
            pkg["x"] = round(pos[0], 4)
            pkg["y"] = round(pos[1], 4)
            pkg["z"] = round(pos[2], 4)

        for pkg_name, cve_list in cves_out.items():
            px, py, pz = positions.get(pkg_name, (0, 0, 0))
            n = len(cve_list)
            # Orbit radius scales with number of CVEs so moons don't pile up
            base_r = max(1.5, min(6.0, 1.0 + n * 0.06))
            for i, cve in enumerate(cve_list):
                phi = (2 * math.pi * i) / max(n, 1)
                theta = math.acos(1 - 2 * (i + 0.5) / max(n, 1))
                r = base_r + cve["composite"] * 1.0
                cve["x"] = round(px + r * math.sin(theta) * math.cos(phi), 4)
                cve["y"] = round(py + r * math.sin(theta) * math.sin(phi), 4)
                cve["z"] = round(pz + r * math.cos(theta), 4)

        link_positions = []
        for link in pkg_links:
            sp = positions.get(link["source"], (0, 0, 0))
            tp = positions.get(link["target"], (0, 0, 0))
            link_positions.append({
                "source": link["source"],
                "target": link["target"],
                "weight": link["weight"],
                "sharedCount": link["sharedCount"],
                "x0": round(sp[0], 4), "y0": round(sp[1], 4), "z0": round(sp[2], 4),
                "x1": round(tp[0], 4), "y1": round(tp[1], 4), "z1": round(tp[2], 4),
            })

        spiral_link_positions = []
        for sl in spiral_links:
            sp = positions.get(sl["source"], (0, 0, 0))
            tp = positions.get(sl["target"], (0, 0, 0))
            spiral_link_positions.append({
                "source": sl["source"],
                "target": sl["target"],
                "shell": sl["shell"],
                "x0": round(sp[0], 4), "y0": round(sp[1], 4), "z0": round(sp[2], 4),
                "x1": round(tp[0], 4), "y1": round(tp[1], 4), "z1": round(tp[2], 4),
            })

        stats = {
            "pkgCount": len(packages),
            "cveCount": sum(len(v) for v in cves_out.values()),
            "linkCount": len(pkg_links),
        }
        return {
            "packages": packages,
            "pkgLinks": link_positions,
            "spiralLinks": spiral_link_positions,
            "cves": cves_out,
            "component": component,
            "stats": stats,
        }

    def get_pkg_cves(self, component, pkg_name):
        """Get CVEs for a single package (lazy load for UI)."""
        graph = self.get_graph(component)
        cves = graph.get("cves", {}).get(pkg_name, [])
        return {"package": pkg_name, "cves": cves}

    def get_graph_lite(self, component):
        """Get graph without CVEs (packages + links only) for fast initial load."""
        graph = self.get_graph(component)
        return {
            "packages": graph["packages"],
            "pkgLinks": graph["pkgLinks"],
            "spiralLinks": graph["spiralLinks"],
            "component": graph["component"],
            "stats": graph["stats"],
        }

    def _compute_positions(self, packages, pkg_links):
        if not packages:
            return {}, []
        G = nx.Graph()
        for pkg in packages:
            G.add_node(pkg["name"])
        for link in pkg_links:
            G.add_edge(link["source"], link["target"], weight=max(0.01, link["weight"]))
        isolated = [n for n in G.nodes() if G.degree(n) == 0]
        connected = [n for n in G.nodes() if G.degree(n) > 0]
        positions = {}
        if connected:
            C = G.subgraph(connected)
            iters = max(30, min(80, len(connected)))
            k_val = max(3.0, 1.5 * math.sqrt(len(connected) / max(1, len(pkg_links))))
            pos = nx.spring_layout(C, dim=3, iterations=iters, weight="weight", seed=42, k=k_val)
            scale = max(20, len(connected) * 0.15)
            for k, v in pos.items():
                positions[k] = (float(v[0]) * scale, float(v[1]) * scale, float(v[2]) * scale)
        spiral_links = []
        if isolated:
            n_iso = len(isolated)
            n_shells = max(2, min(5, n_iso // 30))
            base_radius = max(8, len(connected) * 0.3) if connected else 5
            growth_factor = 1.1
            cx, cy, cz = 0.0, 0.0, 0.0
            if connected:
                cx = sum(p[0] for p in positions.values()) / len(positions)
                cy = sum(p[1] for p in positions.values()) / len(positions)
                cz = sum(p[2] for p in positions.values()) / len(positions)
            rng = random.Random(42)
            shell_assignments = [[] for _ in range(n_shells)]
            for pkg_name in isolated:
                s = rng.randint(0, n_shells - 1)
                shell_assignments[s].append(pkg_name)
            for s_idx, shell_pkgs in enumerate(shell_assignments):
                n_s = len(shell_pkgs)
                if n_s == 0:
                    continue
                r = base_radius * (growth_factor ** s_idx)
                for i, pkg_name in enumerate(shell_pkgs):
                    phi = 2 * math.pi * i / n_s
                    theta = math.acos(1 - 2 * (i + 0.5) / n_s)
                    x = cx + r * math.sin(theta) * math.cos(phi)
                    y = cy + r * math.sin(theta) * math.sin(phi)
                    z = cz + r * math.cos(theta)
                    positions[pkg_name] = (x, y, z)
                    if n_s > 1 and i < n_s - 1:
                        next_pkg = shell_pkgs[i + 1]
                        spiral_links.append({
                            "source": pkg_name,
                            "target": next_pkg,
                            "shell": s_idx,
                        })
        return positions, spiral_links

    def get_status(self):
        with self._lock:
            pkg_per_comp = Counter()
            cve_per_comp = Counter()
            pkg_set_per_comp = defaultdict(set)
            for cve in self.cves.values():
                for pkg in cve["affected_pkgs"]:
                    for comp in self.pkg_comp.get(pkg, set()):
                        pkg_set_per_comp[comp].add(pkg)
                        cve_per_comp[comp] += 1
            for comp, pset in pkg_set_per_comp.items():
                pkg_per_comp[comp] = len(pset)
            comp_counts = {}
            for c in COMPONENTS:
                comp_counts[c] = {
                    "pkgCount": pkg_per_comp.get(c, 0),
                    "cveCount": cve_per_comp.get(c, 0),
                    "linkCount": len(self._graph_cache[c]["pkgLinks"]) if self._graph_ver == self.version and c in self._graph_cache else 0,
                }
            return {
                "version": self.version,
                "lastSync": self.last_sync,
                "ready": self.ready,
                "cveCount": len(self.cves),
                "components": comp_counts,
            }


HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uct_viewer.html")
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

MIME_TYPES = {
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
}


class Handler(BaseHTTPRequestHandler):
    data_source = None

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._serve_html()
        elif path.startswith("/api/graph-lite/"):
            comp = path.split("/")[-1]
            if comp in COMPONENTS and self.data_source.ready:
                self._json(self.data_source.get_graph_lite(comp))
            elif not self.data_source.ready:
                self._json({"error": "Server still loading initial data"}, 503)
            else:
                self._json({"error": "Unknown component"}, 400)
        elif path.startswith("/api/graph/"):
            comp = path.split("/")[-1]
            if comp in COMPONENTS and self.data_source.ready:
                self._json(self.data_source.get_graph(comp))
            elif not self.data_source.ready:
                self._json({"error": "Server still loading initial data"}, 503)
            else:
                self._json({"error": "Unknown component"}, 400)
        elif path.startswith("/api/cves/"):
            # /api/cves/main/packagename
            parts = path.split("/")
            if len(parts) >= 4:
                comp = parts[3]
                pkg_name = "/".join(parts[4:]) if len(parts) > 4 else ""
                if comp in COMPONENTS and self.data_source.ready and pkg_name:
                    self._json(self.data_source.get_pkg_cves(comp, pkg_name))
                else:
                    self._json({"error": "Invalid request"}, 400)
            else:
                self._json({"error": "Invalid request"}, 400)
        elif path == "/api/status":
            self._json(self.data_source.get_status())
        elif path.startswith("/static/"):
            self._serve_static(path[8:])
        else:
            self.send_error(404)

    def _serve_html(self):
        try:
            with open(HTML_PATH, "rb") as f:
                data = f.read()
            self._respond(200, "text/html; charset=utf-8", data)
        except FileNotFoundError:
            self._respond(404, "text/plain", b"uct_viewer.html not found")

    def _serve_static(self, filename):
        safe = os.path.basename(filename)
        filepath = os.path.join(STATIC_DIR, safe)
        if not os.path.isfile(filepath):
            self.send_error(404)
            return
        ext = os.path.splitext(safe)[1].lower()
        ctype = MIME_TYPES.get(ext, "application/octet-stream")
        with open(filepath, "rb") as f:
            data = f.read()
        self._respond(200, ctype, data)

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._respond(code, "application/json", data)

    def _respond(self, code, ctype, data):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


class ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def watch_loop(ds, interval=30):
    while True:
        time.sleep(interval)
        if ds.ready:
            try:
                ds.check_updates()
            except Exception as e:
                print(f"[WATCHER] Error: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Nebula Dispatcher - Ubuntu CVE Tracker Visualizer")
    uct_default = os.environ.get("UCT", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "ubuntu-cve-tracker",
    ))
    ap.add_argument("--uct-path",
                    default=uct_default,
                    help="Path to ubuntu-cve-tracker repo (default: $UCT env var or ~/git-pulls/ubuntu-cve-tracker)")
    ap.add_argument("--port", type=int, default=8080, help="HTTP port")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default: 127.0.0.1; use 0.0.0.0 to expose to network)")
    ap.add_argument("--watch-interval", type=int, default=30, help="Seconds between sync checks")
    args = ap.parse_args()

    ds = UCTDataSource(args.uct_path)

    print("=" * 60)
    print("Nebula Dispatcher - Ubuntu CVE Tracker Visualizer")
    print("=" * 60)

    ds.initial_load()

    watcher = threading.Thread(target=watch_loop, args=(ds, args.watch_interval), daemon=True)
    watcher.start()

    Handler.data_source = ds
    server = ThreadedServer((args.host, args.port), Handler)

    print(f"\nServer ready at http://{args.host}:{args.port}/")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
