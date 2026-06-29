#!/usr/bin/env python3
"""aurcheck — vet AUR updates against the 2026 "Atomic Arch" supply-chain attack.

Lists every updatable AUR package, shows how long since the maintainer last
changed, flags known breach indicators (compromised packages, attacker accounts,
the June 9-12 2026 attack window, and maintainer swaps detected since the last
run), then lets you update only the cleared packages via paru/yay.

Pure standard library. Companion to the pure-shell `aurcheck` script.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# --- constants ---------------------------------------------------------------

RPC_BASE = "https://aur.archlinux.org/rpc/v5/info"
RPC_CHUNK = 150  # packages per request (keep GET URL well under limits)

IOC_BASE = ("https://raw.githubusercontent.com/lenucksi/aur-malware-check/"
            "master/data/campaigns/aur-infected")
IOC_FILES = ("packages.txt", "accounts.json", "npm-packages.txt")

# June 9-12 2026 attack window, inclusive, in UTC epoch seconds.
ATTACK_START = 1749427200   # 2026-06-09 00:00:00 UTC
ATTACK_END = 1749772799     # 2026-06-12 23:59:59 UTC

# minor/major heuristic thresholds (tunable)
POP_THRESHOLD = 1.0
VOTES_THRESHOLD = 10

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED_DATA = os.path.join(HERE, "data")


def xdg(var, default):
    return os.path.join(os.environ.get(var) or os.path.expanduser(default), "aurcheck")


CACHE_DIR = xdg("XDG_CACHE_HOME", "~/.cache")
CONFIG_DIR = xdg("XDG_CONFIG_HOME", "~/.config")
STATE_DIR = xdg("XDG_STATE_HOME", "~/.local/state")
WHITELIST = os.path.join(CONFIG_DIR, "whitelist.txt")
SNAPSHOT = os.path.join(STATE_DIR, "snapshot.json")

# --- colors ------------------------------------------------------------------


class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for k in ("RED", "GREEN", "YELLOW", "DIM", "BOLD", "RESET"):
            setattr(cls, k, "")


# --- shell helpers -----------------------------------------------------------


def run(cmd):
    """Run a command, return (rc, stdout). Never raises on non-zero rc."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return 127, ""


def have(prog):
    return run(["sh", "-c", f"command -v {prog}"])[0] == 0


def detect_helper(preferred=None):
    for h in ([preferred] if preferred else []) + ["paru", "yay"]:
        if h and have(h):
            return h
    return None


# --- data collection ---------------------------------------------------------


def get_updatable(helper):
    """Return dict name -> (old_ver, new_ver) for AUR packages with updates."""
    rc, out = run([helper, "-Qua"])
    updatable = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(("::", " ", ":")):
            continue
        parts = line.split()
        # format: "name oldver -> newver"
        if "->" in parts:
            i = parts.index("->")
            if i >= 2:
                updatable[parts[0]] = (parts[i - 1], parts[i + 1])
        elif len(parts) >= 3:
            updatable[parts[0]] = (parts[1], parts[2])
    return updatable


def explicit_packages():
    return set(run(["pacman", "-Qqe"])[1].split())


def required_by(name):
    """Return list of packages requiring `name` (empty == leaf)."""
    rc, out = run(["pacman", "-Qi", name])
    for line in out.splitlines():
        if line.startswith("Required By"):
            val = line.split(":", 1)[1].strip()
            return [] if val == "None" else val.split()
    return []


def aur_info(names):
    """Query AUR RPC v5 info in chunks. Return dict name -> metadata."""
    result = {}
    names = list(names)
    for i in range(0, len(names), RPC_CHUNK):
        chunk = names[i:i + RPC_CHUNK]
        qs = urllib.parse.urlencode([("arg[]", n) for n in chunk])
        url = f"{RPC_BASE}?{qs}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "aurcheck/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r)
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            print(f"{C.YELLOW}warning: AUR RPC query failed: {e}{C.RESET}",
                  file=sys.stderr)
            continue
        for pkg in data.get("results", []):
            result[pkg["Name"]] = pkg
    return result


# --- IOC + whitelist ---------------------------------------------------------


def fetch_iocs():
    os.makedirs(CACHE_DIR, exist_ok=True)
    ok = True
    for f in IOC_FILES:
        try:
            req = urllib.request.Request(f"{IOC_BASE}/{f}",
                                         headers={"User-Agent": "aurcheck/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                with open(os.path.join(CACHE_DIR, f), "wb") as out:
                    out.write(r.read())
        except (urllib.error.URLError, OSError) as e:
            print(f"{C.YELLOW}warning: could not refresh {f}: {e}{C.RESET}",
                  file=sys.stderr)
            ok = False
    return ok


def ioc_path(f):
    """Prefer cache, fall back to bundled data/."""
    cached = os.path.join(CACHE_DIR, f)
    return cached if os.path.exists(cached) else os.path.join(BUNDLED_DATA, f)


def load_iocs(refresh):
    if refresh or not os.path.exists(os.path.join(CACHE_DIR, "packages.txt")):
        fetch_iocs()

    compromised = set()
    try:
        with open(ioc_path("packages.txt")) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    compromised.add(line)
    except OSError:
        pass

    attackers, forged = set(), set()
    try:
        with open(ioc_path("accounts.json")) as fh:
            accounts = json.load(fh).get("accounts", {})
        for name, info in accounts.items():
            status = info.get("status", "")
            if status == "commitforgery":
                forged.add(name)          # legit maintainer, impersonated
            else:                          # confirmed / monitoring / etc.
                attackers.add(name)
    except (OSError, json.JSONDecodeError):
        pass

    return compromised, attackers, forged


def load_whitelist():
    wl = set()
    try:
        with open(WHITELIST) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    wl.add(line)
    except OSError:
        pass
    return wl


# --- snapshot ----------------------------------------------------------------


def load_snapshot():
    try:
        with open(SNAPSHOT) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_snapshot(snap):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = SNAPSHOT + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(snap, fh, indent=2, sort_keys=True)
    os.replace(tmp, SNAPSHOT)


# --- formatting --------------------------------------------------------------


def rel_time(epoch):
    if not epoch:
        return "?"
    delta = int(time.time()) - int(epoch)
    if delta < 0:
        return "future"
    for unit, secs in (("y", 31536000), ("mo", 2592000), ("d", 86400),
                       ("h", 3600), ("m", 60)):
        if delta >= secs:
            return f"{delta // secs}{unit} ago"
    return "just now"


# --- classification ----------------------------------------------------------


def classify(name, meta, snap, compromised, attackers, forged, whitelist,
             explicit):
    """Return a dict describing the package's risk and verdict."""
    maint = (meta or {}).get("Maintainer")
    last_mod = (meta or {}).get("LastModified")
    reasons = []
    blocked = False
    changed = False

    if name in whitelist:
        verdict = "RECOMMENDED"
        reasons.append("whitelisted by you")
        return _result(name, meta, "whitelist", verdict, reasons, changed)

    if meta is None:
        # foreign package not present on the AUR (locally built, removed, etc.)
        return _result(name, meta, "unknown", "UNKNOWN",
                       ["not found on AUR"], changed)

    # maintainer swap since last run
    prev = snap.get(name, {}).get("maintainer", "__none__")
    if prev != "__none__" and prev != maint:
        changed = True
        blocked = True
        reasons.append(f"maintainer changed: {prev or 'orphan'} -> "
                       f"{maint or 'orphan'}")

    if maint in attackers:
        blocked = True
        reasons.append(f"maintainer '{maint}' is a flagged attacker account")
    if name in compromised:
        blocked = True
        reasons.append("on known compromised-package list")
    if last_mod and ATTACK_START <= int(last_mod) <= ATTACK_END:
        blocked = True
        reasons.append("modified during June 9-12 attack window")

    if blocked:
        return _result(name, meta, "block", "BLOCKED", reasons, changed)

    if maint is None:
        reasons.append("orphaned (no maintainer)")
        return _result(name, meta, "caution", "CAUTION", reasons, changed)

    if maint in forged:
        reasons.append(f"note: '{maint}' identity was forged in attack; "
                       "verify upstream")

    # minor vs major
    major = (required_by(name)
             or float(meta.get("Popularity") or 0) >= POP_THRESHOLD
             or int(meta.get("NumVotes") or 0) >= VOTES_THRESHOLD)
    if major:
        reasons.append("depended-on / popular" if name not in explicit
                       else "popular / depended-on")
        return _result(name, meta, "recommend", "RECOMMENDED", reasons, changed)

    reasons.append("minor leaf package")
    return _result(name, meta, "optional", "OPTIONAL", reasons, changed)


def _result(name, meta, kind, verdict, reasons, changed):
    meta = meta or {}
    return {
        "name": name,
        "maintainer": meta.get("Maintainer"),
        "lastmod": meta.get("LastModified"),
        "popularity": meta.get("Popularity"),
        "votes": meta.get("NumVotes"),
        "kind": kind,
        "verdict": verdict,
        "reasons": reasons,
        "changed": changed,
    }


VERDICT_COLOR = {
    "BLOCKED": "RED",
    "CAUTION": "YELLOW",
    "OPTIONAL": "YELLOW",
    "RECOMMENDED": "GREEN",
    "UNKNOWN": "DIM",
}
SORT_ORDER = {"BLOCKED": 0, "CAUTION": 1, "OPTIONAL": 2, "RECOMMENDED": 3,
              "UNKNOWN": 4}


# --- table -------------------------------------------------------------------


def print_table(rows, updatable):
    hdr = f"{'PACKAGE':<28} {'VERSION':<22} {'MAINTAINER':<16} " \
          f"{'LAST ACTIVITY':<13} {'CHG':<4} {'POP/VOTES':<12} VERDICT"
    print(C.BOLD + hdr + C.RESET)
    print(C.DIM + "-" * len(hdr) + C.RESET)
    for r in rows:
        col = getattr(C, VERDICT_COLOR.get(r["verdict"], "RESET"))
        old, new = updatable.get(r["name"], ("?", "?"))
        ver = f"{old} -> {new}"
        if len(ver) > 22:
            ver = ver[:20] + ".."
        maint = (r["maintainer"] or "—")[:15]
        pv = f"{r['popularity'] or 0:.2f}/{r['votes'] or 0}"
        chg = "YES" if r["changed"] else ""
        print(f"{col}{r['name']:<28.28} {ver:<22} {maint:<16} "
              f"{rel_time(r['lastmod']):<13} {chg:<4} {pv:<12} "
              f"{r['verdict']}{C.RESET}")
    # reasons footnotes for anything not a plain recommend
    notable = [r for r in rows if r["verdict"] != "RECOMMENDED" or r["reasons"]]
    if notable:
        print()
        for r in notable:
            if r["verdict"] in ("RECOMMENDED",) and not r["changed"]:
                continue
            col = getattr(C, VERDICT_COLOR.get(r["verdict"], "RESET"))
            print(f"  {col}{r['name']}{C.RESET}: {'; '.join(r['reasons'])}")


# --- actions -----------------------------------------------------------------


def write_audit(rows, updatable):
    os.makedirs(STATE_DIR, exist_ok=True)
    path = os.path.join(STATE_DIR,
                        f"cleared-{time.strftime('%Y-%m-%d')}.csv")
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "old", "new", "maintainer", "verdict", "reasons"])
        for r in rows:
            old, new = updatable.get(r["name"], ("", ""))
            w.writerow([r["name"], old, new, r["maintainer"] or "",
                        r["verdict"], "; ".join(r["reasons"])])
    return path


def do_update(helper, names):
    if not names:
        print("Nothing to update.")
        return
    cmd = [helper, "-S", "--needed", *names]
    print(C.BOLD + "Running: " + " ".join(cmd) + C.RESET)
    subprocess.run(cmd)


# --- main --------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--refresh", action="store_true",
                    help="re-fetch IOC lists from upstream before checking")
    ap.add_argument("--helper", choices=["paru", "yay"],
                    help="AUR helper to use (default: auto-detect)")
    ap.add_argument("--no-color", action="store_true", help="disable colors")
    ap.add_argument("--yes", action="store_true",
                    help="non-interactive: update recommended without prompting")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    helper = detect_helper(args.helper)
    if not helper:
        sys.exit("error: neither paru nor yay found")

    print(C.DIM + "Loading IOC lists…" + C.RESET)
    compromised, attackers, forged = load_iocs(args.refresh)
    whitelist = load_whitelist()
    snap = load_snapshot()

    print(C.DIM + f"Enumerating AUR updates via {helper}…" + C.RESET)
    updatable = get_updatable(helper)
    if not updatable:
        print(C.GREEN + "No AUR updates available. Nothing to do." + C.RESET)
        return

    print(C.DIM + f"Querying AUR metadata for {len(updatable)} package(s)…"
          + C.RESET)
    meta = aur_info(updatable.keys())
    explicit = explicit_packages()

    rows = []
    new_snap = dict(snap)
    for name in updatable:
        m = meta.get(name)
        r = classify(name, m, snap, compromised, attackers, forged,
                     whitelist, explicit)
        rows.append(r)
        if m is not None:
            new_snap[name] = {
                "maintainer": m.get("Maintainer"),
                "lastmodified": m.get("LastModified"),
                "last_seen": int(time.time()),
            }
    save_snapshot(new_snap)

    rows.sort(key=lambda r: (SORT_ORDER.get(r["verdict"], 9), r["name"]))
    print()
    print_table(rows, updatable)

    recommended = [r["name"] for r in rows if r["verdict"] == "RECOMMENDED"]
    blocked = [r for r in rows if r["verdict"] == "BLOCKED"]
    audit = write_audit(rows, updatable)
    print()
    print(f"{C.GREEN}{len(recommended)} recommended{C.RESET}, "
          f"{C.RED}{len(blocked)} blocked{C.RESET}. Audit: {C.DIM}{audit}{C.RESET}")

    if args.yes:
        do_update(helper, recommended)
        return

    print()
    choice = input("Update [a]ll / [r]ecommended / [q]uit? ").strip().lower()
    if choice == "r":
        do_update(helper, recommended)
    elif choice == "a":
        if blocked:
            warn = input(f"{C.RED}This includes {len(blocked)} BLOCKED "
                         f"package(s). Type 'yes' to proceed: {C.RESET}")
            if warn.strip().lower() != "yes":
                print("Aborted.")
                return
        print(C.BOLD + f"Running: {helper} -Sua" + C.RESET)
        subprocess.run([helper, "-Sua"])
    else:
        print("No changes made. Snapshot updated for next run.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
