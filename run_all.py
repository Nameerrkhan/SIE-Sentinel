from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGETS = HERE / "targets"
IN_SCOPE = ["vibe-kanban", "Who-Targets-Me", "pizauth", "snare"]

def scan_one(name: str, fast: bool) -> dict | None:
    repo = TARGETS / name
    if not repo.is_dir():
        print(f"  ! {name}: not cloned at {repo}", file=sys.stderr)
        return None
    cmd = [sys.executable, str(HERE / "scan.py"), str(repo)]
    if fast:
        cmd.append("--fast")
    print(f"\n=== scanning {name} ===", file=sys.stderr)
    subprocess.run(cmd, check=False)
    report = repo / ".sie_scan" / f"scan-{name}.json"
    if report.is_file():
        return json.loads(report.read_text(encoding="utf-8"))
    return None

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("only", nargs="*", help="specific repo names (default: all in scope)")
    ap.add_argument("--fast", action="store_true")
    args = ap.parse_args()

    names = args.only or IN_SCOPE
    results = []
    for n in names:
        r = scan_one(n, args.fast)
        if r:
            results.append(r)

    print("\n" + "=" * 74)
    print(f"{'REPO':22} {'FINDINGS':>9} {'CRIT':>5} {'HIGH':>5} {'MED':>4} "
          f"{'LOW':>4} {'CREDITS':>8} {'SECS':>6}")
    print("-" * 74)
    tot_c = tot_f = 0
    for r in results:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in r["findings"]:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        credits = r["credits"]["credits_total"]
        tot_c += credits
        tot_f += len(r["findings"])
        print(f"{r['repo'][:22]:22} {len(r['findings']):>9} {sev['critical']:>5} "
              f"{sev['high']:>5} {sev['medium']:>4} {sev['low']:>4} "
              f"{credits:>8} {r['elapsed_s']:>6.0f}")
    print("-" * 74)
    print(f"{'TOTAL':22} {tot_f:>9} {'':>5} {'':>5} {'':>4} {'':>4} {tot_c:>8}")
    print("=" * 74)
    print(f"\nReports: targets/<repo>/.sie_scan/scan-<repo>.md")

if __name__ == "__main__":
    main()
