from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGETS = HERE / "targets"

GROUND_TRUTH: dict[str, list[dict]] = {
    "snare": [
        {"id": "hmac-missing", "file": "httpserver.rs", "cwe": "CWE-347",
         "kw": ["hmac", "signature", "unsigned", "verif"], "sev": "high"},
        {"id": "secretless-exec", "file": "httpserver.rs", "cwe": "CWE-306",
         "kw": ["no secret", "secret", "unauthenticated", "unsigned"], "sev": "high"},
        {"id": "priv-drop-setgroups", "file": "main.rs", "cwe": "CWE-271",
         "kw": ["setgroups", "privilege", "supplementary", "group"], "sev": "medium"},
        {"id": "arg-injection", "file": "httpserver.rs", "cwe": "CWE-88",
         "kw": ["argument", "leading dash", "reponame", "flag"], "sev": "medium"},
        {"id": "dos-headers", "file": "httpserver.rs", "cwe": "CWE-400",
         "kw": ["unbounded", "header", "resource", "exhaust", "slowloris"], "sev": "medium"},
    ],
    "vibe-kanban": [
        {"id": "no-auth", "file": "mod.rs", "cwe": "CWE-306",
         "kw": ["authentication", "unauthenticated", "no auth"], "sev": "critical"},
        {"id": "token-exposure", "file": "config", "cwe": "CWE-200",
         "kw": ["token", "pat", "oauth", "secret", "serial"], "sev": "high"},
        {"id": "bypass-permissions", "file": "", "cwe": "CWE-250",
         "kw": ["permission", "bypass", "auto-approve", "profiles"], "sev": "critical"},
        {"id": "dns-rebind", "file": "origin.rs", "cwe": "CWE-346",
         "kw": ["origin", "host", "rebind", "cors"], "sev": "high"},
        {"id": "body-dos", "file": "proxy.rs", "cwe": "CWE-400",
         "kw": ["unbounded", "body", "buffer", "memory"], "sev": "medium"},
    ],
    "Who-Targets-Me": [
        {"id": "postmessage-bridge", "file": "index.js", "cwe": "CWE-346",
         "kw": ["postmessage", "message", "sender", "origin", "bridge"], "sev": "high"},
        {"id": "token-localstorage", "file": "", "cwe": "CWE-200",
         "kw": ["localstorage", "token", "wildcard", "page origin"], "sev": "medium"},
    ],
    "pizauth": [
        {"id": "socket-authority", "file": "", "cwe": "CWE-",
         "kw": ["socket", "peer", "credential", "authority", "local"], "sev": "medium"},
        {"id": "callback-dos", "file": "http_server.rs", "cwe": "CWE-400",
         "kw": ["unbounded", "slowloris", "timeout", "dos", "resource"], "sev": "medium"},
    ],
}

def matches(gt: dict, f: dict) -> bool:
    loc = (f.get("location") or "").lower()
    if gt["file"] and gt["file"].lower() not in loc:
        return False
    blob = (f.get("title", "") + " " + f.get("source_to_sink", "") + " "
            + f.get("cwe", "")).lower()
    cwe_ok = gt["cwe"].lower() in (f.get("cwe", "").lower()) if gt["cwe"] else False
    kw_ok = any(k in blob for k in gt["kw"])
    return cwe_ok or kw_ok

def score(repo: str) -> dict | None:
    rep_p = TARGETS / repo / ".sie_scan" / f"scan-{repo}.json"
    if not rep_p.is_file():
        return None
    data = json.loads(rep_p.read_text(encoding="utf-8"))
    fs = data.get("findings", [])
    gts = GROUND_TRUTH.get(repo, [])
    matched, missed, matched_f = [], [], set()
    for gt in gts:
        hit = next((i for i, f in enumerate(fs) if matches(gt, f)), None)
        if hit is not None:
            matched.append(gt["id"]); matched_f.add(hit)
        else:
            missed.append(gt["id"])
    extra = len(fs) - len(matched_f)
    return {"repo": repo, "gt": len(gts), "found": len(matched),
            "recall": len(matched) / max(1, len(gts)),
            "missed": missed, "extra": extra, "total_findings": len(fs),
            "credits": data.get("credits", {}).get("credits_total")}

def run_scan(repo: str, ensemble: int) -> None:
    cmd = [sys.executable, str(HERE / "scan.py"), str(TARGETS / repo)]
    if repo == "vibe-kanban":
        cmd += ["--include", "crates/server,crates/executors,crates/services,crates/local-deployment"]
    if ensemble > 1:
        cmd += ["--ensemble", str(ensemble)]
    print(f"  scanning {repo}…", file=sys.stderr)
    subprocess.run(cmd, check=False)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="*", help="subset to score (default all with ground truth)")
    ap.add_argument("--run", action="store_true", help="(re)scan before scoring")
    ap.add_argument("--ensemble", type=int, default=1)
    args = ap.parse_args()

    repos = args.repos or list(GROUND_TRUTH)
    if args.run:
        for r in repos:
            run_scan(r, args.ensemble)

    print(f"\n{'repo':16} {'recall':>8} {'found/gt':>9} {'extra':>6}   missed")
    print("-" * 74)
    tot_f = tot_g = 0
    for r in repos:
        s = score(r)
        if not s:
            print(f"{r:16} {'—':>8}   (no scan report — run: python scan.py targets/{r})")
            continue
        tot_f += s["found"]; tot_g += s["gt"]
        print(f"{r:16} {s['recall']*100:>7.0f}% {s['found']:>4}/{s['gt']:<4} "
              f"{s['extra']:>6}   {', '.join(s['missed']) or '-'}")
    print("-" * 74)
    if tot_g:
        print(f"{'OVERALL':16} {tot_f/tot_g*100:>7.0f}% {tot_f:>4}/{tot_g:<4}   "
              f"(recall of known vulnerabilities)")

if __name__ == "__main__":
    main()
