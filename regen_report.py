import json
import sys
from pathlib import Path

import scan

def main(json_path: str) -> None:
    d = json.loads(Path(json_path).read_text(encoding="utf-8"))
    root = Path(d["root"])
    findings = [scan.Finding(**f) for f in d["findings"]]
    guard = d.get("agent_prompt_track", [])
    demo = scan.guardrail_demo()
    saved = d.get("credits", {})
    scan.sie.METER.total = int(saved.get("credits_total", scan.sie.METER.total))
    scan.sie.METER.calls = int(saved.get("calls", scan.sie.METER.calls))
    scan.sie.METER.by_kind = dict(saved.get("by_kind", scan.sie.METER.by_kind))
    out_dir = root / ".sie_scan"
    md = scan.write_report(root, findings, guard, d.get("stats", {}),
                           d.get("elapsed_s", 0.0), out_dir, demo, write_json=False)
    print(md)

if __name__ == "__main__":
    main(sys.argv[1])
