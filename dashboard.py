from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
TARGETS = HERE / "targets"
PY = sys.executable
IN_SCOPE_HINT = ["vibe-kanban", "Who-Targets-Me", "pizauth", "snare"]

_health_cache = {"ts": 0.0, "data": None}

def list_repos() -> list[dict]:
    out = []
    if not TARGETS.is_dir():
        return out
    for d in sorted(TARGETS.iterdir()):
        if not d.is_dir():
            continue
        scan_json = d / ".sie_scan" / f"scan-{d.name}.json"
        pent_json = d / ".sie_scan" / f"pentest-{d.name}.json"
        info = {"name": d.name, "has_scan": scan_json.is_file(),
                "has_pentest": pent_json.is_file(), "sev": {}, "findings": 0}
        if info["has_scan"]:
            try:
                data = json.loads(scan_json.read_text(encoding="utf-8"))
                fs = data.get("findings", [])
                info["findings"] = len(fs)
                for f in fs:
                    s = f.get("severity", "?")
                    info["sev"][s] = info["sev"].get(s, 0) + 1
                info["credits"] = data.get("credits", {}).get("credits_total")
            except (OSError, ValueError):
                pass
        out.append(info)
    return out

def read_report(kind: str, repo: str) -> dict | None:
    p = TARGETS / repo / ".sie_scan" / f"{kind}-{repo}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

def sie_health() -> dict:
    if time.time() - _health_cache["ts"] < 60 and _health_cache["data"]:
        return _health_cache["data"]
    try:
        import sie_client as sie
        data = sie.health()
    except Exception as e:
        data = {"encode_check": f"FAILED ({e})"}
    _health_cache.update(ts=time.time(), data=data)
    return data

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "sentinel/1.0"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _begin_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def _emit(self, obj) -> bool:
        try:
            self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, OSError):
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._serve_file("dashboard.html", "text/html; charset=utf-8")
        if u.path == "/api/repos":
            return self._json({"repos": list_repos()})
        if u.path == "/api/health":
            return self._json(sie_health())
        if u.path == "/api/report":
            q = parse_qs(u.query)
            kind = (q.get("kind") or ["scan"])[0]
            repo = (q.get("repo") or [""])[0]
            rep = read_report(kind, repo)
            return self._json(rep or {}, 200 if rep else 404)
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        body = self._body()
        if u.path == "/api/scan/run":
            return self._run_scan(body)
        if u.path == "/api/pentest/run":
            return self._run_pentest(body)
        if u.path == "/api/monitor/run":
            return self._run_monitor(body)
        return self._json({"error": "not found"}, 404)

    def _serve_file(self, name, ctype):
        p = HERE / name
        if not p.is_file():
            return self._json({"error": f"{name} missing"}, 404)
        body = p.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stream_proc(self, cmd, pipe: str, wrap):
        self._begin_stream()
        proc = subprocess.Popen(
            cmd, cwd=str(HERE),
            stdout=subprocess.PIPE if pipe == "stdout" else subprocess.DEVNULL,
            stderr=subprocess.PIPE if pipe == "stderr" else subprocess.DEVNULL,
            text=True, bufsize=1, encoding="utf-8", errors="replace")
        stream = proc.stdout if pipe == "stdout" else proc.stderr
        try:
            for line in stream:
                line = line.rstrip("\n")
                if not line:
                    continue
                if not self._emit(wrap(line)):
                    proc.terminate()
                    return None
            proc.wait(timeout=10)
        except Exception as e:
            self._emit({"t": "err", "msg": str(e)})
            proc.terminate()
        return proc.returncode

    def _run_scan(self, body):
        repo = body.get("repo", "")
        rp = TARGETS / repo
        if not rp.is_dir():
            return self._json({"error": "unknown repo"}, 400)
        cmd = [PY, str(HERE / "scan.py"), str(rp)]
        if body.get("fast"):
            cmd.append("--fast")
        if body.get("include"):
            cmd += ["--include", body["include"]]
        if body.get("pentest"):
            cmd.append("--pentest")
        code = self._stream_proc(cmd, "stderr", lambda l: {"t": "log", "line": l})
        if code is not None:
            self._emit({"t": "done", "report": read_report("scan", repo)})

    def _run_pentest(self, body):
        repo = body.get("repo", "")
        rp = TARGETS / repo
        if not (rp / ".sie_scan" / f"scan-{repo}.json").is_file():
            return self._json({"error": "no scan yet — run a scan first"}, 400)
        cmd = [PY, str(HERE / "pentest.py"), str(rp)]
        if body.get("min_severity"):
            cmd += ["--min-severity", body["min_severity"]]
        code = self._stream_proc(cmd, "stderr", lambda l: {"t": "log", "line": l})
        if code is not None:
            self._emit({"t": "done", "report": read_report("pentest", repo)})

    def _run_monitor(self, body):
        cmd = [PY, str(HERE / "monitor.py"), "--json",
               "--action", body.get("action", "block"),
               "--threshold", str(body.get("threshold", 0.5))]
        repo = body.get("repo")
        if repo and (TARGETS / repo).is_dir():
            cmd += ["--repo", str(TARGETS / repo)]
        elif body.get("file"):
            cmd += ["--file", body["file"]]
        else:
            cmd += ["--demo", "--demo-count", str(int(body.get("count", 30))),
                    "--attack-rate", str(body.get("attack_rate", 0.4))]
        self._stream_proc(cmd, "stdout", lambda l: _monitor_line(l))
        self._emit({"t": "done"})

def _monitor_line(line: str) -> dict:
    try:
        return {"t": "event", "rec": json.loads(line)}
    except ValueError:
        return {"t": "log", "line": line}

def main():
    ap = argparse.ArgumentParser(description="Local control panel for the SIE security tools")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"Sentinel control panel on {url}  (Ctrl-C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")

if __name__ == "__main__":
    main()
