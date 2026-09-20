from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx
import numpy as np

def _load_dotenv(path: str = ".env") -> None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, val)
    except FileNotFoundError:
        pass

_load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
_load_dotenv()

BASE_URL = os.environ.get("SIE_BASE_URL", "https://api.superlinked.com").rstrip("/")
API_KEY = os.environ.get("SIE_API_KEY", "")
ENCODE_MODEL = os.environ.get("SIE_ENCODE_MODEL", "Qwen/Qwen3-Embedding-4B")
SPARSE_MODEL = os.environ.get("SIE_SPARSE_MODEL", "prithivida/Splade_PP_en_v2")
SCORE_MODEL = os.environ.get("SIE_SCORE_MODEL", "Qwen/Qwen3-Reranker-4B")
EXTRACT_MODEL = os.environ.get("SIE_EXTRACT_MODEL", "fastino/gliner2-large-v1")
GUARD_MODEL = os.environ.get("SIE_GUARD_MODEL", "fastino/gliguard-LLMGuardrails-300M")
TRIAGE_MODEL = os.environ.get("SIE_TRIAGE_MODEL", "Qwen/Qwen3.5-4B")
ANALYST_MODEL = os.environ.get("SIE_ANALYST_MODEL", "Qwen/Qwen3.8-27B-FP8")

HTTP_TIMEOUT = float(os.environ.get("SIE_HTTP_TIMEOUT", "180"))
MAX_RETRIES = int(os.environ.get("SIE_MAX_RETRIES", "6"))
ENCODE_BATCH = int(os.environ.get("SIE_ENCODE_BATCH", "64"))
MAX_CONCURRENCY = int(os.environ.get("SIE_MAX_CONCURRENCY", "3"))

@dataclass
class Meter:
    total: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    calls: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, kind: str, credits: int) -> None:
        with self._lock:
            self.total += credits
            self.calls += 1
            self.by_kind[kind] = self.by_kind.get(kind, 0) + credits

    def summary(self) -> dict[str, Any]:
        return {"credits_total": self.total, "calls": self.calls,
                "by_kind": dict(sorted(self.by_kind.items(), key=lambda kv: -kv[1]))}

METER = Meter()

def _credits(resp: dict[str, Any]) -> int:
    u = resp.get("usage") or {}
    try:
        return int(u.get("credits_charged", 0) or 0)
    except (TypeError, ValueError):
        return 0

class SIEError(RuntimeError):
    pass

class SIEInsufficientCredits(SIEError):
    pass

_client: httpx.Client | None = None
_inflight = threading.Semaphore(MAX_CONCURRENCY)

def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(
            timeout=HTTP_TIMEOUT,
            limits=httpx.Limits(max_connections=16, max_keepalive_connections=16),
            headers={"Content-Type": "application/json"},
        )
    return _client

def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    return h

_RETRY_STATUS = {429, 500, 502, 503, 504}

def _post(path: str, body: dict[str, Any], kind: str = "misc") -> dict[str, Any]:
    url = f"{BASE_URL}{path}"
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            with _inflight:
                r = _get_client().post(url, json=body, headers=_headers())
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError,
                httpx.WriteError, httpx.PoolTimeout) as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                time.sleep(_backoff(attempt))
                continue
            raise SIEError(f"Cannot reach SIE at {BASE_URL}{path} after "
                           f"{MAX_RETRIES + 1} tries: {e}") from e

        if r.status_code == 402:
            raise SIEInsufficientCredits(
                "SIE returned 402 INSUFFICIENT_CREDITS. Ask the organizers to top up "
                "(console.superlinked.com / Discord).")
        if r.status_code in _RETRY_STATUS and attempt < MAX_RETRIES:
            ra = r.headers.get("retry-after")
            delay = float(ra) if (ra and ra.isdigit()) else _backoff(attempt)
            time.sleep(delay)
            continue
        if r.status_code >= 400:
            raise SIEError(f"SIE {path} -> {r.status_code}: {r.text[:400]}")

        resp = r.json()
        METER.add(kind, _credits(resp))
        return resp

    raise SIEError(f"SIE {path} exhausted retries: {last_exc}")

def _backoff(attempt: int) -> float:
    return min(20.0, (0.5 * (2 ** attempt))) * (0.5 + random.random())

def encode_dense(texts: list[str]) -> list[np.ndarray]:
    out: list[np.ndarray] = []
    for i in range(0, len(texts), ENCODE_BATCH):
        batch = texts[i:i + ENCODE_BATCH]
        body = {
            "items": [{"id": str(j), "text": t} for j, t in enumerate(batch)],
            "params": {"output_types": ["dense"], "output_dtype": "float32"},
        }
        resp = _post(f"/v1/encode/{quote(ENCODE_MODEL, safe='')}", body, kind="encode_dense")
        items = resp.get("items", [])
        by_id = {str(it.get("id")): it for it in items}
        for j in range(len(batch)):
            it = by_id.get(str(j), items[j] if j < len(items) else {})
            dense = (it.get("dense") or {}).get("values") or []
            out.append(np.asarray(dense, dtype=np.float32))
    return out

def encode_sparse(texts: list[str]) -> list[dict[int, float]]:
    out: list[dict[int, float]] = []
    for i in range(0, len(texts), ENCODE_BATCH):
        batch = texts[i:i + ENCODE_BATCH]
        body = {
            "items": [{"id": str(j), "text": t} for j, t in enumerate(batch)],
            "params": {"output_types": ["sparse"]},
        }
        resp = _post(f"/v1/encode/{quote(SPARSE_MODEL, safe='')}", body, kind="encode_sparse")
        items = resp.get("items", [])
        by_id = {str(it.get("id")): it for it in items}
        for j in range(len(batch)):
            it = by_id.get(str(j), items[j] if j < len(items) else {})
            sp = it.get("sparse") or {}
            idxs = sp.get("indices") or []
            vals = sp.get("values") or []
            out.append({int(k): float(v) for k, v in zip(idxs, vals)})
    return out

def score(query: str, candidates: list[tuple[str, str]]) -> list[tuple[str, float]] | None:
    if not candidates:
        return []
    body = {
        "query": {"id": "q", "text": query},
        "items": [{"id": cid, "text": text} for cid, text in candidates],
    }
    try:
        resp = _post(f"/v1/score/{quote(SCORE_MODEL, safe='')}", body, kind="score")
    except SIEInsufficientCredits:
        raise
    except SIEError:
        return None
    scores = resp.get("scores", [])
    ranked = sorted(scores, key=lambda s: s.get("score", 0.0), reverse=True)
    return [(s["item_id"], float(s.get("score", 0.0))) for s in ranked]

def extract(text: str, labels: list[str]) -> dict[str, Any]:
    body = {"items": [{"id": "0", "text": text}], "params": {"labels": labels}}
    resp = _post(f"/v1/extract/{quote(EXTRACT_MODEL, safe='')}", body, kind="extract")
    items = resp.get("items", [])
    return items[0] if items else {}

GUARD_LABELS = ["prompt injection", "jailbreak", "safe"]

def guardrail(text: str, labels: list[str] | None = None) -> dict[str, Any]:
    labels = labels or GUARD_LABELS
    body = {"items": [{"id": "0", "text": text}], "params": {"labels": labels}}
    resp = _post(f"/v1/extract/{quote(GUARD_MODEL, safe='')}", body, kind="guardrail")
    items = resp.get("items", [])
    cls = (items[0].get("classifications") if items else []) or []
    cls = sorted(cls, key=lambda c: c.get("score", 0.0), reverse=True)
    top = cls[0] if cls else {"label": "safe", "score": 0.0}
    return {"top_label": top.get("label", "safe"),
            "top_score": float(top.get("score", 0.0)),
            "all": [{"label": c.get("label"), "score": float(c.get("score", 0.0))} for c in cls]}

def chat(model: str, system: str, user: str, *, max_tokens: int = 1200,
         temperature: float = 0.0, kind: str = "chat") -> str:
    body = {
        "model": model,
        "messages": (([{"role": "system", "content": system}] if system else [])
                     + [{"role": "user", "content": user}]),
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    resp = _post("/v1/chat/completions", body, kind=kind)
    choices = resp.get("choices") or []
    if not choices:
        return ""
    return (choices[0].get("message") or {}).get("content", "") or ""

def triage(system: str, user: str, **kw) -> str:
    return chat(TRIAGE_MODEL, system, user, kind="triage", **kw)

def analyst(system: str, user: str, **kw) -> str:
    return chat(ANALYST_MODEL, system, user, kind="analyst", **kw)

def health() -> dict[str, Any]:
    info: dict[str, Any] = {
        "base_url": BASE_URL,
        "auth": "bearer key set" if API_KEY else "NO KEY (set SIE_API_KEY)",
        "models": {
            "encode": ENCODE_MODEL, "sparse": SPARSE_MODEL, "score": SCORE_MODEL,
            "extract": EXTRACT_MODEL, "guard": GUARD_MODEL,
            "triage": TRIAGE_MODEL, "analyst": ANALYST_MODEL,
        },
    }
    try:
        v = encode_dense(["ping"])[0]
        info["encode_check"] = f"OK ({v.shape[0]}-dim)" if v.size else "ERROR: empty vector"
    except Exception as e:
        info["encode_check"] = f"FAILED ({e})"
    return info

if __name__ == "__main__":
    import json
    print(json.dumps(health(), indent=2))
