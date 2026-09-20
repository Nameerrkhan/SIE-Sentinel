from __future__ import annotations

import ast
import json
import os
import pathlib
import re
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import quote

import httpx
import numpy as np

try:
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:
    from mcp.server.fastmcp import FastMCP as _Server

def _load_dotenv() -> None:
    envp = pathlib.Path(__file__).resolve().parent / ".env"
    if not envp.exists():
        return
    for line in envp.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))

_load_dotenv()

SIE_BASE_URL = os.environ.get("SIE_BASE_URL", "https://api.superlinked.com").rstrip("/")
SIE_API_KEY = os.environ.get("SIE_API_KEY", "")
ENCODE_MODEL = os.environ.get("SIE_ENCODE_MODEL", "Qwen/Qwen3-Embedding-4B")
SCORE_MODEL = os.environ.get("SIE_SCORE_MODEL", "Qwen/Qwen3-Reranker-4B")
EXTRACT_MODEL = os.environ.get("SIE_EXTRACT_MODEL", "fastino/gliner2-large-v1")
HTTP_TIMEOUT = float(os.environ.get("SIE_HTTP_TIMEOUT", "120"))
ENCODE_BATCH = int(os.environ.get("SIE_ENCODE_BATCH", "64"))

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".mypy_cache", ".pytest_cache", "dist", "build", ".next", "target",
    ".sie_index", ".idea", ".vscode", "vendor", "site-packages",
}
DEFAULT_EXTS = [
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".c",
    ".h", ".cpp", ".hpp", ".cs", ".rs", ".sol", ".sh", ".ps1", ".sql", ".yaml",
    ".yml", ".json", ".tf", ".html", ".md",
]

mcp = _Server("sie-code")

@dataclass
class Chunk:
    id: str
    ns: str
    file: str
    symbol: str
    language: str
    start_line: int
    end_line: int
    text: str

class Index:
    def __init__(self) -> None:
        self.chunks: dict[str, Chunk] = {}
        self.vectors: dict[str, np.ndarray] = {}
        self.root: str | None = None

    def clear_ns(self, ns: str) -> None:
        drop = [cid for cid, c in self.chunks.items() if c.ns == ns]
        for cid in drop:
            self.chunks.pop(cid, None)
            self.vectors.pop(cid, None)

    def add(self, chunk: Chunk, vec: np.ndarray) -> None:
        n = np.linalg.norm(vec)
        self.vectors[chunk.id] = vec / n if n else vec
        self.chunks[chunk.id] = chunk

    def matrix(self, ns: str | None) -> tuple[np.ndarray, list[str]]:
        ids = [cid for cid, c in self.chunks.items()
               if ns is None or c.ns == ns]
        if not ids:
            return np.empty((0, 0)), []
        return np.vstack([self.vectors[cid] for cid in ids]), ids

INDEX = Index()

def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if SIE_API_KEY:
        h["Authorization"] = f"Bearer {SIE_API_KEY}"
    return h

def _post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    url = f"{SIE_BASE_URL}{path}"
    try:
        r = httpx.post(url, json=body, headers=_headers(), timeout=HTTP_TIMEOUT)
    except httpx.ConnectError as e:
        raise RuntimeError(
            f"Cannot reach SIE at {SIE_BASE_URL}. Is the SIE server running? "
            f"(underlying error: {e})"
        ) from e
    if r.status_code >= 400:
        raise RuntimeError(f"SIE {path} returned {r.status_code}: {r.text[:500]}")
    return r.json()

def sie_encode(texts: list[str]) -> list[np.ndarray]:
    out: list[np.ndarray] = []
    for i in range(0, len(texts), ENCODE_BATCH):
        batch = texts[i:i + ENCODE_BATCH]
        body = {
            "items": [{"id": str(j), "text": t} for j, t in enumerate(batch)],
            "params": {"output_types": ["dense"], "output_dtype": "float32"},
        }
        resp = _post(f"/v1/encode/{quote(ENCODE_MODEL, safe='')}", body)
        items = resp.get("items", [])
        by_id = {str(it.get("id")): it for it in items}
        for j in range(len(batch)):
            it = by_id.get(str(j), items[j] if j < len(items) else {})
            dense = (it.get("dense") or {}).get("values") or []
            out.append(np.asarray(dense, dtype=np.float32))
    return out

def sie_score(query: str, candidates: list[tuple[str, str]]) -> list[tuple[str, float]] | None:
    body = {
        "query": {"id": "q", "text": query},
        "items": [{"id": cid, "text": text} for cid, text in candidates],
    }
    try:
        resp = _post(f"/v1/score/{quote(SCORE_MODEL, safe='')}", body)
    except RuntimeError:
        return None
    scores = resp.get("scores", [])
    ranked = sorted(scores, key=lambda s: s.get("score", 0.0), reverse=True)
    return [(s["item_id"], float(s.get("score", 0.0))) for s in ranked]

def sie_extract(text: str, labels: list[str]) -> dict[str, Any]:
    body = {
        "items": [{"id": "0", "text": text}],
        "params": {"labels": labels},
    }
    resp = _post(f"/v1/extract/{quote(EXTRACT_MODEL, safe='')}", body)
    items = resp.get("items", [])
    return items[0] if items else {}

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".jsx": "javascript", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cs": "csharp", ".rs": "rust",
    ".sol": "solidity", ".sh": "bash", ".ps1": "powershell", ".sql": "sql",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".tf": "terraform",
    ".html": "html", ".md": "markdown",
}
WINDOW_LINES = 60
WINDOW_OVERLAP = 12

def _lang(path: pathlib.Path) -> str:
    return LANG_BY_EXT.get(path.suffix.lower(), "text")

def chunk_python(rel: str, text: str) -> list[tuple[str, int, int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return chunk_generic(text)
    lines = text.splitlines()
    out: list[tuple[str, int, int, str]] = []

    def emit(name: str, node: ast.AST) -> None:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        body = "\n".join(lines[start - 1:end])
        out.append((name, start, end, body))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            emit(node.name + "()", node)
        elif isinstance(node, ast.ClassDef):
            start = node.lineno
            end = node.body[0].lineno if node.body else node.lineno
            out.append((f"class {node.name}", start, end,
                        "\n".join(lines[start - 1:end])))
    if not out:
        return chunk_generic(text)
    return out

DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:public|private|protected|static|async|final|func|fn|function|def|class|interface|struct|impl|contract|module)\b.*",
    re.MULTILINE,
)

def chunk_generic(text: str) -> list[tuple[str, int, int, str]]:
    lines = text.splitlines()
    if not lines:
        return []
    out: list[tuple[str, int, int, str]] = []
    step = WINDOW_LINES - WINDOW_OVERLAP
    for start in range(0, len(lines), step):
        window = lines[start:start + WINDOW_LINES]
        if not any(l.strip() for l in window):
            continue
        body = "\n".join(window)
        m = DEF_RE.search(body)
        symbol = m.group(0).strip()[:80] if m else f"lines {start + 1}"
        out.append((symbol, start + 1, start + len(window), body))
        if start + WINDOW_LINES >= len(lines):
            break
    return out

def chunk_file(path: pathlib.Path, rel: str) -> list[Chunk]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lang = _lang(path)
    raw = chunk_python(rel, text) if lang == "python" else chunk_generic(text)
    chunks = []
    for i, (symbol, s, e, body) in enumerate(raw):
        if not body.strip():
            continue
        chunks.append(Chunk(
            id=f"code::{rel}::{i}",
            ns="code",
            file=rel,
            symbol=symbol,
            language=lang,
            start_line=s,
            end_line=e,
            text=body[:8000],
        ))
    return chunks

def cosine_shortlist(qvec: np.ndarray, ns: str | None, k: int) -> list[str]:
    mat, ids = INDEX.matrix(ns)
    if not ids:
        return []
    n = np.linalg.norm(qvec)
    q = qvec / n if n else qvec
    sims = mat @ q
    order = np.argsort(-sims)[:k]
    return [ids[i] for i in order]

@mcp.tool()
def sie_health() -> str:
    """Check that SIE is reachable + the key/model work by embedding one token,
    and report the configured models."""
    try:
        v = sie_encode(["ping"])[0]
        status = f"OK (encode returned {v.size}-dim vector)" if v.size else "ERROR: empty vector"
    except Exception as e:
        status = f"FAILED ({e})"
    return json.dumps({
        "sie_base_url": SIE_BASE_URL,
        "auth": "bearer key set" if SIE_API_KEY else "NO KEY (set SIE_API_KEY)",
        "encode_check": status,
        "encode_model": ENCODE_MODEL,
        "score_model": SCORE_MODEL,
        "extract_model": EXTRACT_MODEL,
        "indexed_root": INDEX.root,
        "code_chunks": sum(1 for c in INDEX.chunks.values() if c.ns == "code"),
        "reference_chunks": sum(1 for c in INDEX.chunks.values() if c.ns == "reference"),
    }, indent=2)

@mcp.tool()
def index_repo(path: str, extensions: list[str] | None = None,
               max_file_kb: int = 400) -> str:
    """Walk a repository, chunk its code (AST for Python, sliding window otherwise),
    embed every chunk via SIE /v1/encode, and store the vectors locally.

    Call this once per codebase before searching. Re-running replaces the code index.

    Args:
        path: absolute path to the repo root to index.
        extensions: file extensions to include (defaults to a broad code/config set).
        max_file_kb: skip files larger than this (keeps generated/minified junk out).
    """
    root = pathlib.Path(path).expanduser().resolve()
    if not root.is_dir():
        return f"Error: {root} is not a directory."
    exts = set(e if e.startswith(".") else f".{e}" for e in (extensions or DEFAULT_EXTS))

    INDEX.clear_ns("code")
    INDEX.root = str(root)

    all_chunks: list[Chunk] = []
    skipped_big = 0
    files_seen = 0
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in exts:
            continue
        if p.stat().st_size > max_file_kb * 1024:
            skipped_big += 1
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        files_seen += 1
        all_chunks.extend(chunk_file(p, rel))

    if not all_chunks:
        return f"No indexable files found under {root} (extensions={sorted(exts)})."

    vecs = sie_encode([c.text for c in all_chunks])
    added = 0
    for c, v in zip(all_chunks, vecs):
        if v.size:
            INDEX.add(c, v)
            added += 1

    return json.dumps({
        "root": str(root),
        "files_indexed": files_seen,
        "chunks_embedded": added,
        "files_skipped_too_big": skipped_big,
        "next": "Use search_code(query=...) to find relevant code.",
    }, indent=2)

@mcp.tool()
def add_reference(name: str, text: str) -> str:
    """Embed a security cheat-sheet / heuristic / note into the 'reference' namespace
    so it can be retrieved alongside code (e.g. OWASP patterns, sink lists).

    Call multiple times to build up a knowledge base; each call adds one document.
    """
    vec = sie_encode([text])[0]
    if not vec.size:
        return "Error: SIE returned an empty embedding."
    cid = f"ref::{name}"
    INDEX.add(Chunk(id=cid, ns="reference", file=name, symbol=name,
                    language="note", start_line=0, end_line=0, text=text[:8000]), vec)
    return f"Indexed reference '{name}' ({len(text)} chars)."

@mcp.tool()
def search_code(query: str, top_k: int = 8, path_contains: str = "",
                namespace: str = "code", shortlist: int = 40,
                rerank: bool = True) -> str:
    """Semantic search over the indexed codebase. Returns compact hits
    (file, line range, symbol, score, snippet) so the caller does NOT need to
    read whole files.

    Pipeline: encode query -> cosine shortlist -> SIE /v1/score rerank -> top_k.

    Args:
        query: natural-language or code-intent query
               (e.g. "where user input reaches a SQL query").
        top_k: number of results to return.
        path_contains: only keep hits whose file path contains this substring.
        namespace: "code", "reference", or "all".
        shortlist: how many candidates to pull with cheap cosine before reranking.
        rerank: use the SIE cross-encoder to reorder (falls back to cosine if the
                reranker model is unavailable).
    """
    if not INDEX.chunks:
        return "Index is empty. Call index_repo(path=...) first."
    ns = None if namespace == "all" else namespace
    qvec = sie_encode([query])[0]
    if not qvec.size:
        return "Error: SIE returned an empty query embedding."

    cand_ids = cosine_shortlist(qvec, ns, max(shortlist, top_k))
    if path_contains:
        cand_ids = [cid for cid in cand_ids if path_contains in INDEX.chunks[cid].file]
    if not cand_ids:
        return "No matches."

    ordered: list[tuple[str, float | None]]
    used_rerank = False
    if rerank:
        pairs = [(cid, INDEX.chunks[cid].text) for cid in cand_ids]
        reranked = sie_score(query, pairs)
        if reranked is not None:
            keep = {cid for cid in cand_ids}
            ordered = [(cid, sc) for cid, sc in reranked if cid in keep][:top_k]
            used_rerank = True
        else:
            ordered = [(cid, None) for cid in cand_ids[:top_k]]
    else:
        ordered = [(cid, None) for cid in cand_ids[:top_k]]

    results = []
    for rank, (cid, score) in enumerate(ordered):
        c = INDEX.chunks[cid]
        snippet = c.text if len(c.text) <= 600 else c.text[:600] + "\n… (truncated)"
        results.append({
            "rank": rank,
            "score": round(score, 4) if score is not None else None,
            "chunk_id": c.id,
            "location": f"{c.file}:{c.start_line}-{c.end_line}",
            "symbol": c.symbol,
            "language": c.language,
            "snippet": snippet,
        })
    return json.dumps({
        "query": query,
        "reranked": used_rerank,
        "results": results,
        "hint": "Call get_chunk(chunk_id) for a full chunk, or read the file at 'location'.",
    }, indent=2)

@mcp.tool()
def get_chunk(chunk_id: str) -> str:
    """Return the full text of a single chunk by its chunk_id (from search_code)."""
    c = INDEX.chunks.get(chunk_id)
    if not c:
        return f"No chunk with id {chunk_id}."
    return json.dumps({
        "chunk_id": c.id,
        "location": f"{c.file}:{c.start_line}-{c.end_line}",
        "symbol": c.symbol,
        "language": c.language,
        "text": c.text,
    }, indent=2)

@mcp.tool()
def extract_structure(file_path: str,
                      labels: list[str] | None = None,
                      max_chars: int = 6000) -> str:
    """Run SIE /v1/extract over a file to pull structured entities
    (default labels target security review: secrets, endpoints, functions, etc.).

    Args:
        file_path: path to the file (absolute, or relative to the indexed root).
        labels: entity labels to extract.
        max_chars: cap the text sent to SIE.
    """
    labels = labels or ["function", "endpoint", "secret", "credential",
                        "url", "import", "environment variable"]
    p = pathlib.Path(file_path)
    if not p.is_absolute() and INDEX.root:
        p = pathlib.Path(INDEX.root) / file_path
    if not p.is_file():
        return f"No file at {p}."
    text = p.read_text(encoding="utf-8", errors="replace")[:max_chars]
    return json.dumps(sie_extract(text, labels), indent=2)

try:
    import sie_client as _sc
except Exception:
    _sc = None

@mcp.tool()
def check_prompt_injection(text: str, labels: list[str] | None = None) -> str:
    """Classify a string for prompt-injection / jailbreak risk with the
    open-source gliguard LLM-guardrail model (fastino/gliguard-LLMGuardrails-300M).

    Use on any text that could reach an autonomous agent's prompt — a task
    description, issue/PR body, README, git diff, or MCP tool output — to see
    whether it reads as an injection attempt.

    Returns JSON: {top_label, top_score, all:[{label,score}]}.
    """
    if _sc is None:
        return "Error: sie_client not importable (place sie_client.py beside this file)."
    return json.dumps(_sc.guardrail(text, labels), indent=2)

@mcp.tool()
def analyze_chunks(question: str, chunk_ids: list[str], deep: bool = True) -> str:
    """Reason over specific indexed chunks with an open-source Qwen model to
    confirm or disprove a suspected vulnerability.

    Pulls the named chunks (from search_code) as context and asks the model the
    question. `deep=True` uses the larger analyst model (Qwen3.8-27B), False uses
    the fast triage model (Qwen3.5-4B).

    Args:
        question: what to determine (e.g. "does untrusted input reach this spawn?").
        chunk_ids: chunk_ids returned by search_code.
        deep: pick the analyst (True) or triage (False) model.
    """
    if _sc is None:
        return "Error: sie_client not importable (place sie_client.py beside this file)."
    ctx = []
    for cid in chunk_ids:
        c = INDEX.chunks.get(cid)
        if c:
            ctx.append(f"# {c.file}:{c.start_line}-{c.end_line} {c.symbol}\n{c.text[:3000]}")
    if not ctx:
        return "No matching chunks. Pass chunk_ids from search_code."
    sys_p = ("You are a precise application-security analyst. Answer only from the "
             "code shown. Give a concrete source->sink path and a concrete trigger, "
             "or explain why it is not exploitable.")
    user = f"{question}\n\nCode:\n```\n" + "\n\n".join(ctx)[:12000] + "\n```"
    fn = _sc.analyst if deep else _sc.triage
    return fn(sys_p, user, max_tokens=900)

@mcp.tool()
def credit_usage() -> str:
    """Report SIE credits spent this session (by the drill-down tools) so the
    reviewer can watch the budget."""
    if _sc is None:
        return "Error: sie_client not importable."
    return json.dumps(_sc.METER.summary(), indent=2)

if __name__ == "__main__":
    mcp.run()
