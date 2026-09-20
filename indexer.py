from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np

import sie_client as sie

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".mypy_cache", ".pytest_cache", "dist", "build", ".next", "target",
    ".sie_index", ".idea", ".vscode", "vendor", "site-packages", "coverage",
}
DEFAULT_EXTS = [
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".java", ".kt", ".go", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".cs", ".rs", ".sol", ".sh", ".ps1", ".sql", ".yaml", ".yml", ".toml",
    ".json", ".tf", ".html", ".md", ".env", ".conf",
]
LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".vue": "vue", ".svelte": "svelte", ".java": "java", ".kt": "kotlin",
    ".go": "go", ".rb": "ruby", ".php": "php", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp", ".cs": "csharp", ".rs": "rust",
    ".sol": "solidity", ".sh": "bash", ".ps1": "powershell", ".sql": "sql",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".json": "json",
    ".tf": "terraform", ".html": "html", ".md": "markdown", ".env": "dotenv",
    ".conf": "conf",
}

WINDOW_LINES = 60
WINDOW_OVERLAP = 12
MAX_CHUNK_CHARS = 8000

DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:pub\s+)?(?:public|private|protected|static|async|final|"
    r"unsafe|func|fn|function|def|class|interface|struct|impl|trait|contract|"
    r"module|const|let|var)\b.*",
    re.MULTILINE,
)

@dataclass
class Chunk:
    id: str
    file: str
    symbol: str
    language: str
    start_line: int
    end_line: int
    text: str

def chunk_python(text: str) -> list[tuple[str, int, int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return chunk_generic(text)
    lines = text.splitlines()
    out: list[tuple[str, int, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sym = f"{node.name}()"
        elif isinstance(node, ast.ClassDef):
            sym = f"class {node.name}"
        else:
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", start) or start
        body = "\n".join(lines[start - 1:end])
        if body.strip():
            out.append((sym, start, end, body))
    return out or chunk_generic(text)

def chunk_generic(text: str) -> list[tuple[str, int, int, str]]:
    lines = text.splitlines()
    out: list[tuple[str, int, int, str]] = []
    step = WINDOW_LINES - WINDOW_OVERLAP
    for start in range(0, max(1, len(lines)), step):
        window = lines[start:start + WINDOW_LINES]
        body = "\n".join(window)
        if not body.strip():
            continue
        m = DEF_RE.search(body)
        end = start + len(window)
        sym = m.group(0).strip()[:80] if m else f"lines {start + 1}-{end}"
        out.append((sym, start + 1, end, body))
        if start + WINDOW_LINES >= len(lines):
            break
    return out

def iter_files(root: Path, exts: list[str], max_file_kb: int):
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_parts = Path(dirpath).resolve().relative_to(root).parts
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in exts and fn not in ("Dockerfile", "Makefile"):
                continue
            try:
                if p.stat().st_size > max_file_kb * 1024:
                    yield p, True
                    continue
            except OSError:
                continue
            yield p, False

class Index:
    def __init__(self, root: str):
        self.root = str(Path(root).resolve())
        self.chunks: dict[str, Chunk] = {}
        self.dense: dict[str, np.ndarray] = {}
        self.sparse: dict[str, dict[int, float]] = {}

    @property
    def cache_dir(self) -> Path:
        return Path(self.root) / ".sie_index"

    def save(self) -> None:
        d = self.cache_dir
        d.mkdir(exist_ok=True)
        with open(d / "chunks.json", "w", encoding="utf-8") as fh:
            json.dump({cid: asdict(c) for cid, c in self.chunks.items()}, fh)
        ids = list(self.dense.keys())
        if ids:
            mat = np.vstack([self.dense[i] for i in ids])
            np.savez_compressed(d / "dense.npz", ids=np.array(ids), mat=mat)
        with open(d / "sparse.json", "w", encoding="utf-8") as fh:
            json.dump({cid: {str(k): v for k, v in sp.items()}
                       for cid, sp in self.sparse.items()}, fh)
        with open(d / "meta.json", "w", encoding="utf-8") as fh:
            json.dump({"root": self.root, "chunks": len(self.chunks)}, fh)

    @classmethod
    def load(cls, root: str) -> "Index | None":
        idx = cls(root)
        d = idx.cache_dir
        if not (d / "chunks.json").exists():
            return None
        try:
            with open(d / "chunks.json", "r", encoding="utf-8") as fh:
                idx.chunks = {cid: Chunk(**c) for cid, c in json.load(fh).items()}
            if (d / "dense.npz").exists():
                z = np.load(d / "dense.npz", allow_pickle=True)
                for cid, vec in zip(z["ids"].tolist(), z["mat"]):
                    idx.dense[cid] = np.asarray(vec, dtype=np.float32)
            if (d / "sparse.json").exists():
                with open(d / "sparse.json", "r", encoding="utf-8") as fh:
                    idx.sparse = {cid: {int(k): float(v) for k, v in sp.items()}
                                  for cid, sp in json.load(fh).items()}
        except (OSError, ValueError, KeyError):
            return None
        return idx

    def add(self, chunk: Chunk, dvec: np.ndarray, svec: dict[int, float]) -> None:
        n = float(np.linalg.norm(dvec))
        self.dense[chunk.id] = dvec / n if n else dvec
        self.sparse[chunk.id] = svec
        self.chunks[chunk.id] = chunk

    def search(self, query: str, k: int = 40, path_contains: str = "",
               alpha: float = 0.65) -> list[tuple[str, float]]:
        ids = [cid for cid, c in self.chunks.items()
               if not path_contains or path_contains.lower() in c.file.lower()]
        if not ids:
            return []
        qd = sie.encode_dense([query])[0]
        qs = sie.encode_sparse([query])[0]
        nq = float(np.linalg.norm(qd))
        qd = qd / nq if nq else qd

        dense_scores = np.array([float(self.dense[cid] @ qd) for cid in ids])
        sparse_scores = np.array([_sparse_dot(qs, self.sparse.get(cid, {})) for cid in ids])
        fused = alpha * _minmax(dense_scores) + (1 - alpha) * _minmax(sparse_scores)
        order = np.argsort(-fused)[:k]
        return [(ids[i], float(fused[i])) for i in order]

def _sparse_dot(a: dict[int, float], b: dict[int, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(w * b.get(t, 0.0) for t, w in a.items())

def _minmax(x: np.ndarray) -> np.ndarray:
    if x.size == 0:
        return x
    lo, hi = float(x.min()), float(x.max())
    if hi - lo < 1e-9:
        return np.zeros_like(x)
    return (x - lo) / (hi - lo)

def build_index(root: str, exts: list[str] | None = None, max_file_kb: int = 500,
                on_progress=None, include: list[str] | None = None) -> tuple[Index, dict]:
    exts = [e if e.startswith(".") else "." + e for e in (exts or DEFAULT_EXTS)]
    root_path = Path(root)
    if not root_path.is_dir():
        raise NotADirectoryError(f"{root} is not a directory")
    include = [i.replace("\\", "/") for i in include] if include else None

    idx = Index(root)
    chunk_texts: list[str] = []
    chunks: list[Chunk] = []
    skipped_big = 0
    files = 0

    for p, too_big in iter_files(root_path, exts, max_file_kb):
        if too_big:
            skipped_big += 1
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not text.strip():
            continue
        rel = p.resolve().relative_to(root_path.resolve()).as_posix()
        if include and not any(inc in rel for inc in include):
            continue
        lang = LANG_BY_EXT.get(p.suffix.lower(), "text")
        raw = chunk_python(text) if lang == "python" else chunk_generic(text)
        files += 1
        for i, (sym, s, e, body) in enumerate(raw):
            body = body[:MAX_CHUNK_CHARS]
            cid = f"{rel}::{i}"
            chunks.append(Chunk(cid, rel, sym, lang, s, e, body))
            chunk_texts.append(f"[{lang}] {rel} {sym}\n{body}")

    if not chunks:
        raise ValueError(f"No indexable files under {root} (exts={exts})")

    BATCH = sie.ENCODE_BATCH
    for i in range(0, len(chunk_texts), BATCH):
        batch_texts = chunk_texts[i:i + BATCH]
        batch_chunks = chunks[i:i + BATCH]
        dvecs = sie.encode_dense(batch_texts)
        svecs = sie.encode_sparse(batch_texts)
        for c, dv, sv in zip(batch_chunks, dvecs, svecs):
            if dv.size:
                idx.add(c, dv, sv)
        if on_progress:
            on_progress(min(i + BATCH, len(chunk_texts)), len(chunk_texts))

    idx.save()
    stats = {"root": idx.root, "files_indexed": files,
             "chunks_embedded": len(idx.chunks),
             "files_skipped_too_big": skipped_big}
    return idx, stats

def get_or_build(root: str, rebuild: bool = False, on_progress=None,
                 include: list[str] | None = None) -> tuple[Index, dict]:
    if not rebuild and not include:
        cached = Index.load(root)
        if cached and cached.dense:
            return cached, {"root": cached.root, "chunks_embedded": len(cached.chunks),
                            "cached": True}
    return build_index(root, on_progress=on_progress, include=include)
