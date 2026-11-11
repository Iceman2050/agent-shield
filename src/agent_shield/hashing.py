"""File hashing and inventory.

Adapted from Iceman2050/plugin-provenance-verifier (provenance/scanner.py:
hash_file, inventory_files) — same author, consolidated here.
"""
import hashlib
import os

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def hash_file(path):
    """Streaming sha256 of a file's bytes."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory_files(root):
    """Walk root -> list of {path (relative), sha256, size, executable}.

    Sorted by relative path for deterministic output.
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                digest = hash_file(full)
                size = os.path.getsize(full)
            except OSError:
                continue
            out.append({
                "path": rel,
                "sha256": digest,
                "size": size,
                "executable": os.access(full, os.X_OK)
                or os.path.splitext(fn)[1].lower() in SCRIPT_EXTS,
            })
    return out


SCRIPT_EXTS = {".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}
TEXT_EXTS = SCRIPT_EXTS | {".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".cfg"}


def read_text(path, limit=2_000_000):
    """Read a text file defensively; '' on any failure or oversize."""
    try:
        if os.path.getsize(path) > limit:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""
