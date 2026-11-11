"""Lockfile support: `lock` records approved per-file hashes + metadata;
`diff` compares the current tree against that record.

Adapted in pattern from Iceman2050/plugin-provenance-verifier
(provenance/snapshot.py + differ.py) — same author, consolidated here.
"""
import json
import os

from . import __version__
from .discovery import discover
from .hashing import inventory_files
from .sbom import LOCK_NAME, _now, scan_artifact


def build_lock(root):
    """Lock record for every artifact under root: per-file sha256 + metadata."""
    root = os.path.abspath(root)
    entries = {}
    for art in discover(root):
        record = scan_artifact(art, root)
        key = record["source"] if record["kind"] != "mcp-config" else record["source"]
        entries[key] = {
            "name": record["name"],
            "kind": record["kind"],
            "version": record["version"],
            "commit": record["commit"],
            "files": {f["path"]: f["sha256"] for f in record["files"]},
        }
    return {"tool": "agent-shield", "tool_version": __version__,
            "locked_at": _now(), "root": root, "artifacts": entries}


def write_lock(root, out_path=None):
    lock = build_lock(root)
    out_path = out_path or os.path.join(os.path.abspath(root), LOCK_NAME)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(lock, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return out_path, lock


def load_lock(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def diff(root, lock_path=None):
    """Compare current tree against the lockfile.

    Returns dict with added/removed/changed file lists per artifact plus
    added/removed artifacts. File keys are 'artifact_relpath'.
    """
    root = os.path.abspath(root)
    lock_path = lock_path or os.path.join(root, LOCK_NAME)
    lock = load_lock(lock_path)
    current = build_lock(root)["artifacts"]
    locked = lock.get("artifacts", {})

    def flatten(entries):
        flat = {}
        for key, entry in entries.items():
            base = key if entry["kind"] != "mcp-config" else ""
            for rel, digest in entry["files"].items():
                flat[os.path.join(key, rel) if base else rel] = digest
        return flat

    cur_flat = flatten(current)
    old_flat = flatten(locked)
    changed = sorted(k for k in cur_flat.keys() & old_flat.keys()
                     if cur_flat[k] != old_flat[k])
    added = sorted(cur_flat.keys() - old_flat.keys())
    removed = sorted(old_flat.keys() - cur_flat.keys())
    return {
        "lock_path": lock_path,
        "added_artifacts": sorted(set(current) - set(locked)),
        "removed_artifacts": sorted(set(locked) - set(current)),
        "added_files": added,
        "removed_files": removed,
        "changed_files": changed,
        "clean": not (added or removed or changed
                      or set(current) != set(locked)),
    }


def tree_inventory(root):
    """Per-file hashes of everything under root (helper for tests/tools)."""
    return {f["path"]: f["sha256"] for f in inventory_files(root)}
