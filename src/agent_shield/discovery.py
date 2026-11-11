"""Artifact discovery: skills (SKILL.md), plugins (plugin.json/manifest.json),
and MCP configs (JSON files with an mcpServers map) under a root directory.
"""
import os

from . import mcp as mcp_mod
from .hashing import SKIP_DIRS, read_text

SKILL_FILE = "SKILL.md"
PLUGIN_MANIFESTS = ("plugin.json", "manifest.json")
MCP_NAME_HINTS = ("mcp", "claude_desktop_config")


def _walk_dirs(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        yield dirpath, sorted(filenames)


def discover(root):
    """Return a list of artifact descriptors under root.

    Each: {kind: skill|plugin|mcp-config, dir (artifact dir), path (key file),
           rel (dir relative to root)}.
    Discovery is shallowest-first per kind so a skill dir is not also
    reported for every nested file.
    """
    root = os.path.abspath(root)
    artifacts = []
    claimed = []  # dirs already claimed as skill/plugin artifacts

    def under_claimed(d):
        return any(d == c or d.startswith(c + os.sep) for c in claimed)

    for dirpath, filenames in _walk_dirs(root):
        if under_claimed(dirpath) and dirpath not in claimed:
            continue
        lower = {f.lower(): f for f in filenames}
        if SKILL_FILE.lower() in lower:
            artifacts.append({"kind": "skill", "dir": dirpath,
                              "path": os.path.join(dirpath, lower[SKILL_FILE.lower()]),
                              "rel": os.path.relpath(dirpath, root)})
            claimed.append(dirpath)
            continue
        for manifest in PLUGIN_MANIFESTS:
            if manifest in lower:
                artifacts.append({"kind": "plugin", "dir": dirpath,
                                  "path": os.path.join(dirpath, lower[manifest]),
                                  "rel": os.path.relpath(dirpath, root)})
                claimed.append(dirpath)
                break

    for dirpath, filenames in _walk_dirs(root):
        for fn in filenames:
            if not fn.lower().endswith(".json"):
                continue
            full = os.path.join(dirpath, fn)
            if fn == "agent-shield.lock.json":
                continue
            data = mcp_mod.load_mcp_config(full)
            if data is not None and mcp_mod.is_mcp_config(data):
                artifacts.append({"kind": "mcp-config", "dir": dirpath,
                                  "path": full,
                                  "rel": os.path.relpath(full, root),
                                  "data": data})
    return artifacts


def classify_target(path):
    """For `inspect`: classify a single file or directory path."""
    path = os.path.abspath(path)
    if os.path.isfile(path):
        if os.path.basename(path).lower() == SKILL_FILE.lower():
            return {"kind": "skill", "dir": os.path.dirname(path),
                    "path": path, "rel": os.path.basename(os.path.dirname(path))}
        data = mcp_mod.load_mcp_config(path)
        if data is not None and mcp_mod.is_mcp_config(data):
            return {"kind": "mcp-config", "dir": os.path.dirname(path),
                    "path": path, "rel": os.path.basename(path), "data": data}
        if os.path.basename(path) in PLUGIN_MANIFESTS:
            return {"kind": "plugin", "dir": os.path.dirname(path),
                    "path": path, "rel": os.path.basename(os.path.dirname(path))}
        return None
    if os.path.isdir(path):
        for art in discover(path):
            if os.path.abspath(art["dir"]) == path and art["kind"] != "mcp-config":
                return art
        arts = discover(path)
        return arts[0] if arts else {"kind": "skill", "dir": path,
                                     "path": path, "rel": os.path.basename(path)}
    return None
