"""Scan orchestration: build the Agent Capability Bill of Materials (ACBOM).

An ACBOM record inventories one artifact: identity, source, per-file sha256,
executable components, declared vs observed capabilities, dependencies,
findings, and the verification timestamp.
"""
import json
import os
import subprocess
from datetime import datetime, timezone

from . import __version__, checks, mcp as mcp_mod
from .discovery import discover, classify_target
from .frontmatter import parse_frontmatter, parse_package_json, parse_requirements
from .hashing import TEXT_EXTS, inventory_files, read_text

LOCK_NAME = "agent-shield.lock.json"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_source(directory):
    """Best-effort (source_url, commit) from a surrounding git repo; else Nones."""
    try:
        url = subprocess.run(["git", "-C", directory, "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=5)
        commit = subprocess.run(["git", "-C", directory, "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=5)
        return (url.stdout.strip() or None) if url.returncode == 0 else None, \
               (commit.stdout.strip() or None) if commit.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None, None


def _rel(root, path):
    return os.path.relpath(path, root)


def scan_artifact(art, root):
    """Build the ACBOM record + findings for one discovered artifact."""
    kind = art["kind"]
    directory = art["dir"]
    findings = []
    meta = {}
    dependencies = []

    if kind == "mcp-config":
        files = []
        data = art.get("data") or mcp_mod.load_mcp_config(art["path"]) or {}
        from .hashing import hash_file
        try:
            files = [{"path": _rel(directory, art["path"]),
                      "sha256": hash_file(art["path"]),
                      "size": os.path.getsize(art["path"]),
                      "executable": False}]
        except OSError:
            files = []
        name = os.path.splitext(os.path.basename(art["path"]))[0]
        findings.extend(mcp_mod.scan_mcp_config(
            name, _rel(root, art["path"]), data))
        servers = mcp_mod.server_records(data)
        return {
            "name": name, "kind": kind, "source": _rel(root, art["path"]),
            "version": None, "commit": None,
            "description": "MCP configuration with %d server(s)" % len(servers),
            "mcp_servers": servers,
            "files": files,
            "executable_components": [],
            "declared_capabilities": [],
            "observed_capabilities": sorted(
                {c for f in findings for c in f.capabilities}),
            "dependencies": [],
            "findings": [f.to_dict() for f in sorted(findings, key=lambda f: f.sort_key())],
            "last_verified": _now(),
        }

    # The lockfile is metadata about the tree, not part of the artifact:
    # excluding it keeps `lock` -> `diff` clean on an untouched tree.
    files = [f for f in inventory_files(directory) if f["path"] != LOCK_NAME]
    executables = [f["path"] for f in files if f["executable"]]

    if kind == "skill":
        text = read_text(art["path"])
        meta, body = parse_frontmatter(text)
        name = meta.get("name") or os.path.basename(directory)
        findings.extend(checks.scan_instruction_text(
            name, _rel(root, art["path"]), body))
    else:  # plugin
        try:
            with open(art["path"], "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            if not isinstance(meta, dict):
                meta = {}
        except (OSError, ValueError):
            meta = {}
        name = meta.get("name") or os.path.basename(directory)

    # dependencies anywhere in the artifact dir
    for f in files:
        full = os.path.join(directory, f["path"])
        if f["path"].endswith("requirements.txt"):
            deps = parse_requirements(full)
            dependencies.extend(deps)
            findings.extend(checks.scan_dependencies(name, deps, _rel(root, full)))
        elif os.path.basename(f["path"]) == "package.json":
            deps = parse_package_json(full)
            dependencies.extend(deps)
            findings.extend(checks.scan_dependencies(name, deps, _rel(root, full)))

    # code + instruction checks over text files
    for f in files:
        ext = os.path.splitext(f["path"])[1].lower()
        if ext not in TEXT_EXTS:
            continue
        full = os.path.join(directory, f["path"])
        text = read_text(full)
        if not text:
            continue
        findings.extend(checks.scan_text_file(name, _rel(root, full), text))
        if ext == ".md" and os.path.basename(f["path"]).lower() != "skill.md":
            findings.extend(checks.scan_instruction_text(name, _rel(root, full), text))

    declared = meta.get("capabilities") or meta.get("permissions") or []
    if isinstance(declared, str):
        declared = [declared]
    source_url, commit = _git_source(directory)
    return {
        "name": name,
        "kind": kind,
        "source": source_url or _rel(root, directory),
        "version": str(meta.get("version")) if meta.get("version") else None,
        "commit": commit,
        "description": meta.get("description") if isinstance(meta.get("description"), str) else None,
        "files": files,
        "executable_components": executables,
        "declared_capabilities": list(declared),
        "observed_capabilities": sorted(
            {c for f in findings for c in f.capabilities}),
        "dependencies": dependencies,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: f.sort_key())],
        "last_verified": _now(),
    }


def summarize(artifacts):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    suspicious = 0
    for art in artifacts:
        for f in art["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            if f["category"] == "suspicious-instruction":
                suspicious += 1
    return {"artifacts": len(artifacts), "findings_by_severity": counts,
            "suspicious_instructions": suspicious}


def scan(root):
    """Scan a directory tree; returns the full report dict (ACBOM set)."""
    root = os.path.abspath(root)
    artifacts = [scan_artifact(art, root) for art in discover(root)]
    return {"tool": "agent-shield", "tool_version": __version__,
            "generated_at": _now(), "root": root,
            "artifacts": artifacts, "summary": summarize(artifacts)}


def inspect(path):
    """Deep-scan one artifact (skill dir, plugin dir, or MCP config file)."""
    art = classify_target(path)
    if art is None:
        return None
    root = art["dir"] if art["kind"] != "mcp-config" else os.path.dirname(art["dir"])
    record = scan_artifact(art, root)
    return {"tool": "agent-shield", "tool_version": __version__,
            "generated_at": _now(), "root": root,
            "artifacts": [record], "summary": summarize([record])}
