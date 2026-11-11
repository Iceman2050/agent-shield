"""Minimal YAML-frontmatter parsing for SKILL.md files (stdlib only).

Adapted from Iceman2050/agent-skill-sbom (agent_skill_sbom.parse_frontmatter,
parse_requirements, parse_package_json) — same author, consolidated here.
Handles top-level scalar keys and simple inline lists like
``capabilities: [shell, network]``. Nested blocks are skipped, not parsed.
"""
import json
import re

_EXACT_PIN_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^*,\s]+)$")


def parse_frontmatter(text):
    """Return dict of top-level frontmatter keys from a markdown document."""
    meta = {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return meta, text
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            body_start = i + 1
            break
        if not line.strip() or line[0] in (" ", "\t"):
            continue  # skip nested blocks and blanks
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key or not re.match(r"^[A-Za-z0-9_.\-]+$", key):
            continue
        if value.startswith("[") and value.endswith("]"):
            items = [v.strip().strip("\"'") for v in value[1:-1].split(",")]
            meta[key] = [v for v in items if v]
        else:
            meta[key] = value.strip("\"'")
    return meta, "\n".join(lines[body_start:])


def parse_requirements(path):
    """requirements.txt -> list of {name, spec, pinned} (from agent-skill-sbom)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return deps
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _EXACT_PIN_RE.match(line)
        if m:
            deps.append({"name": m.group(1), "spec": line, "pinned": True,
                         "ecosystem": "pypi"})
        else:
            name = re.split(r"[<>=!~\s\[]", line, 1)[0]
            if name:
                deps.append({"name": name, "spec": line, "pinned": False,
                             "ecosystem": "pypi"})
    return deps


def parse_package_json(path):
    """package.json -> list of {name, spec, pinned, ecosystem} (from agent-skill-sbom)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            spec = str(spec)
            pinned = bool(re.match(r"^\d", spec)) and not any(
                c in spec for c in "^~*><=| ")
            deps.append({"name": name, "spec": spec, "pinned": pinned,
                         "ecosystem": "npm"})
    return deps
