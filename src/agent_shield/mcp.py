"""MCP configuration parsing and risk checks.

An MCP config is a JSON object with an ``mcpServers`` map. Each server is
either a local stdio server (command + args + env) or a remote server
(url). Risks checked deterministically: shell interpreters as the server
command, shell operators in args, literal secrets in env values, secret
keys passed through the environment, unpinned npx/uvx packages, and
remote endpoints (plaintext http especially).
"""
import json
import os
import re

from .checks import SECRET_PATTERNS
from .model import Finding

SHELL_COMMANDS = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell",
                  "powershell.exe", "pwsh"}
SECRET_ENV_KEY_RE = re.compile(
    r"(?i)(key|secret|token|password|passwd|credential|auth)")
PINNED_PKG_RE = re.compile(r"@\d+\.\d+\.\d+")


def load_mcp_config(path):
    """Return the parsed config dict, or None if not a JSON object."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def is_mcp_config(data):
    return isinstance(data, dict) and isinstance(data.get("mcpServers"), dict)


def server_records(data):
    """Normalize mcpServers into a list of plain dicts."""
    out = []
    for name, srv in sorted((data.get("mcpServers") or {}).items()):
        if not isinstance(srv, dict):
            continue
        out.append({
            "name": name,
            "command": srv.get("command"),
            "args": [str(a) for a in srv.get("args") or []],
            "url": srv.get("url"),
            "env_keys": sorted((srv.get("env") or {}).keys()),
            "env": srv.get("env") or {},
        })
    return out


def scan_mcp_config(artifact, relpath, data):
    """Risk findings for one MCP config."""
    findings = []

    def add(rule_id, severity, message, evidence, capabilities=None):
        findings.append(Finding(
            rule_id=rule_id, severity=severity, artifact=artifact,
            file=relpath, line=0, evidence=evidence, message=message,
            category="config", capabilities=capabilities or []))

    for srv in server_records(data):
        name = srv["name"]
        cmd = srv["command"] or ""
        base = os.path.basename(cmd).lower() if cmd else ""
        if base in SHELL_COMMANDS:
            add("mcp.shell-command", "critical",
                "MCP server '%s' launches a shell interpreter ('%s') — the "
                "agent gains arbitrary command execution through it."
                % (name, cmd),
                "server '%s': command=%s" % (name, cmd), ["shell-execution"])
        joined_args = " ".join(srv["args"])
        if cmd and re.search(r"(?:&&|\|\||;|\$\(|`)", joined_args):
            add("mcp.shell-operators-in-args", "high",
                "MCP server '%s' passes shell operators in its args; if the "
                "command is ever run through a shell this is code execution."
                % name,
                "server '%s': args=%s" % (name, joined_args[:120]),
                ["shell-execution"])
        if base in ("npx", "uvx", "pnpm", "bunx") and srv["args"]:
            pkg = next((a for a in srv["args"] if not a.startswith("-")), "")
            if pkg and not PINNED_PKG_RE.search(pkg) and "/" not in pkg.split("@")[0]:
                if "@" not in pkg[1:]:
                    add("mcp.unpinned-package", "medium",
                        "MCP server '%s' runs unpinned package '%s' via %s; "
                        "the executed code can change upstream."
                        % (name, pkg, base),
                        "server '%s': %s %s" % (name, base, pkg))
        url = srv["url"] or ""
        if url:
            if url.startswith("http://"):
                add("mcp.remote-plaintext", "high",
                    "MCP server '%s' uses a plaintext http remote endpoint; "
                    "traffic (including any credentials) is unencrypted."
                    % name,
                    "server '%s': url=%s" % (name, url), ["network-egress"])
            else:
                add("mcp.remote-server", "medium",
                    "MCP server '%s' is a remote endpoint; tool calls and "
                    "their data leave this machine." % name,
                    "server '%s': url=%s" % (name, url), ["network-egress"])
        for key, value in sorted(srv["env"].items()):
            value = "" if value is None else str(value)
            if not value:
                continue
            secret_hit = any(p.search(value) for _r, p, _l in SECRET_PATTERNS)
            if secret_hit or (SECRET_ENV_KEY_RE.search(key) and len(value) >= 8
                              and not value.startswith("${")):
                add("mcp.secret-in-env", "critical",
                    "MCP server '%s' carries a literal secret in env key "
                    "'%s'. Anyone who can read this config has the secret."
                    % (name, key),
                    "server '%s': env %s=<redacted, %d chars>"
                    % (name, key, len(value)), ["credential-access"])
            elif value.startswith("${"):
                add("mcp.env-passthrough", "low",
                    "MCP server '%s' receives env key '%s' by reference (%s); "
                    "the agent process passes this credential to the server."
                    % (name, key, value),
                    "server '%s': env %s=%s" % (name, key, value),
                    ["credential-access"])
    return findings
