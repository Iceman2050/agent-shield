"""Report rendering: human-readable console, JSON (ACBOM), SARIF 2.1.0."""
import json

from . import __version__

HONESTY_NOTE = (
    "Note: a scan that detects nothing means the checked patterns were not "
    "detected in these files — it does not prove an artifact is safe. "
    "Static analysis cannot establish intent; suspicious-instruction "
    "findings quote the evidence and require human review."
)

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def render_console(report):
    lines = []
    lines.append("agent-shield %s — scan of %s" % (__version__, report["root"]))
    lines.append("generated %s" % report["generated_at"])
    lines.append("")
    if not report["artifacts"]:
        lines.append("No skills, plugins, or MCP configs detected under this path.")
    for art in report["artifacts"]:
        lines.append("== %s (%s) ==" % (art["name"], art["kind"]))
        lines.append("  source: %s" % art["source"])
        if art.get("publisher"):
            lines.append("  publisher (as declared): %s" % art["publisher"])
        if art.get("digest"):
            lines.append("  digest: sha256:%s" % art["digest"])
        if art.get("changed_since_approved") is not None:
            lines.append("  changed since approved lock: %s"
                         % ("yes" if art["changed_since_approved"] else "no"))
        if art["version"]:
            lines.append("  version: %s" % art["version"])
        lines.append("  files: %d (%d executable)" % (
            len(art["files"]), len(art["executable_components"])))
        if art["declared_capabilities"]:
            lines.append("  declared capabilities: %s"
                         % ", ".join(art["declared_capabilities"]))
        if art["observed_capabilities"]:
            lines.append("  observed capabilities: %s"
                         % ", ".join(art["observed_capabilities"]))
        if art.get("mcp_servers"):
            for srv in art["mcp_servers"]:
                target = srv["url"] or srv["command"] or "?"
                lines.append("  server: %s -> %s" % (srv["name"], target))
        if not art["findings"]:
            lines.append("  findings: none detected")
        for f in art["findings"]:
            loc = f["file"] + (":%d" % f["line"] if f["line"] else "")
            lines.append("  [%s] %s (%s)" % (f["severity"].upper(), f["rule_id"], loc))
            lines.append("      %s" % f["message"])
            if f["evidence"]:
                lines.append("      evidence: %s" % f["evidence"])
        lines.append("")
    s = report["summary"]
    counts = s["findings_by_severity"]
    lines.append("Summary: %d artifact(s); findings: %s; suspicious instructions: %d"
                 % (s["artifacts"],
                    ", ".join("%s=%d" % (k, counts[k]) for k in
                              ("critical", "high", "medium", "low", "info")),
                    s["suspicious_instructions"]))
    if counts.get("critical"):
        lines.append("Result: %d critical finding(s) detected — review before use."
                     % counts["critical"])
    else:
        lines.append("Result: no critical findings detected.")
    lines.append(HONESTY_NOTE)
    return "\n".join(lines) + "\n"


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_sarif(report):
    """SARIF 2.1.0 for the findings across all artifacts in the report."""
    rules = {}
    results = []
    for art in report["artifacts"]:
        for f in art["findings"]:
            rid = f["rule_id"]
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": rid.replace(".", "_").replace("-", "_"),
                    "shortDescription": {"text": rid},
                    "fullDescription": {"text": f["message"]},
                    "defaultConfiguration": {
                        "level": SARIF_LEVEL.get(f["severity"], "warning")},
                    "properties": {"severity": f["severity"],
                                   "category": f["category"]},
                }
            loc = {"physicalLocation": {"artifactLocation": {"uri": f["file"]}}}
            if f["line"]:
                loc["physicalLocation"]["region"] = {"startLine": f["line"]}
            results.append({
                "ruleId": rid,
                "level": SARIF_LEVEL.get(f["severity"], "warning"),
                "message": {"text": f["message"]},
                "locations": [loc],
                "properties": {"severity": f["severity"],
                               "category": f["category"],
                               "evidence": f["evidence"],
                               "artifact": f["artifact"]},
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agent-shield",
                "version": __version__,
                "informationUri": "https://github.com/Iceman2050/agent-shield",
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"


RENDERERS = {"console": render_console, "json": render_json, "sarif": render_sarif}
