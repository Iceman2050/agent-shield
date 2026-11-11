"""Deterministic static checks over skill/plugin files.

Every rule is a documented pattern match over file text. Findings quote the
evidence line. Static analysis cannot prove intent: instruction-layer hits
are reported as SUSPICIOUS (human review), never as confirmed malice, and a
scan with no hits means "not detected", never "safe".
"""
import os
import re

from .model import Finding

# --- secret patterns: (rule_id, regex, label) -------------------------------
SECRET_PATTERNS = [
    ("secret.aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    ("secret.github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "GitHub token"),
    ("secret.openai-key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "OpenAI-style API key"),
    ("secret.private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "private key material"),
    ("secret.slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    ("secret.generic", re.compile(
        r"""(?i)(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token)"""
        r"""\s*[:=]\s*["'][^"'\s]{8,}["']"""), "hardcoded credential assignment"),
]

# --- code patterns per language ---------------------------------------------
# (rule_id, severity, regex, message, capability)
PY_RULES = [
    ("code.shell-execution", "high", re.compile(r"\b(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen|commands\.getoutput)"),
     "Shell command execution", "shell-execution"),
    ("code.dynamic-exec", "high", re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
     "Dynamic code execution (eval/exec)", "dynamic-code-execution"),
    ("code.network-egress", "medium", re.compile(r"\b(?:requests|httpx|aiohttp)\.(?:get|post|put|patch|delete|request|Session)|urllib\.request|socket\.socket|http\.client"),
     "Network access from script", "network-egress"),
    ("code.credential-access", "critical", re.compile(
        r"(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.env\b|keychain|gnupg|\.git-credentials|\.npmrc)"),
     "Access to credential files or key material", "credential-access"),
    ("code.fs-write-outside", "high", re.compile(
        r"""open\(\s*["']/(?:etc|usr|var|opt|root)/[^"']*["']\s*,\s*["'][wa]"""),
     "Write to an absolute system path outside the artifact directory", "filesystem-write"),
    ("code.home-write", "medium", re.compile(
        r"""(?:expanduser\(\s*["']~|Path\.home\(\))"""),
     "Path resolution into the user's home directory", "filesystem-access"),
]

SH_RULES = [
    ("code.remote-pipe-shell", "critical", re.compile(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
     "Remote script piped directly into a shell (curl | sh)", "shell-execution"),
    ("code.shell-execution", "high", re.compile(r"(?<![\w.])(?:eval|source)\s+|\$\([^)]*\)"),
     "Shell eval/source or command substitution", "shell-execution"),
    ("code.network-egress", "medium", re.compile(r"\b(?:curl|wget|nc|netcat)\b"),
     "Network access from shell script", "network-egress"),
    ("code.credential-access", "critical", re.compile(
        r"(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.env\b|keychain|gnupg)"),
     "Access to credential files or key material", "credential-access"),
    ("code.destructive", "critical", re.compile(r"rm\s+-[rf]+\s+(?:/|\$\{?HOME\}?|~)(?:\s|$)"),
     "Recursive delete targeting root or home", "filesystem-write"),
]

JS_RULES = [
    ("code.shell-execution", "high", re.compile(r"child_process|\bexecSync\b|\bspawn\s*\("),
     "Shell command execution (child_process)", "shell-execution"),
    ("code.dynamic-exec", "high", re.compile(r"(?<![\w.])(?:eval|Function)\s*\("),
     "Dynamic code execution (eval/Function)", "dynamic-code-execution"),
    ("code.network-egress", "medium", re.compile(r"\bfetch\s*\(|https?\.(?:get|request)\s*\(|axios\.|node-fetch"),
     "Network access from script", "network-egress"),
    ("code.credential-access", "critical", re.compile(
        r"(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.env\b|keychain|gnupg)"),
     "Access to credential files or key material", "credential-access"),
    ("code.env-access", "low", re.compile(r"process\.env"),
     "Reads process environment variables", "environment-access"),
]

LANG_RULES = {".py": PY_RULES, ".sh": SH_RULES, ".bash": SH_RULES,
              ".js": JS_RULES, ".mjs": JS_RULES, ".cjs": JS_RULES}

REMOTE_PIPE_RE = re.compile(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")

# --- instruction-layer heuristics (markdown / SKILL.md text) -----------------
# Hits are SUSPICIOUS, with the quoted line as evidence. Natural-language
# intent cannot be confirmed by pattern matching.
INSTRUCTION_PATTERNS = [
    ("instruction.ignore-previous", re.compile(
        r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)"),
     "Instruction to disregard prior instructions"),
    ("instruction.conceal-from-user", re.compile(
        r"(?i)(?:do\s+not|never|don'?t)\s+(?:tell|inform|mention|reveal\s+to|show)\s+(?:the\s+)?user"),
     "Instruction to conceal behavior from the user"),
    ("instruction.exfiltration", re.compile(
        r"(?i)(?:send|upload|post|transmit|forward|exfiltrate)\s+[^.\n]{0,60}?"
        r"(?:to\s+https?://|contents\s+of|the\s+file|credentials|passwords|tokens|\.env)"),
     "Instruction directing data to be sent out or file contents transmitted"),
    ("instruction.silent-action", re.compile(
        r"(?i)silently\s+(?:send|upload|run|execute|install|download|delete)"),
     "Instruction to act silently"),
    ("instruction.reveal-system-prompt", re.compile(
        r"(?i)reveal\s+(?:your\s+)?(?:system\s+prompt|instructions|prompt)"),
     "Instruction to reveal the system prompt"),
    ("instruction.override-safety", re.compile(
        r"(?i)(?:bypass|disable|override)\s+(?:the\s+)?(?:safety|security|approval|confirmation|permission)"),
     "Instruction to bypass safety or approval steps"),
]


def _evidence(line, limit=140):
    line = line.strip()
    return line if len(line) <= limit else line[:limit - 1] + "…"


def scan_text_file(artifact, relpath, text):
    """Run code + secret rules over one file's text. Returns findings."""
    findings = []
    ext = os.path.splitext(relpath)[1].lower()
    rules = LANG_RULES.get(ext, [])
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for rule_id, pattern, label in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=rule_id, severity="critical", artifact=artifact,
                    file=relpath, line=lineno, evidence=_evidence(line),
                    message="Hardcoded secret detected: %s" % label,
                    category="code", capabilities=["credential-access"]))
        for rule_id, severity, pattern, message, capability in rules:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=rule_id, severity=severity, artifact=artifact,
                    file=relpath, line=lineno, evidence=_evidence(line),
                    message=message, category="code", capabilities=[capability]))
        if ext not in LANG_RULES and REMOTE_PIPE_RE.search(line):
            findings.append(Finding(
                rule_id="code.remote-pipe-shell", severity="critical",
                artifact=artifact, file=relpath, line=lineno,
                evidence=_evidence(line),
                message="Remote script piped directly into a shell (curl | sh)",
                category="code", capabilities=["shell-execution"]))
    return findings


def scan_instruction_text(artifact, relpath, text):
    """Heuristic instruction-layer scan of markdown text -> SUSPICIOUS findings."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule_id, pattern, label in INSTRUCTION_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=rule_id, severity="high", artifact=artifact,
                    file=relpath, line=lineno, evidence=_evidence(line),
                    message=("SUSPICIOUS instruction pattern: %s. Quoted evidence "
                             "only — static text analysis cannot confirm intent; "
                             "human review required." % label),
                    category="suspicious-instruction"))
    return findings


def scan_dependencies(artifact, deps, source_file):
    """Unpinned dependencies -> medium findings (supply-chain drift risk)."""
    findings = []
    for dep in deps:
        if not dep.get("pinned", False):
            findings.append(Finding(
                rule_id="dependency.unpinned", severity="medium",
                artifact=artifact, file=source_file, line=0,
                evidence="%s (%s)" % (dep["name"], dep["spec"]),
                message=("Dependency '%s' is not pinned to an exact version "
                         "(%s); its content can change upstream."
                         % (dep["name"], dep["spec"])),
                category="dependency"))
    return findings
