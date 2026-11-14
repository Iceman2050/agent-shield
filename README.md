# agent-shield

**A security scanner for the AI agent supply chain.**

Developers now install skills, plugins, and MCP servers that give AI agents
new capabilities — executable scripts, file access, network access,
credentials. Most people install them without ever reading what they do.

`agent-shield` statically inspects those artifacts *before* you trust them:

- **Inventories** every skill, plugin, and MCP config in a directory and
  emits an **Agent SBOM (ACBOM)** — per-file sha256 plus one digest per
  artifact, the publisher exactly as declared in the artifact's own
  metadata (never inferred), executable components, declared vs. observed
  capabilities, dependencies, and — when an approved lockfile exists — a
  per-artifact changed-since-approved flag.
- **Detects** deterministic risks: hardcoded secrets, shell execution,
  dynamic `eval`/`exec`, credential-file access, network egress,
  `curl | sh`, unpinned dependencies, MCP servers that launch shells or
  carry literal secrets in their environment.
- **Flags suspicious instructions** in `SKILL.md` text (prompt-injection
  patterns such as "ignore all previous instructions" or "do not tell the
  user") — quoted as evidence for human review, never declared "confirmed
  malicious" from text alone.
- **Locks** approved versions (`agent-shield.lock.json`) and **diffs**
  installed artifacts against the lock to catch silent changes.

> agent-shield consolidates two earlier Ingenious AI tools —
> [agent-skill-sbom](https://github.com/Iceman2050/agent-skill-sbom) and
> [plugin-provenance-verifier](https://github.com/Iceman2050/plugin-provenance-verifier) —
> into one scanner.

## Why this exists

Snyk's *ToxicSkills* research (Feb 2026) scanned 3,984 published agent
skills and found 1,467 with at least one security flaw, 534 with a
critical-level issue, and 76 with confirmed malicious payloads. OWASP's
Agentic Skills Top 10 names the same classes of risk: malicious skills,
supply-chain compromise, excessive permissions, untrusted instructions.
Skills are not inert text — a skill directory can carry executable scripts,
and an MCP config decides what code your agent runs and which credentials
it receives.

## Install

```bash
pip install git+https://github.com/Iceman2050/agent-shield
# or, from a clone:
pip install .
```

Python 3.9+, standard library only. No network access; scanning is local
and nothing you scan is ever executed.

## Usage

```bash
agent-shield scan ./skills                  # inventory + checks, console report
agent-shield scan ./skills --format json    # ACBOM + findings as JSON
agent-shield scan ./skills --format sarif   # SARIF 2.1.0 for code scanning
agent-shield inspect ./skills/my-skill      # deep report on one artifact
agent-shield inspect ~/.config/mcp.json     # ... or one MCP config file
agent-shield lock ./skills                  # write agent-shield.lock.json
agent-shield diff ./skills                  # what changed since the lock?
```

`scan` and `inspect` exit **1** when a critical finding is detected,
**0** otherwise. `diff` exits **1** when the tree differs from the lock.

### Example output

Scanning the adversarial fixtures bundled in `tests/fixtures/`:

```
== cloud-backup-helper (skill) ==
  source: skills/adversarial-exfil
  version: 2.1.0
  files: 2 (1 executable)
  declared capabilities: network, filesystem-write
  observed capabilities: credential-access, network-egress
  [CRITICAL] secret.generic (skills/adversarial-exfil/scripts/sync.py:8)
      Hardcoded secret detected: hardcoded credential assignment
  [CRITICAL] code.credential-access (skills/adversarial-exfil/scripts/sync.py:14)
      Access to credential files or key material
      evidence: for path in ("~/.ssh/id_rsa", "~/.aws/credentials"):

== friendly-formatter (skill) ==
  [HIGH] instruction.ignore-previous (skills/adversarial-injection/SKILL.md:7)
      SUSPICIOUS instruction pattern: Instruction to disregard prior
      instructions. Quoted evidence only — static text analysis cannot
      confirm intent; human review required.

Summary: 6 artifact(s); findings: critical=4, high=5, medium=3, low=1, info=0; suspicious instructions: 4
Result: 4 critical finding(s) detected — review before use.
```

### GitHub Action

```yaml
- uses: Iceman2050/agent-shield@v0.1.0
  with:
    path: "."        # directory containing your skills / MCP configs
    format: sarif    # console | json | sarif
    output: agent-shield.sarif
```

See [`examples/github-action.yml`](examples/github-action.yml) for a full
workflow, including optional SARIF upload to GitHub code scanning.

## What it checks

| Area | Examples |
|---|---|
| Secrets | AWS/GitHub/OpenAI key shapes, private keys, hardcoded credential assignments |
| Code execution | `subprocess`/`os.system`, `eval`/`exec`, `child_process`, `curl \| sh` |
| Credential access | reads of `~/.ssh`, `id_rsa`, `.aws/credentials`, `.env`, keychains |
| Network | `requests`/`urllib`/`socket`, `fetch`/`axios`, `curl`/`wget` |
| Dependencies | `requirements.txt` entries without `==`, npm specs with `^`/`~`/`*` |
| MCP configs | shell interpreters as server commands, shell operators in args, literal secrets in `env`, `${VAR}` passthrough, unpinned `npx`/`uvx` packages, plaintext-http remote servers |
| Instructions | concealment, instruction-override, exfiltration, silent-action, and safety-bypass phrasing in `SKILL.md` (flagged SUSPICIOUS with quoted evidence) |

## Honest limitations

- **"Not detected" never means "safe."** A clean scan means the checked
  patterns were not found in these files. Obfuscated, encoded, dynamically
  fetched, or novel malicious behavior will not be caught by pattern
  matching.
- **Static analysis only.** agent-shield never executes the artifacts it
  scans, so it cannot observe runtime behavior. A script that downloads
  its real payload at runtime shows up here only as "network access".
- **Instruction heuristics are leads, not verdicts.** Natural-language
  intent cannot be confirmed by regex. Suspicious-instruction findings
  quote the exact text so a human can judge; some will be false positives
  (e.g. a security guide *discussing* prompt injection).
- **Capability labels are evidence-based, not exhaustive.** "Observed
  capabilities" lists what the checks detected evidence of, not everything
  an artifact could do.
- Parsing is intentionally shallow: the frontmatter parser handles
  top-level scalars and simple inline lists, not full YAML.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE). Security policy: [SECURITY.md](SECURITY.md).
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
