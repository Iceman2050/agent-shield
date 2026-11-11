# BUILD REPORT — agent-shield v0.1.0

Built 2026-11-10 under the engineering loop: build → pytest green →
self-review gate on real fixture output → fix → re-verify → upload.

## Location note

The assigned working dir `~/workspace/github-repos-build/agent-shield/`
could not be created: the workspace disk quota (Errno 122) refused the
mkdir, and refused again after the prescribed ~20s wait + retry. Per the
build ground rules the repo was built under **`/tmp/agent-shield-build/`**
and uploaded from there. Nothing else in the workspace was touched.

## What was built

`agent-shield` — a stdlib-only Python CLI (entry point `agent-shield`)
that statically scans AI agent artifacts: skills (SKILL.md), plugins
(plugin.json/manifest.json), and MCP configs (JSON with `mcpServers`).

- `scan <dir>` — discovery + all checks + ACBOM; console / `--format json`
  / `--format sarif` (SARIF 2.1.0); exit 1 on critical findings.
- `inspect <path>` — deep report on one skill dir, plugin dir, or MCP
  config file.
- `lock <dir>` — writes `agent-shield.lock.json` (per-file sha256 +
  name/version/commit metadata per artifact).
- `diff <dir>` — added/removed/changed vs the lockfile; exit 1 on drift.
- Checks: hardcoded secrets (6 patterns), shell execution, eval/exec,
  network egress, credential-file access, fs writes to system paths,
  `curl | sh`, destructive `rm`, unpinned pip/npm dependencies, MCP
  shell-command servers, shell operators in args, literal secrets in env,
  `${VAR}` env passthrough, unpinned npx/uvx packages, plaintext-http
  remote MCP servers.
- Instruction heuristics over markdown: override / conceal / exfiltrate /
  silent-action / reveal-system-prompt / safety-bypass phrasing →
  **SUSPICIOUS** findings with the quoted line as evidence; never labeled
  confirmed malicious.
- ACBOM per artifact: name, kind, source, version/commit (git probe),
  per-file sha256 + size, executable components, declared vs observed
  capabilities, dependencies, findings, `last_verified` timestamp.
- GitHub Action: composite `action.yml` (path/format/output inputs) +
  `examples/github-action.yml`; CI workflow runs pytest on Python 3.9 and
  3.12 plus a self-scan of the fixture corpus.

## Reuse (audit-first, per spec)

Fleet sources audited before writing new code (GitHub canonical repos,
registry: `~/workspace/github-godmode-v2/registry.yaml`; local mirror at
`~/workspace/tools/Iceman2050/agent-skill-sbom/`):

- **Iceman2050/agent-skill-sbom** (`agent_skill_sbom.py`) → adapted into
  `agent_shield/frontmatter.py`: `parse_frontmatter` (extended with
  inline-list support for `capabilities:`), `parse_requirements`,
  `parse_package_json` incl. the pinned-version logic.
- **Iceman2050/plugin-provenance-verifier** (`provenance/scanner.py`,
  `snapshot.py`, `differ.py`) → adapted into `agent_shield/hashing.py`
  (`hash_file` streaming sha256, inventory walk) and the
  `agent_shield/lockfile.py` snapshot/diff design.
- New in agent-shield: the check rule engine, MCP risk checks,
  instruction heuristics, ACBOM assembly, SARIF renderer, CLI.

## Test results

- `pytest`: **18 passed, 0 failed** (Python 3.12 venv).
- Fixture assertions cover: all 6 fixtures discovered; adversarial-exfil
  caught (credential-access + hardcoded secret criticals); injection
  SKILL.md flagged SUSPICIOUS ×4 with quoted evidence; benign skills
  produce **no critical and no high** findings (note-taker fully clean);
  bad-mcp caught (shell-command + secret-in-env criticals; the literal
  secret value is asserted absent from findings output); good-mcp clean;
  SARIF parses with `version == "2.1.0"` and consistent rule ids; JSON
  output parses; lock→diff clean round-trip and tamper detection,
  including the regression below.

## Self-review gate evidence

Ran the installed CLI on `tests/fixtures/` and read the full output:
6 artifacts; findings critical=4, high=5, medium=3, low=1; suspicious
instructions=4; exit 1. Benign note-taker: "findings: none detected".
Lock/diff CLI pass in a scratch copy: lock → diff clean (exit 0);
append one line to a script → `CHANGED` + exit 1.

**Bug found and fixed by this gate:** the first lock→diff pass reported
`ADDED ./agent-shield.lock.json` on an untouched tree (the lockfile
written inside an artifact root was inventoried as part of the artifact).
Fixed by excluding the lockfile from artifact inventories in
`sbom.scan_artifact`; regression test
`test_lock_diff_clean_when_lockfile_lives_in_artifact_root` added;
suite re-run green.

## Honest limitations

- Pattern-based static analysis only. "Not detected" means the checked
  patterns were absent — never "safe". Obfuscated/encoded/downloaded
  payloads are out of reach; the scanner never executes artifacts, so
  runtime behavior is unobserved.
- Instruction heuristics will false-positive on text that *discusses*
  prompt injection (e.g. security documentation); findings are leads
  with quoted evidence for a human, by design.
- Frontmatter parsing is a minimal top-level parser, not full YAML.
- MCP `env` secret detection is pattern/key-name based; a secret split
  across variables or fetched at runtime is not detected.
- Discovery treats each SKILL.md/plugin-manifest directory as one
  artifact; an MCP config bundled inside a skill directory is also
  listed as its own artifact.

## Known gaps / future work

- No rules directory / user-supplied custom rules yet (v0.2 candidate).
- No behavioral/sandbox mode (deliberate: static-only is the safety
  posture for v0.1).
- SARIF output validated structurally (version, rule/result cross-refs)
  in tests; not yet submitted to GitHub code scanning in CI.
