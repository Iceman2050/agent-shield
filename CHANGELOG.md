# Changelog

All notable changes to agent-shield are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-11-10

### Added

- `agent-shield scan` — inventory and check every skill, plugin, and MCP
  config under a directory; console, JSON (ACBOM), and SARIF 2.1.0 output;
  exit 1 on critical findings.
- `agent-shield inspect` — deep report on one skill/plugin directory or
  one MCP config file.
- `agent-shield lock` / `agent-shield diff` — per-file sha256 lockfile of
  approved artifact versions, with added/removed/changed reporting.
- Agent SBOM (ACBOM): per-artifact name, source, version/commit, per-file
  sha256, executable components, declared vs. observed capabilities,
  dependencies, findings, verification timestamp.
- Deterministic checks: hardcoded secrets, shell/dynamic code execution,
  credential-file access, network egress, `curl | sh`, unpinned Python
  and npm dependencies.
- MCP config checks: shell-interpreter server commands, shell operators
  in args, literal secrets in env values, `${VAR}` env passthrough,
  unpinned `npx`/`uvx` packages, plaintext-http remote servers.
- Instruction-layer heuristics over `SKILL.md` text (override, conceal,
  exfiltration, silent-action, reveal-system-prompt, safety-bypass
  phrasing), reported as SUSPICIOUS with quoted evidence.
- GitHub Action (`action.yml`) and an example workflow under `examples/`.
- Fixture corpus + test suite: benign and adversarial skills and MCP
  configs, with assertions that adversarial artifacts are caught and
  benign ones produce no critical findings.

### Notes

- Consolidates Iceman2050/agent-skill-sbom (frontmatter and dependency
  parsing) and Iceman2050/plugin-provenance-verifier (streaming sha256
  inventory, snapshot/diff pattern).
