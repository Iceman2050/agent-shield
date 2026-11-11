# Contributing

Thanks for considering a contribution to agent-shield.

## Ground rules

- **Stdlib only.** The scanner must stay installable with no third-party
  runtime dependencies.
- **Read-only analysis.** Never execute scanned artifacts, never make
  network requests from the scanner.
- **Verdict honesty.** New checks must quote evidence. Instruction-layer
  heuristics must stay SUSPICIOUS-with-evidence, never "confirmed".
  Nothing in this project may claim an artifact is "safe" or "100% safe".
- **Every new rule ships with fixtures:** one artifact that must trigger
  it and one benign artifact that must not produce a critical finding
  from it.

## Development

```bash
git clone https://github.com/Iceman2050/agent-shield
cd agent-shield
pip install -e ".[dev]"
pytest
agent-shield scan tests/fixtures   # self-check against the fixture corpus
```

## Pull requests

- Keep changes surgical: one rule, one parser fix, or one report change
  per PR where practical.
- Run `pytest` and include the result in the PR description.
- Update `CHANGELOG.md` under "Unreleased".
