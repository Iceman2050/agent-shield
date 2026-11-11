# Security Policy

## Reporting a vulnerability

If you find a security issue in agent-shield itself — especially anything
that would let a scanned artifact escape the scanner's read-only posture,
corrupt a lockfile, or hide a finding — please report it privately:

- Open a GitHub security advisory on this repository
  ("Security" tab → "Report a vulnerability"), or
- email the maintainer via the contact listed on
  https://getingeniousai.com

Please do not open a public issue for an exploitable vulnerability until a
fix is available.

## Scope notes

- agent-shield performs **static, read-only** analysis. It never executes
  scanned code, never follows instructions found in scanned files, and
  makes no network requests.
- Findings are evidence, not verdicts. A scan that detects nothing means
  "not detected", not "safe"; suspicious-instruction findings require
  human review.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
