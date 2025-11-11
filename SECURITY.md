# Security Policy

**Local-first:** Do not expose any service publicly by default.

## Reporting a vulnerability
Open a private issue or email the maintainers (without real secrets). Provide version, OS, Python version, and steps to reproduce.

## Operating recommendations
- Keep `keys/` outside version control, strict permissions.
- Tune your policy before use; prefer `block`/`redact` for new detectors.
- Run `mypy`, `black`, `bandit`, `pip-audit` locally before releases.
