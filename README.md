<div align="center">

# 🔒 CloakMCP

### Micro-Cleanse Preprocessor — Local Secret Removal

**Protect your secrets before sharing code with LLMs**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.2.0--beta-green.svg)](https://github.com/ovitrac/CloakMCP/releases)
[![Tests](https://img.shields.io/badge/tests-90%2B%20passing-brightgreen.svg)](./tests)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[Features](#-features) • [Quick Start](#-quick-start) • [Installation](#-installation) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 📖 Overview

**CloakMCP** is a **local-first, deterministic sanitizer** that removes or neutralizes secrets (emails, IPs, URLs, tokens, API keys, PII) **before** your text/code is sent to LLMs like Claude, GitHub Copilot, or OpenAI Codex.

### Why CloakMCP?

- 🔐 **Local-first**: All operations run on your machine — no cloud dependencies
- 🔄 **Reversible**: Deterministic tagging allows safe restoration via encrypted vaults
- 📦 **Batch processing**: Pack/unpack entire codebases with one command
- ⚙️ **Policy-driven**: Configure detection rules via YAML (regex, entropy, IPs, URLs)
- 🔍 **Auditable**: Every operation logged to `audit/audit.jsonl`
- 🚀 **LLM-ready**: Designed for safe collaboration with AI coding assistants
- 💻 **VS Code integrated**: One-keystroke sanitization with `Ctrl+Alt+S`

### Use Cases

- ✅ Share code with LLMs without exposing credentials
- ✅ Pre-commit hooks to prevent secret leaks
- ✅ Sanitize logs before uploading to issue trackers
- ✅ Anonymize customer data in demos/screenshots
- ✅ CI/CD pipelines with encrypted secret management

---

## 🎯 Features

### Core Features

| Feature                      | Description                                                  |
| ---------------------------- | ------------------------------------------------------------ |
| **Scan**                     | Detect secrets without modification (audit mode)             |
| **Sanitize**                 | Replace secrets with tags, hashes, or pseudonyms             |
| **Pack/Unpack**              | Batch-process entire directories with encrypted vault storage|
| **Policy Engine**            | YAML-based rules for detection and actions                   |
| **Encrypted Vaults**         | AES-128 (Fernet) encryption for reversible secret storage    |
| **Deterministic Tags**       | Same secret → same tag (stable across sessions)              |
| **VS Code Integration**      | Keyboard shortcuts and tasks for seamless workflow           |
| **Local API Server**         | Optional FastAPI server for IDE extensions                   |
| **Audit Logging**            | JSONL logs with timestamps, rule IDs, and value hashes       |

### Detectors

- 🔑 **AWS keys** (`AKIA*`, `ASIA*`)
- 🔑 **GCP API keys** (`AIza*`)
- 🔑 **JWT tokens** (3-part base64)
- 🔑 **SSH private keys** (PEM blocks)
- 🔑 **X.509 certificates** (PEM blocks)
- 📧 **Email addresses** (with whitelist support)
- 🌐 **URLs** (HTTP/HTTPS)
- 🖧 **IP addresses** (IPv4/IPv6 with CIDR whitelists)
- 🎲 **High-entropy strings** (base64-like tokens)
- 🔧 **Custom regex patterns** (user-defined)

### Actions

- **`block`**: Refuse to process (exit with error)
- **`redact`**: Replace with `<REDACTED:rule_id>`
- **`pseudonymize`**: Replace with HMAC-based token (`PZ-xxxxx`)
- **`hash`**: Replace with SHA-256 hash
- **`replace_with_template`**: Use custom template (e.g., `<EMAIL:{hash8}>`)
- **`allow`**: Keep unchanged (whitelist)

---

## 🚀 Quick Start

### 1. Install (5 minutes)

```bash
# Clone repository
git clone https://github.com/ovitrac/CloakMCP.git
cd CloakMCP

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package
pip install -e .

# Verify installation
mcp --help
```

### 2. Generate Keys

```bash
# Create keys directory
mkdir -p keys audit

# Generate HMAC key (for pseudonymization)
openssl rand -hex 32 > keys/mcp_hmac_key

# Optional: Generate API token (for server mode)
openssl rand -hex 32 > keys/mcp_api_token

# Secure permissions
chmod 600 keys/*
```

### 3. Test with Example

```bash
# Create test file with secrets
cat > test_secrets.py <<EOF
# Production credentials
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "admin@company.com"
DB_URL = "postgresql://user:pass@db.internal.com:5432/mydb"
EOF

# Scan (detect only, no modification)
mcp scan --policy examples/mcp_policy.yaml --input test_secrets.py

# Sanitize (preview to terminal)
mcp sanitize --policy examples/mcp_policy.yaml --input test_secrets.py --output -
```

**Expected output**:
```python
# Production credentials
AWS_KEY = ""  # BLOCKED (high-risk secret)
EMAIL = "<EMAIL:a3b2c1d4>"
DB_URL = "PZ-Gh9Ij1Kl3"
```

### 4. Pack/Unpack Workflow (Recommended)

```bash
# Pack: Replace secrets with tags (vaulted)
mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG

# Now safe to share with LLMs (secrets replaced with TAG-xxxxxxxxxxxx)
# Vault stored securely in ~/.cloakmcp/vaults/

# Unpack: Restore original secrets
mcp unpack --dir .
```

---

## 📦 Installation

### Prerequisites

- **Python 3.10+**
- **pip** (Python package manager)
- **OpenSSL** (for key generation)
- **Git** (for cloning repository)

### Option 1: From Source (Recommended)

```bash
git clone https://github.com/yourusername/CloakMCP.git
cd CloakMCP
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Option 2: Direct Install (Future)

```bash
# Once published to PyPI
pip install cloakmcp
```

### Dependencies

Core dependencies (auto-installed):
- `pyyaml>=6.0.1` — YAML policy parsing
- `cryptography>=43.0.0` — Vault encryption (Fernet)
- `fastapi>=0.115.0` — Optional API server
- `uvicorn>=0.30.0` — ASGI server for API
- `pydantic>=2.7.0` — Data validation

Development dependencies:
```bash
pip install pytest pytest-cov black mypy bandit
```

---

## 🎮 Usage

### CLI Commands

#### `mcp scan`

Scan file for secrets (audit mode, no modification):

```bash
mcp scan --policy examples/mcp_policy.yaml --input file.py
```

**Output**: Logs written to `audit/audit.jsonl`

#### `mcp sanitize`

Sanitize file and output result:

```bash
# Preview to stdout
mcp sanitize --policy examples/mcp_policy.yaml --input file.py --output -

# Overwrite file (use with caution)
mcp sanitize --policy examples/mcp_policy.yaml --input file.py --output file.py

# Write to new file
mcp sanitize --policy examples/mcp_policy.yaml --input file.py --output file.sanitized.py
```

#### `mcp pack`

Pack directory (replace secrets with tags):

```bash
mcp pack --policy examples/mcp_policy.yaml --dir /path/to/project --prefix TAG
```

**What it does**:
- Scans all files (respects `.mcpignore`)
- Replaces secrets with deterministic tags: `TAG-a1b2c3d4e5f6`
- Stores mapping in encrypted vault: `~/.cloakmcp/vaults/<slug>.vault`
- Modifies files **in place**

#### `mcp unpack`

Unpack directory (restore secrets from vault):

```bash
mcp unpack --dir /path/to/project
```

**What it does**:
- Finds all tags matching pattern `PREFIX-[0-9a-f]{12}`
- Looks up original values in vault
- Restores secrets **in place**

---

## ⚙️ Configuration

### Policy File (`mcp_policy.yaml`)

Configuration is YAML-based. Example:

```yaml
version: 1

globals:
  default_action: redact
  audit:
    enabled: true
    path: ./audit/audit.jsonl
    include_value_hash: true
  pseudonymization:
    method: hmac-sha256
    secret_key_file: ./keys/mcp_hmac_key
    salt: session  # or 'permanent' for cross-session consistency

detection:
  # Block high-risk secrets
  - id: aws_access_key
    type: regex
    pattern: '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    action: block
    severity: high

  # Pseudonymize JWT tokens
  - id: jwt_token
    type: regex
    pattern: '\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'
    action: pseudonymize

  # Replace emails with template
  - id: email
    type: regex
    pattern: '(?i)[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9.-]+'
    action: replace_with_template
    template: '<EMAIL:{hash8}>'
    whitelist: ['*@example.com']  # Allow company emails

  # Pseudonymize IPs (with CIDR whitelist)
  - id: ipv4
    type: ipv4
    whitelist_cidrs: ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']
    action: pseudonymize

  # Detect high-entropy tokens
  - id: high_entropy_token
    type: entropy
    min_entropy: 4.5
    min_length: 20
    action: redact

# Whitelist (never sanitize)
whitelist:
  emails:
    - '*@public-domain.com'
  urls:
    - 'https://public.example.com'

# Blacklist (always block)
blacklist:
  emails:
    - 'secret@internal.company'
  ips:
    - '203.0.113.42'
```

### `.mcpignore` File

Control which files are skipped during `pack`/`unpack` (similar to `.gitignore`):

```
# .mcpignore

# Binaries
*.pyc
*.so
*.dll

# Build artifacts
dist/
build/
__pycache__/

# Virtual environments
.venv/
venv/
node_modules/

# Media files
*.png
*.jpg
*.pdf
*.mp4

# Already sensitive
audit/
keys/
.vscode/
.git/
```

---

## 🖥️ VS Code Integration

CloakMCP includes pre-configured VS Code tasks and keyboard shortcuts.

### Keyboard Shortcuts

| Shortcut       | Action                            | Description                          |
| -------------- | --------------------------------- | ------------------------------------ |
| `Ctrl+Alt+S`   | Sanitize current file (preview)   | Print sanitized output to terminal   |
| `Ctrl+Alt+A`   | Scan current file (audit only)    | Log detections to `audit/` (silent)  |

### Tasks

Run via Command Palette (`Ctrl+Shift+P` → "Tasks: Run Task"):

1. **MCP: Sanitize current file → preview**
2. **MCP: Scan current file (audit only)**
3. **MCP: Sanitize selection via API** (requires server)

### Configuration Files

- `.vscode/keybindings.json` — Keyboard shortcuts
- `.vscode/tasks.json` — Task definitions
- `.vscode/settings.json` — Project settings

**📖 Full guide**: See [`VSCODE_MANUAL.md`](VSCODE_MANUAL.md) (24 KB, 1200+ lines)

---

## 🌐 API Server (Optional)

CloakMCP includes an optional FastAPI server for real-time sanitization.

### Start Server

```bash
# Generate API token (once)
openssl rand -hex 32 > keys/mcp_api_token

# Start server (localhost only)
uvicorn mcp.server:app --host 127.0.0.1 --port 8765
```

### Endpoints

| Endpoint     | Method | Description                           |
| ------------ | ------ | ------------------------------------- |
| `/health`    | GET    | Server status and policy hash         |
| `/sanitize`  | POST   | Sanitize text (modify secrets)        |
| `/scan`      | POST   | Scan text (audit only, no modification)|

All endpoints require **Bearer token** authentication.

### API Documentation

Interactive docs available at: http://127.0.0.1:8765/docs (when server running)

### Example Request

```bash
TOKEN=$(cat keys/mcp_api_token)

curl -X POST http://127.0.0.1:8765/sanitize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email: alice@example.com\nKey: AKIAIOSFODNN7EXAMPLE",
    "policy_path": "examples/mcp_policy.yaml",
    "dry_run": false
  }'
```

---

## 🔐 Security & Vaults

### Vault Architecture

```
~/.cloakmcp/
├── keys/
│   └── <project-slug>.key        # Fernet encryption key (AES-128)
└── vaults/
    └── <project-slug>.vault      # Encrypted JSON: {TAG → secret}
```

- **Slug**: 16-character SHA-256 prefix of project's absolute path
- **Encryption**: AES-128 via `cryptography.Fernet`
- **Permissions**: 0600 (owner read/write only)
- **Portability**: Copy `.key` and `.vault` to share between machines

### Security Features

- ✅ **Local-first**: No network calls during sanitization
- ✅ **Encrypted storage**: Vaults use industry-standard AES-128
- ✅ **Deterministic**: Same secret → same tag (reproducible)
- ✅ **Auditable**: All operations logged with timestamps
- ✅ **Isolated**: Vaults stored outside project directory

### Best Practices

1. **Never commit keys**: Add `keys/` to `.gitignore`
2. **Backup vaults**: Regularly backup `~/.cloakmcp/` directory
3. **Rotate keys**: Periodically regenerate HMAC keys
4. **Use pre-commit hooks**: Automate scanning before commits
5. **Pack before sharing**: Always `pack` before uploading to LLMs
6. **Review audit logs**: Check `audit/audit.jsonl` for unexpected detections

---

## 🔄 Workflows

### Workflow 1: Safe LLM Code Review

```bash
# 1. Pack project (anonymize)
mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG

# 2. Verify secrets removed
grep -r "AKIA" .  # Should return nothing
grep -r "TAG-" .  # Should find tags

# 3. Share with Claude/Codex/Copilot
# (Upload files or paste code)

# 4. Receive reviewed/modified code from LLM
# (Tags preserved in LLM output)

# 5. Unpack to restore secrets
mcp unpack --dir .

# 6. Verify restoration
git diff  # Should show no changes if no edits made
```

### Workflow 2: Pre-Commit Hook

**`.git/hooks/pre-commit`**:

```bash
#!/bin/bash
# CloakMCP pre-commit hook

echo "🔒 CloakMCP: Scanning staged files for secrets..."

for file in $(git diff --cached --name-only --diff-filter=ACM); do
  if [ -f "$file" ]; then
    if ! mcp scan --policy examples/mcp_policy.yaml --input "$file"; then
      echo "❌ Secrets detected in $file. Commit blocked."
      echo "   Fix: mcp sanitize --policy examples/mcp_policy.yaml --input $file --output $file"
      exit 1
    fi
  fi
done

echo "✅ No secrets detected. Commit allowed."
exit 0
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

### Workflow 3: CI/CD Pipeline

**`.github/workflows/test.yml`**:

```yaml
name: Test with CloakMCP

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install CloakMCP
        run: |
          pip install -e .
          mkdir -p keys
          echo "${{ secrets.MCP_HMAC_KEY }}" > keys/mcp_hmac_key

      - name: Pack secrets (anonymize)
        run: mcp pack --policy examples/mcp_policy.yaml --dir . --prefix CI_TAG

      - name: Run tests
        run: pytest -v

      # Do NOT unpack in CI (secrets should never be in CI logs)
```

**⚠️ Important**: Store `MCP_HMAC_KEY` in GitHub Secrets, never in repository.

---

## 🧪 Testing

### Run Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest -v

# Run with coverage
pytest --cov=mcp --cov-report=html --cov-report=term

# View coverage report
xdg-open htmlcov/index.html  # Linux
open htmlcov/index.html      # macOS
```

### Test Suite

- **90+ tests** across 15 test classes
- **Target coverage**: 95%
- **Test categories**:
  - Unit tests (individual functions)
  - Integration tests (full workflows)
  - API tests (FastAPI endpoints)
  - Edge cases (empty, long, malformed input)
  - Error handling (missing files, invalid data)
  - Performance tests (large files, many secrets)

**📖 Full guide**: See [`tests/README.md`](tests/README.md)

---

## 📚 Documentation

| Document                    | Description                                  | Size     |
| --------------------------- | -------------------------------------------- | -------- |
| **`README.md`**             | This file (overview and quick start)         | Current  |
| **`VSCODE_MANUAL.md`**      | Complete VS Code integration guide           | 24 KB    |
| **`QUICKREF.md`**           | One-page cheat sheet for daily use           | 4 KB     |
| **`CLAUDE.md`**             | Project specifications (for LLMs)            | —        |
| **`ISSUES_REPORT.md`**      | Pre-deployment code review findings          | 8 KB     |
| **`DEPLOYMENT_SUMMARY.md`** | Comprehensive deployment summary             | 15 KB    |
| **`tests/README.md`**       | Test suite documentation                     | 6 KB     |
| **`SECURITY.md`**           | Security policy and disclosure               | —        |
| **`CONTRIBUTING.md`**       | Contribution guidelines                      | —        |
| **`AUTHORS.md`**            | Credits and authorship                       | —        |

---

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/ovitrac/CloakMCP.git
cd CloakMCP

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e .
pip install pytest pytest-cov black mypy bandit pre-commit

# Install pre-commit hooks
pre-commit install

# Generate keys
mkdir -p keys audit
openssl rand -hex 32 > keys/mcp_hmac_key
```

### Code Quality Tools

```bash
# Format code (Black)
black mcp/ tests/

# Sort imports (isort)
isort mcp/ tests/

# Type checking (mypy)
mypy mcp/

# Security linting (Bandit)
bandit -r mcp/

# Run all checks
pre-commit run --all-files
```

### Project Structure

```
CloakMCP/
├── mcp/                        # Main package
│   ├── __init__.py
│   ├── actions.py              # Action engine (redact, pseudonymize, etc.)
│   ├── audit.py                # Audit logging
│   ├── cli.py                  # CLI entry point
│   ├── dirpack.py              # Directory pack/unpack
│   ├── normalizer.py           # Text normalization
│   ├── policy.py               # Policy engine (YAML parsing)
│   ├── scanner.py              # Secret detectors
│   ├── server.py               # FastAPI server
│   ├── storage.py              # Vault encryption
│   └── utils.py                # Utilities (hashing, encoding)
├── tests/                      # Test suite
│   ├── test_comprehensive.py  # Full feature tests
│   ├── test_api.py             # API endpoint tests
│   ├── test_smoke.py           # Basic smoke test
│   └── README.md
├── examples/                   # Example files
│   ├── mcp_policy.yaml         # Example policy
│   └── client_sanitize.py      # API client example
├── .vscode/                    # VS Code integration
│   ├── keybindings.json
│   ├── settings.json
│   └── tasks.json
├── deploy/                     # Deployment configs
│   └── mcp-local.service       # systemd service
├── api/                        # API examples
│   └── requests.http           # REST Client examples
├── docs/                       # Documentation
│   ├── VSCODE_MANUAL.md
│   ├── QUICKREF.md
│   ├── ISSUES_REPORT.md
│   └── DEPLOYMENT_SUMMARY.md
├── pyproject.toml              # Package metadata
├── pytest.ini                  # pytest configuration
├── .gitignore
├── .mcpignore                  # Pack/unpack ignore patterns
├── LICENSE                     # MIT License
├── README.md                   # This file
├── CLAUDE.md                   # LLM instructions
├── CONTRIBUTING.md
├── SECURITY.md
└── AUTHORS.md
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes
4. **Add tests** for new functionality
5. **Run tests**: `pytest -v`
6. **Format code**: `black mcp/ tests/`
7. **Commit**: `git commit -m "feat: add amazing feature"`
8. **Push**: `git push origin feature/amazing-feature`
9. **Open** a Pull Request

### Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### Code Style

- **Python 3.10+** with type hints
- **Black** for formatting (line length: 100)
- **isort** for import sorting
- **mypy** for type checking (strict mode)
- **pytest** for testing (target: 95% coverage)

### Pull Request Checklist

- [ ] Tests pass (`pytest -v`)
- [ ] Code formatted (`black mcp/ tests/`)
- [ ] Type checks pass (`mypy mcp/`)
- [ ] Security checks pass (`bandit -r mcp/`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No secrets committed (run `mcp scan`)

**📖 Full guide**: See [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## 📝 Changelog

### v0.2.0 (2025-11-11) — Beta Release

**Added**:
- Pack/unpack commands for directory-level operations
- Encrypted vault storage (`~/.cloakmcp/`)
- Deterministic tagging (same secret → same tag)
- Comprehensive test suite (90+ tests)
- VS Code integration (keyboard shortcuts, tasks)
- Complete documentation (50+ pages)
- API server mode (FastAPI)
- `.mcpignore` support for excluding files

**Fixed**:
- Leading backslashes in source files (YAML parsing issue)
- Version mismatch in API server (0.1.0 → 0.2.0)

**Changed**:
- Improved error handling in file operations
- Better audit logging format
- Enhanced documentation structure

### v0.1.0 (2025-11-06) — Alpha Release

**Initial release**:
- Basic scan/sanitize commands
- Policy-driven detection
- YAML configuration
- Audit logging
- CLI interface

---

## 📄 License

This project is licensed under the **MIT License** — see the [`LICENSE`](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Olivier Vitrac and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 👥 Authors & Acknowledgments

### Authors

- **Olivier Vitrac** — *Design & Implementation* — [Adservio Innovation Lab](https://adservio.fr)

### Contributors

See [`AUTHORS.md`](AUTHORS.md) for the full list of contributors.

### Acknowledgments

- Inspired by [GitGuardian CLI](https://github.com/GitGuardian/ggshield)
- Inspired by [Mozilla SOPS](https://github.com/mozilla/sops)
- Inspired by OpenAI Red Team practices
- Thanks to the Python cryptography team
- Thanks to FastAPI and Pydantic maintainers

---

## 🔗 Links

- **GitHub Repository**: https://github.com/ovitrac/CloakMCP
- **Issue Tracker**: https://github.com/ovitrac/CloakMCP/issues
- **Discussions**: https://github.com/ovitrac/CloakMCP/discussions
- **Documentation**: [Full docs](./docs/)
- **License**: [MIT](./LICENSE)

---

## 🆘 Support

### Getting Help

1. **Read the docs**: Start with [`QUICKREF.md`](QUICKREF.md) or [`VSCODE_MANUAL.md`](VSCODE_MANUAL.md)
2. **Check issues**: Search [existing issues](https://github.com/ovitrac/CloakMCP/issues)
3. **Ask questions**: Open a [discussion](https://github.com/ovitrac/CloakMCP/discussions)
4. **Report bugs**: Create an [issue](https://github.com/ovitrac/CloakMCP/issues/new)

### Common Issues

| Problem                       | Solution                                          |
| ----------------------------- | ------------------------------------------------- |
| `mcp: command not found`      | Activate venv: `source .venv/bin/activate`        |
| `Missing API token`           | Create: `openssl rand -hex 32 > keys/mcp_api_token` |
| `Policy file not found`       | Use absolute path or check working directory      |
| Secrets not detected          | Add custom rule to `mcp_policy.yaml`              |
| `InvalidToken` (vault error)  | Key mismatch; check `~/.cloakmcp/keys/`           |

**📖 Full troubleshooting**: See [`VSCODE_MANUAL.md#troubleshooting`](VSCODE_MANUAL.md#troubleshooting)

---

## ⚠️ Disclaimer

CloakMCP protects **content confidentiality** (hides values), not **intent semantics** (project logic). Always review sanitized output before sharing. Vault integrity relies on local filesystem security — keep `~/.cloakmcp/` private and backed up.

**Important**: This tool is designed for **authorized use only**. Do not use to circumvent security policies or exfiltrate sensitive data.

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ovitrac/CloakMCP&type=Date)](https://star-history.com/#ovitrac/CloakMCP&Date)

---

<div align="center">

**Made with ❤️ by [Olivier Vitrac](https://github.com/ovitrac) at [Adservio Innovation Lab](https://adservio.fr)**

**⭐ Star us on GitHub — it helps!**

[⬆ Back to Top](#-cloakmcp)

</div>
