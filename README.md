<div align="center">
<p align="center">
  <img src="assets/cloakMCP-logo.png" alt="cloackMCP Logo" height="128"><br>
</p>

# 🔒 CloakMCP

### Micro-Cleanse Preprocessor — Local Secret Removal

**Protect your secrets before sharing code with LLMs**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.3.2--alpha-orange.svg)](https://github.com/ovitrac/CloakMCP/releases)
[![Tests](https://img.shields.io/badge/tests-90%2B%20passing-brightgreen.svg)](./tests)
[![DeepWiki](https://img.shields.io/badge/Docs-DeepWiki-purple.svg)](https://deepwiki.com/ovitrac/CloakMCP)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[Features](#-features) • [Security](#-security-architecture) • [Quick Start](#-quick-start) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## ⚡ 2-Minute Quick Start

**Try CloakMCP in under 2 minutes:**

```bash
# 1. Install (30 seconds)
git clone https://github.com/ovitrac/CloakMCP.git && cd CloakMCP
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# 2. Setup (30 seconds)
mkdir -p keys && openssl rand -hex 32 > keys/mcp_hmac_key

# 3. Test (1 minute)
# Create a test file with a fake secret
echo "API_KEY=sk_live_abc123xyz456" > test.py

# Sanitize it
cloak sanitize --policy examples/mcp_policy.yaml --input test.py --output -

# Output: API_KEY=<REDACTED:generic_secret>
# ✅ Secret removed! Original stays safe in your file.
```

**Next**: See [Quick Start](#-quick-start) for full workflows with pack/unpack.

---

## 📖 Overview

**CloakMCP** is a **local-first, deterministic sanitizer** that removes or neutralizes secrets (emails, IPs, URLs, tokens, API keys, PII) **before** your text/code is sent to LLMs like Claude, GitHub Copilot, or OpenAI Codex.

### Why CloakMCP?

- 🔐 **Local-first**: All operations run on your machine — no cloud dependencies
- 🔄 **Reversible**: Deterministic tagging allows safe restoration via encrypted vaults
- 📦 **Batch processing**: Pack/unpack entire codebases with one command
- ⚙️ **Policy-driven**: Configure detection rules via YAML (regex, entropy, IPs, URLs)
- 🏢 **Group policies**: Hierarchical policy inheritance (company → team → project)
- 🔍 **Auditable**: Every operation logged to `audit/audit.jsonl`
- 🚀 **LLM-ready**: Designed for safe collaboration with AI coding assistants
- 💻 **VS Code integrated**: One-keystroke sanitization with `Ctrl+Alt+S`

### Use Cases

- ✅ Share code with LLMs without exposing credentials
- ✅ Pre-commit hooks to prevent secret leaks
- ✅ Sanitize logs before uploading to issue trackers
- ✅ Anonymize customer data in demos/screenshots
- ✅ CI/CD pipelines with encrypted secret management

### Comparison with Existing Tools

| Feature | CloakMCP | ggshield/gitleaks | SOPS | DIY Scripts |
|---------|----------|-------------------|------|-------------|
| **Detect secrets** | ✅ | ✅ | ❌ | ✅ |
| **Reversible redaction** | ✅ | ❌ | ❌ | ❌ |
| **LLM-optimized workflow** | ✅ | ❌ | ❌ | ❌ |
| **Deterministic tags** | ✅ (HMAC-based) | ❌ | ❌ | Varies |
| **Local-only vault** | ✅ | ❌ | ❌ (cloud KMS) | Varies |
| **Directory pack/unpack** | ✅ | ❌ | ❌ | ❌ |
| **Encrypted storage** | ✅ (AES-128 Fernet) | ❌ | ✅ (cloud KMS) | Varies |
| **IDE integration** | ✅ (VS Code) | ✅ | ❌ | ❌ |

**When to use CloakMCP**:
- ✅ You're sharing code with LLMs (Claude, Codex, Copilot) and need to restore secrets later
- ✅ You need **reversible** secret redaction for development workflows
- ✅ You want **local-only** secret storage (no cloud dependencies)

**When to use ggshield/gitleaks**:
- ✅ You only need detection/blocking (no restoration required)
- ✅ You want pre-commit hooks with extensive pattern databases

**When to use SOPS**:
- ✅ You need cloud KMS integration for infrastructure secrets
- ✅ You're managing secrets in production environments (Kubernetes, AWS)

---

## 🎯 Features

### Core Features

| Feature                      | Description                                                  |
| ---------------------------- | ------------------------------------------------------------ |
| **Scan**                     | Detect secrets without modification (audit mode)             |
| **Sanitize**                 | Replace secrets with tags, hashes, or pseudonyms             |
| **Pack/Unpack**              | Batch-process entire directories with encrypted vault storage|
| **Policy Engine**            | YAML-based rules for detection and actions                   |
| **Group Policies**           | Hierarchical policy inheritance with cycle detection         |
| **Encrypted Vaults**         | AES-128 (Fernet) encryption for reversible secret storage    |
| **Deterministic Tags**       | HMAC-based tags: same secret → same tag (cryptographically secure) |
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

## 🔒 Security Architecture

### How CloakMCP Protects Your Secrets

CloakMCP ensures that **secrets never leave your local machine**. Here's how:

#### Where Secrets Are Stored

```mermaid
graph TB
    subgraph "Your Local Machine"
        A[Original Code<br/>with Secrets] -->|cloak pack| B[Packed Code<br/>with Tags]
        B --> C[Git Repository]
        A -->|secrets extracted| D[Encrypted Vault<br/>~/.cloakmcp/vaults/]
        D -.encryption key.-> E[Encryption Key<br/>~/.cloakmcp/keys/]
    end

    subgraph "Shared with LLM"
        C -->|safe to share| F[Claude/Codex<br/>sees only tags]
    end

    subgraph "Restoration"
        F -->|modified code| G[Code with Tags]
        G -->|cloak unpack| H[Original Code<br/>secrets restored]
        D -.decryption.-> H
    end

    style D fill:#ffcccc, color:#000000
    style E fill:#ffcccc, color:#000000
    style F fill:#ccffcc, color:#000000
    style H fill:#ccccff, color:#000000
```

**Key Points**:
- 🔐 **Vault location**: `~/.cloakmcp/vaults/<project-slug>.vault`
- 🔑 **Keys location**: `~/.cloakmcp/keys/<project-slug>.key`
- 📦 **Encryption**: AES-128 (Fernet) symmetric encryption
- 🚫 **Never committed**: Vaults and keys stay outside git repository
- 🏷️ **Tags in code**: HMAC-based deterministic identifiers like `TAG-2f1a8e3c9b12` (keyed with vault key)

#### Why LLMs Cannot Access Secrets

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant MCP as CloakMCP
    participant Vault as Encrypted Vault<br/>(~/.cloakmcp/)
    participant LLM as LLM (Claude/Codex)

    Dev->>MCP: cloak pack --dir /project
    MCP->>MCP: Scan for secrets
    MCP->>Vault: Store secret → TAG mapping (encrypted)
    MCP->>Dev: Code with tags (TAG-xxxx)

    Dev->>LLM: Share tagged code
    Note over LLM: LLM sees: TAG-2f1a8e3c9b12<br/>NOT: sk_live_abc123xyz

    LLM->>Dev: Modified code (tags preserved)
    Dev->>MCP: cloak unpack --dir /project
    MCP->>Vault: Retrieve secret for TAG-xxxx
    Vault->>MCP: Decrypted secret
    MCP->>Dev: Code with original secrets
```

**Security Properties**:
1. **Vault is local-only** — Never uploaded to git, cloud, or LLM
2. **HMAC-based tags** — Tags use HMAC-SHA256 with vault key; cannot reverse `TAG-2f1a8e3c9b12` → original secret without vault key
3. **Brute-force resistant** — Even with tag and candidate secret, attacker needs vault key to verify guesses
4. **Encryption protects vault** — Even if vault file leaks, attacker needs encryption key
5. **Keys are separate** — Vault + key both required for decryption

### Data Flow Comparison

#### Without CloakMCP ❌
```mermaid
graph LR
    A[Code with Secrets] -->|sent directly| B[LLM Provider]
    B -->|logged forever| C[Provider Database]
    style C fill:#ffcccc
```
**Risk**: Secrets permanently stored on provider servers

#### With CloakMCP ✅
```mermaid
graph LR
    A[Code with Secrets] -->|cloak pack| B[Code with Tags]
    B -->|safe to send| C[LLM Provider]
    C -->|only sees tags| D[Provider Database]
    A -.secrets stay local.-> E[Encrypted Vault<br/>~/.cloakmcp/]
    style E fill:#ccffcc
    style D fill:#ccffcc
```
**Protection**: Only meaningless tags reach provider

### CLI vs Server Mode

#### CLI Mode (Local Processing)
```mermaid
graph TB
    subgraph "Your Machine"
        A[File with Secrets] -->|cloak sanitize| B[Policy Engine]
        B --> C[Scanner]
        C --> D[Action Engine]
        D --> E[Sanitized Output]
    end

    E -.copy/paste.-> F[LLM Chat]
```
**Use case**: Manual sanitization before copy/paste to LLM

#### Server Mode (IDE Integration)
```mermaid
graph TB
    subgraph "Your Machine"
        A[VS Code] -->|HTTP 127.0.0.1:8765| B[MCP Server]
        B --> C[Policy Engine]
        C --> D[Action Engine]
        D -->|sanitized| A
    end

    A -.safe to send.-> E[LLM API]

    style B fill:#ffffcc
```
**Use case**: Automatic sanitization in IDE before sending to LLM API

**Important**: Server binds to `127.0.0.1` (localhost) — no network exposure

### Vault Security Model

| Component | Location | Format | Access |
|-----------|----------|--------|--------|
| **Original Secrets** | Your files | Plaintext | You only (before pack) |
| **Encrypted Vault** | `~/.cloakmcp/vaults/` | AES-128 Fernet | You only (local filesystem) |
| **Encryption Key** | `~/.cloakmcp/keys/` | Binary (Fernet) | You only (600 permissions) |
| **Tagged Code** | Git repository | Text files | Safe to share |
| **LLM View** | LLM provider | Tags only | Cannot reverse to secrets |

### Common Questions

**Q: Can someone with my git repo see my secrets?**
**A**: No. Git only contains tags like `TAG-2f1a8e3c9b12`. The vault (with actual secrets) is in `~/.cloakmcp/` on your machine.

**Q: What if I lose my vault key?**
**A**: Secrets are unrecoverable. Keep backups of `~/.cloakmcp/keys/` in a secure location (password manager, encrypted USB).

**Q: Can LLMs guess secrets from tags?**
**A**: No. Tags are HMAC-SHA256 signatures (keyed with your vault key) truncated to 12 hex chars. Without access to your `~/.cloakmcp/keys/` directory, reversing tags is cryptographically infeasible. Even with the tag, an attacker would need your vault key to verify guesses.

**Q: Does the API server expose secrets over network?**
**A**: No. Server binds to `127.0.0.1` (localhost only). Requests never leave your machine. Sanitized output (with tags) can then be sent to LLMs.

**Q: Can I use CloakMCP with remote LLM APIs?**
**A**: Yes. Sanitize locally first, then send tagged output to API. Example:
```bash
cloak sanitize --input code.py --output code.tagged.py --policy mcp_policy.yaml
curl -X POST https://api.anthropic.com/v1/complete -d @code.tagged.py
```

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
cloak --help
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
cloak scan --policy examples/mcp_policy.yaml --input test_secrets.py

# Sanitize (preview to terminal)
cloak sanitize --policy examples/mcp_policy.yaml --input test_secrets.py --output -
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
cloak pack --policy examples/mcp_policy.yaml --dir . --prefix TAG

# Now safe to share with LLMs (secrets replaced with TAG-xxxxxxxxxxxx)
# Vault stored securely in ~/.cloakmcp/vaults/

# Unpack: Restore original secrets
cloak unpack --dir .
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

#### `cloak scan`

Scan file for secrets (audit mode, no modification):

```bash
cloak scan --policy examples/mcp_policy.yaml --input file.py
```

**Output**: Logs written to `audit/audit.jsonl`

#### `cloak sanitize`

Sanitize file and output result:

```bash
# Preview to stdout
cloak sanitize --policy examples/mcp_policy.yaml --input file.py --output -

# Overwrite file (use with caution)
cloak sanitize --policy examples/mcp_policy.yaml --input file.py --output file.py

# Write to new file
cloak sanitize --policy examples/mcp_policy.yaml --input file.py --output file.sanitized.py
```

#### `cloak pack`

Pack directory (replace secrets with tags):

```bash
cloak pack --policy examples/mcp_policy.yaml --dir /path/to/project --prefix TAG
```

**What it does**:
- Scans all files (respects `.mcpignore`)
- Replaces secrets with deterministic tags: `TAG-a1b2c3d4e5f6`
- Stores mapping in encrypted vault: `~/.cloakmcp/vaults/<slug>.vault`
- Modifies files **in place**

#### `cloak unpack`

Unpack directory (restore secrets from vault):

```bash
cloak unpack --dir /path/to/project
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

## 🏢 Group Policies

**New in v0.3.2**: Organizations can now define hierarchical security policies that cascade from company → team → project level.

### Why Group Policies?

- ✅ **Centralized compliance**: Define organization-wide baseline rules once
- ✅ **Team customization**: Teams can add specialized rules (backend, frontend, DevOps)
- ✅ **Project flexibility**: Individual projects can override or extend inherited rules
- ✅ **Easy distribution**: Share policies via Git repos or internal package managers
- ✅ **No key sharing**: Policies share RULES (detection patterns), NOT encryption keys

### Architecture

```mermaid
graph TB
    A[Company Baseline<br/>~/.cloakmcp/policies/company-baseline.yaml] --> B[Backend Team Policy<br/>~/.cloakmcp/policies/team-backend.yaml]
    A --> C[Frontend Team Policy<br/>~/.cloakmcp/policies/team-frontend.yaml]
    B --> D[Project Policy<br/>examples/my-project-policy.yaml]

    style A fill:#ffcccc
    style B fill:#ccffcc
    style D fill:#ccccff
```

**Key principles**:
1. Policies share **detection rules**, NOT vault keys
2. Each project maintains its own **unique vault key**
3. Later policies **override** earlier ones (for rules with same ID)
4. Cycle detection prevents circular inheritance

### Example: 3-Level Hierarchy

#### Company Baseline (`~/.cloakmcp/policies/company-baseline.yaml`)
```yaml
version: 1

globals:
  default_action: block

detection:
  - id: company_api_key
    type: regex
    pattern: '\bCOMP-[A-Z0-9]{32}\b'
    action: block

  - id: aws_access_key
    type: regex
    pattern: '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    action: block

  - id: internal_email
    type: regex
    pattern: '[a-z0-9_.+\-]+@company\.com'
    action: pseudonymize
```

#### Team Policy (`~/.cloakmcp/policies/team-backend.yaml`)
```yaml
version: 1

inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml

detection:
  - id: postgresql_connection
    type: regex
    pattern: 'postgresql://[^\s]+'
    action: block

  - id: redis_password
    type: regex
    pattern: 'redis://:[^@]+@'
    action: block
```

#### Project Policy (`examples/my-project-policy.yaml`)
```yaml
version: 1

inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml
  - ~/.cloakmcp/policies/team-backend.yaml

globals:
  default_action: redact  # Override company default

detection:
  - id: project_api_token
    type: regex
    pattern: '\bPROJ-[A-Z0-9]{24}\b'
    action: block

  # Override parent rule
  - id: internal_email
    type: regex
    pattern: '[a-z0-9_.+\-]+@company\.com'
    action: redact  # Override company's 'pseudonymize'
```

### Policy Management Commands

#### Validate Policy (with inheritance)
```bash
$ cloak policy validate --policy examples/my-project-policy.yaml
✓ Policy is valid: examples/my-project-policy.yaml
  Inheritance chain:
    1. /home/user/.cloakmcp/policies/company-baseline.yaml
    2. /home/user/.cloakmcp/policies/team-backend.yaml
    3. /home/user/projects/myapp/examples/my-project-policy.yaml
  Total detection rules: 20
```

#### Show Merged Policy
```bash
# Show final merged policy (after inheritance)
cloak policy show --policy examples/my-project-policy.yaml --format yaml

# Export as JSON for programmatic use
cloak policy show --policy examples/my-project-policy.yaml --format json
```

### Setup: Organization-Wide Policies

```bash
# 1. Create global policies directory
mkdir -p ~/.cloakmcp/policies

# 2. Deploy company baseline (via Git or internal package)
curl -o ~/.cloakmcp/policies/company-baseline.yaml \
  https://internal.company.com/security/cloakmcp-policy.yaml

# Or clone from internal Git repo
git clone git@company.com:security/cloakmcp-policies.git ~/.cloakmcp/policies/

# 3. Projects reference company policy
cat > my-project-policy.yaml <<EOF
version: 1
inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml
EOF

# 4. Use as normal
cloak pack --policy my-project-policy.yaml --dir .
```

### Merging Rules

When policies inherit from multiple parents:

1. **Globals**: Later values override earlier values
2. **Detection rules**: Rules with same `id` are replaced, others are appended
3. **Whitelist/blacklist**: Lists are concatenated (no deduplication)
4. **Order matters**: Last policy in `inherits` list has highest precedence

**Example**:
```yaml
inherits:
  - company-baseline.yaml    # Applied first
  - team-backend.yaml        # Overrides company rules
  # Current file rules       # Overrides all parents (highest precedence)
```

### Security Model

**Q: Does group policy share encryption keys?**
**A**: No. Policies share **detection rules** (patterns, actions), NOT vault keys. Each project maintains its own unique encryption key in `~/.cloakmcp/keys/<project-slug>.key`.

**Q: Where are policies stored?**
**A**:
- **Company/team policies**: `~/.cloakmcp/policies/` (outside project directories)
- **Project policies**: Inside project (e.g., `examples/mcp_policy.yaml`)
- **Vaults (with secrets)**: `~/.cloakmcp/vaults/` (never shared)

**Q: Can I use relative paths in `inherits`?**
**A**: Yes. Relative paths are resolved relative to the current policy file's directory. Tilde (`~`) is expanded to home directory.

### Best Practices

1. **Version control company policies**: Use Git to distribute baseline policies across org
2. **Keep team policies DRY**: Inherit from company baseline, only add team-specific rules
3. **Document overrides**: Comment why project policies override parent rules
4. **Test inheritance**: Use `cloak policy validate` to see full inheritance chain
5. **Avoid deep nesting**: Keep inheritance to 3 levels max (company → team → project)

**📖 Full guide**: See [`GROUP_POLICY_IMPLEMENTATION.md`](GROUP_POLICY_IMPLEMENTATION.md) for implementation details.

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
uvicorn cloak.server:app --host 127.0.0.1 --port 8765
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
cloak pack --policy examples/mcp_policy.yaml --dir . --prefix TAG

# 2. Verify secrets removed
grep -r "AKIA" .  # Should return nothing
grep -r "TAG-" .  # Should find tags

# 3. Share with Claude/Codex/Copilot
# (Upload files or paste code)

# 4. Receive reviewed/modified code from LLM
# (Tags preserved in LLM output)

# 5. Unpack to restore secrets
cloak unpack --dir .

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
    if ! cloak scan --policy examples/mcp_policy.yaml --input "$file"; then
      echo "❌ Secrets detected in $file. Commit blocked."
      echo "   Fix: cloak sanitize --policy examples/mcp_policy.yaml --input $file --output $file"
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
        run: cloak pack --policy examples/mcp_policy.yaml --dir . --prefix CI_TAG

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
pytest --cov=cloak --cov-report=html --cov-report=term

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
| **`SERVER.md`**             | Server configuration and data storage        | 20 KB    |
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
│   └── cloak-local.service       # systemd service
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
- [ ] No secrets committed (run `cloak scan`)

**📖 Full guide**: See [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## 📝 Changelog

### v0.3.2 (2025-11-12) — Group Policy Inheritance

**Added**:
- **Group policy inheritance**: Hierarchical policy loading (company → team → project)
- **Policy management commands**: `cloak policy validate` and `cloak policy show`
- **Cycle detection**: Prevent circular policy inheritance
- **Deep policy merging**: Later policies override earlier ones with clear precedence rules
- **Path resolution**: Tilde expansion and relative path support for `inherits` field

**Features**:
- Policies can inherit from multiple parents using `inherits` field
- Inheritance chain tracking for debugging (shows full policy ancestry)
- Merged policy export in YAML or JSON format
- Example policies demonstrating 3-level hierarchy (company/team/project)

**Security**:
- Policies share **detection rules** only, NOT encryption keys
- Each project maintains unique vault key (local-first model preserved)
- No remote vault server required for policy distribution

**Documentation**:
- Added comprehensive Group Policies section to README
- Created GROUP_POLICY_IMPLEMENTATION.md with implementation details
- Example policy files: company-baseline.yaml, team-backend.yaml, project-with-inheritance.yaml

**Fixed**:
- Path resolution bug: tilde expansion now occurs before absolute path check

### v0.3.1 (2025-11-12) — Security Hardening Release

**BREAKING CHANGES**:
- Tags now use HMAC-SHA256 (keyed) instead of plain SHA-256. **Existing vaults are incompatible** with v0.3.1. Backup your vaults before upgrading.

**Security** (Critical):
- **HMAC-based tags**: Vault tags now use HMAC-SHA256 with vault key, preventing brute-force attacks on structured secrets
- Comprehensive SERVER.md documentation with threat model and security architecture
- Explicit warnings for server network exposure
- Updated security claims in README with accurate cryptographic guarantees

**Documentation**:
- Added SERVER.md (20 KB) with complete server configuration guide
- Added 5 Mermaid diagrams showing data flow and security architecture
- Clarified where secrets are stored and why LLMs cannot access them
- Added comparison table with existing tools (ggshield, SOPS, etc.)

**Changed**:
- Version badge changed from "beta" to "alpha" to reflect ongoing security review
- Improved security messaging throughout documentation

### v0.2.5 (2025-11-11) — Performance & Features

**Added**:
- HMAC key caching for 100-1000× performance improvement in bulk operations
- API rate limiting (10 requests/minute per IP) with slowapi integration
- Vault export/import commands for disaster recovery (`vault-export`, `vault-import`, `vault-stats`)
- CLI input validation for all file and directory paths
- Key length validation with security warnings

**Fixed**:
- CLI crashes on invalid file paths (now shows clear error messages)
- CIDR validation errors on malformed policy entries
- Silent failures in pack/unpack operations (now logged with specific exception types)
- Missing error visibility in file operations (added counters and summary messages)

**Security**:
- Input path validation prevents path traversal attacks
- Rate limiting protects against brute-force token attacks
- Graceful handling of malformed CIDR strings in policies

**Performance**:
- Key caching reduces I/O bottleneck from 100-500 ops/sec to 100,000+ ops/sec

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
| `cloak: command not found`      | Activate venv: `source .venv/bin/activate`        |
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
