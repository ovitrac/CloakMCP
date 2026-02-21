# CloakMCP Server Documentation

**Version**: 0.3.1
**Date**: 2025-11-11
**Maintainer**: Olivier Vitrac — Adservio Innovation Lab

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Data Storage](#data-storage)
- [Server Modes](#server-modes)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Overview

CloakMCP can operate in two modes:

1. **CLI Mode** (default) — Direct command-line usage, no network involved
2. **Server Mode** (optional) — FastAPI REST API for IDE integration

**Important**: CloakMCP is designed as a **local-first** tool. The server mode is for **localhost-only** integration with IDEs and tools, not for remote deployment.

---

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR LOCAL MACHINE                       │
│                                                             │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │   VS Code    │────────▶│  MCP Server  │                  │
│  │              │  HTTP   │ 127.0.0.1:   │                  │
│  │  (or IDE)    │ Request │  8765        │                  │
│  └──────────────┘         └──────┬───────┘                  │
│                                   │                         │
│                                   ▼                         │
│                          ┌────────────────┐                 │
│                          │  Policy Engine │                 │
│                          │  + Scanner     │                 │
│                          └────────┬───────┘                 │
│                                   │                         │
│                    ┌──────────────┴──────────────┐          │
│                    ▼                             ▼          │
│           ┌─────────────────┐          ┌──────────────┐     │
│           │  Encrypted Vault│          │ Audit Logs   │     │
│           │  ~/.cloakmcp/   │          │ ./audit/     │     │
│           └─────────────────┘          └──────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Sanitized output
                          │ (secrets replaced by tags)
                          ▼
                  ┌───────────────┐
                  │  LLM (Claude, │
                  │   Codex, etc) │
                  └───────────────┘
```

**Key principle**: Secrets **never leave your machine**. Only sanitized data (with tags) goes to LLMs.

---

## Data Storage

### Where Data is Stored

#### 1. **Vault Data** (Encrypted Secrets)

**Location**: `~/.cloakmcp/vaults/`

```
~/.cloakmcp/
├── keys/
│   └── <project-slug>.key        # Fernet encryption key (600 perms)
└── vaults/
    └── <project-slug>.vault      # Encrypted JSON: {TAG → secret}
```

**Details**:
- **Project slug**: 16-character SHA-256 hash of project's absolute path
- **Encryption**: AES-128 via Python's `cryptography.Fernet`
- **Permissions**: `chmod 600` (owner read/write only)
- **Storage format**: Encrypted JSON
- **Backup**: Use `cloak vault-export` to create encrypted backups

**Example**:
```bash
# Project: /home/user/myproject
# Slug: 9f8e7d6c5b4a3210
# Vault: ~/.cloakmcp/vaults/9f8e7d6c5b4a3210.vault
# Key:   ~/.cloakmcp/keys/9f8e7d6c5b4a3210.key
```

#### 2. **Audit Logs**

**Location**: `./audit/audit.jsonl` (inside project directory)

**Format**: JSON Lines (one JSON object per line)

```json
{"ts": "2025-11-11T10:30:00+00:00", "rule_id": "aws_key", "action": "pseudonymize", "blocked": false, "start": 42, "end": 62, "value_hash": "sha256:abc123..."}
```

**Contents**:
- Timestamp of detection
- Rule that matched
- Action taken (redact/pseudonymize/block)
- Whether action was blocked
- Position in file (start/end)
- SHA-256 hash of original value (for traceability)

**Security**:
- Original secrets are **never** logged
- Only hashes are stored for audit trail

#### 3. **HMAC Keys** (for Pseudonymization)

**Location**: `./keys/mcp_hmac_key` (inside project directory)

**Purpose**: Generate deterministic pseudonyms via HMAC-SHA256

**Generation**:
```bash
mkdir -p keys
openssl rand -hex 32 > keys/mcp_hmac_key
chmod 600 keys/mcp_hmac_key
```

**Important**: Add `keys/` to `.gitignore` to prevent committing

#### 4. **Policy Files**

**Location**: `./examples/mcp_policy.yaml` (or custom path)

**Purpose**: Define detection rules and actions

**Storage**: Plain text YAML (no secrets)

---

## Server Modes

### 1. CLI Mode (Default)

**Usage**: Direct command execution, no network involved

```bash
cloak scan --policy examples/mcp_policy.yaml --input file.py
cloak sanitize --policy examples/mcp_policy.yaml --input file.py --output -
cloak pack --policy examples/mcp_policy.yaml --dir /path/to/project
cloak unpack --dir /path/to/project
```

**Data flow**:
```
File → Policy Engine → Action Engine → Output
          ↓                  ↓
      Scanner            Vault (if pack/unpack)
```

### 2. Server Mode (Optional)

**Usage**: FastAPI server for IDE/tool integration

#### Start Server

```bash
# Install server dependencies (if not already)
pip install -e .

# Generate API token (one-time)
mkdir -p keys
openssl rand -hex 32 > keys/mcp_api_token
chmod 600 keys/mcp_api_token

# Start server (localhost only - DEFAULT - RECOMMENDED)
uvicorn cloak.server:app --host 127.0.0.1 --port 8765

# ⚠️  SECURITY WARNING: LAN/network access
# Only use --host 0.0.0.0 on fully trusted networks with proper firewall rules
# Exposing this server publicly transmits secrets over the network and defeats
# the entire security model of CloakMCP. Use TLS, authentication, and VPN.
# YOU HAVE BEEN WARNED.
uvicorn cloak.server:app --host 0.0.0.0 --port 8765  # NOT RECOMMENDED
```

#### Server Features

- **Rate limiting**: 10 requests/minute per IP (requires `slowapi`)
- **Token authentication**: Bearer token from `keys/mcp_api_token`
- **Endpoints**: `/health`, `/sanitize`, `/scan`
- **API docs**: http://127.0.0.1:8765/docs (OpenAPI/Swagger)

---

## Configuration

### Environment Variables

| Variable        | Description                          | Default                      |
| --------------- | ------------------------------------ | ---------------------------- |
| `MCP_POLICY`    | Path to policy YAML file             | `examples/mcp_policy.yaml`   |
| `MCP_VAULT_DIR` | Override vault storage location      | `~/.cloakmcp`                |
| `MCP_AUDIT_DIR` | Override audit log location          | `./audit`                    |

### Server Configuration

**File**: `mcp/server.py` (modify if needed)

```python
# Default policy
DEFAULT_POLICY = os.getenv("MCP_POLICY", "examples/mcp_policy.yaml")

# Rate limiting (if slowapi installed)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10/minute"]  # Adjust as needed
)
```

### Systemd Service (Optional)

**File**: `~/.config/systemd/user/mcp-local.service`

```ini
[Unit]
Description=CloakMCP Local Server
After=network-online.target

[Service]
WorkingDirectory=/path/to/CloakMCP
ExecStart=/usr/bin/env uvicorn cloak.server:app --host 127.0.0.1 --port 8765
Restart=on-failure
Environment=MCP_POLICY=examples/mcp_policy.yaml

[Install]
WantedBy=default.target
```

**Enable**:
```bash
systemctl --user daemon-reload
systemctl --user enable --now cloak-local.service
systemctl --user status cloak-local.service
```

---

## Security Model

### Threat Model

**Assumptions**:
1. Local machine is trusted (filesystem, processes)
2. Vault encryption key remains local and secure
3. Network between IDE and localhost server is secure (loopback)
4. LLM provider is untrusted (may log all data sent to it)

**Protections**:
1. **Secrets never leave local machine** — Only tags are sent to LLM
2. **Vault is encrypted** — AES-128 Fernet with per-project keys
3. **Deterministic tags** — Same secret → same tag (enables stable diffs)
4. **Audit trail** — All operations logged with hashes (not plaintext)
5. **Rate limiting** — Protects server from brute-force attacks
6. **Token authentication** — Prevents unauthorized API access

### Attack Scenarios

#### ❌ Scenario 1: LLM Provider Logs All Data
**Mitigation**: Secrets are replaced with tags like `TAG-2f1a8e3c9b12`. LLM only sees tags, never original secrets.

#### ❌ Scenario 2: Man-in-the-Middle on API Requests
**Mitigation**: Server binds to `127.0.0.1` (localhost only). No network traffic leaves machine.

#### ❌ Scenario 3: Attacker Gets Access to `~/.cloakmcp/`
**Mitigation**: Vault is encrypted. Attacker needs both `.vault` file AND `.key` file to decrypt.

#### ❌ Scenario 4: Git Repository Leak
**Mitigation**: Vaults are stored in `~/.cloakmcp/`, NOT in project directory. `.gitignore` excludes `keys/` and `audit/`.

#### ✅ Safe Workflow
```
1. cloak pack --dir /project         # Secrets → tags, vault updated
2. git commit -am "Add feature"    # Only tags committed
3. Share code with LLM             # LLM sees tags, not secrets
4. cloak unpack --dir /project       # Tags → secrets restored locally
```

---

## API Reference

### Endpoints

#### 1. `GET /health`

**Description**: Health check endpoint

**Authentication**: Bearer token required

**Response**:
```json
{
  "status": "ok",
  "policy_path": "examples/mcp_policy.yaml",
  "policy_sha256": "abc123..."
}
```

#### 2. `POST /sanitize`

**Description**: Sanitize text (replace secrets with tags)

**Authentication**: Bearer token required

**Request**:
```json
{
  "text": "Email: alice@secret.com\nAPI Key: AKIAIOSFODNN7EXAMPLE",
  "policy_path": "examples/mcp_policy.yaml",
  "dry_run": false
}
```

**Response**:
```json
{
  "sanitized": "Email: <EMAIL:a1b2c3d4>\nAPI Key: <REDACTED:aws_key>",
  "blocked": false,
  "policy_sha256": "abc123..."
}
```

#### 3. `POST /scan`

**Description**: Scan text (detect secrets without modification)

**Authentication**: Bearer token required

**Request**:
```json
{
  "text": "Email: alice@secret.com",
  "policy_path": "examples/mcp_policy.yaml",
  "dry_run": true
}
```

**Response**: Same as `/sanitize` but `sanitized` field is unchanged

### Authentication

All endpoints require a Bearer token:

```bash
TOKEN=$(cat keys/mcp_api_token)
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"text":"test@example.com","dry_run":false}' \
     http://127.0.0.1:8765/sanitize
```

---

## Deployment

### Local Development

```bash
# 1. Install dependencies
pip install -e .

# 2. Generate keys
mkdir -p keys
openssl rand -hex 32 > keys/mcp_hmac_key
openssl rand -hex 32 > keys/mcp_api_token

# 3. Start server
uvicorn cloak.server:app --host 127.0.0.1 --port 8765 --reload
```

### Production (Local Network)

**🚨 CRITICAL SECURITY WARNING 🚨**:

**DO NOT expose CloakMCP server to the public internet or untrusted networks.**

When you use `--host 0.0.0.0`, you are transmitting secrets over the network, which **defeats the core security model** of CloakMCP (local-only secret storage).

Only proceed if:
- You have a fully trusted, firewalled local network
- You use TLS termination with valid certificates
- You have strong authentication (rotate tokens regularly)
- You understand the risks of network-based secret transmission

**RECOMMENDED**: Use `--host 127.0.0.1` (localhost only) and never expose beyond your machine.

```bash
# 1. Install with security dependencies
pip install -e . slowapi

# 2. Generate strong tokens
openssl rand -hex 64 > keys/mcp_api_token

# 3. Configure firewall (restrict to LAN subnet)
sudo ufw allow from 192.168.1.0/24 to any port 8765

# 4. Start with host binding
uvicorn cloak.server:app --host 0.0.0.0 --port 8765 --workers 2

# 5. Use systemd for persistence (see Configuration section)
```

### Docker (Optional)

**🚨 STRONGLY NOT RECOMMENDED 🚨**:

Docker containers inherently expose services over network interfaces. Using CloakMCP in Docker:
- Requires `--host 0.0.0.0` which transmits secrets over network
- Adds container orchestration as attack surface
- Defeats the "local-first" security model

**ONLY use Docker if**:
- You bind to localhost only (`-p 127.0.0.1:8765:8765`)
- Container runs on the same machine as the user
- You fully understand the security implications

If you must use Docker (for testing/development only):

```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY . .
RUN pip install -e .

# Mount volumes for persistent data
VOLUME ["/root/.cloakmcp", "/app/keys", "/app/audit"]

CMD ["uvicorn", "cloak.server:app", "--host", "0.0.0.0", "--port", "8765"]
```

```bash
docker run -it --rm \
  -v ~/.cloakmcp:/root/.cloakmcp \
  -v $(pwd)/keys:/app/keys \
  -v $(pwd)/audit:/app/audit \
  -p 127.0.0.1:8765:8765 \
  cloakmcp
```

---

## Monitoring

### Health Checks

```bash
# Check server status
curl -H "Authorization: Bearer $(cat keys/mcp_api_token)" \
     http://127.0.0.1:8765/health

# Check rate limiting
for i in {1..15}; do
  curl -H "Authorization: Bearer $(cat keys/mcp_api_token)" \
       http://127.0.0.1:8765/health
  echo "Request $i"
done
```

### Audit Log Analysis

```bash
# View recent operations
tail -f audit/audit.jsonl | jq .

# Count operations by rule
cat audit/audit.jsonl | jq -r .rule_id | sort | uniq -c

# Find blocked operations
cat audit/audit.jsonl | jq 'select(.blocked == true)'
```

### Vault Statistics

```bash
# Check vault contents (encrypted, safe to inspect)
cloak vault-stats --dir /path/to/project

# Output:
# Vault statistics for: /path/to/project
#   Project slug: 9f8e7d6c5b4a3210
#   Total secrets: 42
#   Unique tags: 42
#   Vault location: ~/.cloakmcp/vaults/9f8e7d6c5b4a3210.vault
```

---

## Troubleshooting

### Common Issues

#### 1. Server won't start

**Error**: `Address already in use`

**Solution**:
```bash
# Find process using port 8765
lsof -i :8765
kill <PID>

# Or use different port
uvicorn cloak.server:app --host 127.0.0.1 --port 8766
```

#### 2. Authentication fails

**Error**: `401 Unauthorized`

**Solution**:
```bash
# Regenerate token
openssl rand -hex 32 > keys/mcp_api_token

# Restart server
pkill -f "uvicorn cloak.server"
uvicorn cloak.server:app --host 127.0.0.1 --port 8765
```

#### 3. Rate limit errors

**Error**: `429 Too Many Requests`

**Solution**:
```bash
# Wait 60 seconds, or increase limit in mcp/server.py:
# default_limits=["20/minute"]  # Increase from 10
```

#### 4. Vault decryption fails

**Error**: `cryptography.fernet.InvalidToken`

**Solution**:
```bash
# Key file may be corrupted
# Restore from backup if available:
cp .backups/latest/keys/<slug>.key ~/.cloakmcp/keys/

# Or regenerate (WARNING: loses all vaulted secrets):
rm ~/.cloakmcp/vaults/<slug>.vault
rm ~/.cloakmcp/keys/<slug>.key
cloak pack --policy examples/mcp_policy.yaml --dir /project
```

#### 5. Missing slowapi (rate limiting)

**Warning**: `Rate limiting disabled: slowapi not installed`

**Solution**:
```bash
pip install slowapi
# Restart server to enable rate limiting
```

---

## Best Practices

### Security

1. **Never expose server to public internet** — Use localhost or trusted LAN only
2. **Rotate API tokens regularly** — Especially if server is LAN-accessible
3. **Backup vaults before major operations** — Use `cloak vault-export`
4. **Monitor audit logs** — Set up alerts for blocked operations
5. **Use strong HMAC keys** — Minimum 32 bytes (256 bits)

### Performance

1. **Enable HMAC key caching** — Already enabled in v0.2.5 (100-1000× speedup)
2. **Use pack/unpack for batch operations** — More efficient than per-file sanitize
3. **Tune rate limits** — Adjust based on your IDE's request patterns
4. **Keep policy files small** — Large regex lists slow down scanning

### Operational

1. **Version control policy files** — Track changes to detection rules
2. **Document custom rules** — Add comments in YAML policy
3. **Test policies before deployment** — Use `cloak scan --dry-run`
4. **Automate backups** — Schedule `cloak vault-export` via cron

---

## FAQ

### Q: Can I run the server on a remote machine?

**A**: Not recommended. CloakMCP is designed for local operation. Running remotely means secrets transit the network (defeating the purpose). If you must, use VPN + TLS.

### Q: Where are vault keys stored?

**A**: `~/.cloakmcp/keys/<project-slug>.key` on your local machine. Each project gets a unique encryption key.

### Q: Can I share vaults with teammates?

**A**: Yes, but securely:
1. Export vault: `cloak vault-export --dir /project --output backup.vault`
2. Transfer encrypted file via secure channel (already encrypted)
3. Import on teammate's machine: `cloak vault-import --dir /project --input backup.vault`

### Q: What happens if I lose the vault key?

**A**: Encrypted secrets are permanently unrecoverable. Always:
- Backup keys securely (e.g., password manager, encrypted USB)
- Keep original unmodified code as ultimate backup

### Q: Can LLMs reverse-engineer secrets from tags?

**A**: No. Tags are deterministic hashes (SHA-256) truncated to 12 hex chars. Without the original secret or HMAC key, reversal is computationally infeasible (2^48 brute-force space minimum).

### Q: Does the server log requests?

**A**: Only to audit logs (with hashes, not plaintext). Uvicorn access logs can be disabled:
```bash
uvicorn cloak.server:app --host 127.0.0.1 --port 8765 --log-level warning
```

---

## Related Documentation

- **[../README.md](../README.md)** — Quick start and overview
- **[VSCODE_MANUAL.md](VSCODE_MANUAL.md)** — IDE integration guide
- **[QUICKREF.md](QUICKREF.md)** — One-page command reference
- **[../SECURITY.md](../SECURITY.md)** — Security policy and disclosure

---

**Prepared by**: Olivier Vitrac — Adservio Innovation Lab
**Date**: 2025-11-11
**License**: MIT
**Project**: CloakMCP v0.3.1
