# CloakMCP Quick Reference Card

**Version**: 0.3.0 | **One-page cheat sheet for daily use**

---

## 🚀 Quick Setup (First Time)

```bash
# 1. Install
pip install -e .

# 2. Generate keys
mkdir -p keys && openssl rand -hex 32 > keys/mcp_hmac_key

# 3. Test
mcp scan --policy examples/mcp_policy.yaml --input README.md
```

---

## ⌨️ VS Code Shortcuts

| Shortcut       | Action                            |
| -------------- | --------------------------------- |
| `Ctrl+Alt+S`   | Sanitize current file (preview)   |
| `Ctrl+Alt+A`   | Scan current file (audit only)    |

---

## 🔧 CLI Commands

### Scan (no modification)
```bash
mcp scan --policy examples/mcp_policy.yaml --input file.py
```

### Sanitize (preview to stdout)
```bash
mcp sanitize --policy examples/mcp_policy.yaml --input file.py --output -
```

### Sanitize (overwrite file)
```bash
mcp sanitize --policy examples/mcp_policy.yaml --input file.py --output file.py
```

### Pack directory (anonymize all files)
```bash
mcp pack --policy examples/mcp_policy.yaml --dir /path/to/project --prefix TAG
```

### Unpack directory (restore secrets)
```bash
mcp unpack --dir /path/to/project
```

---

## 🔐 Vault Locations

- **Keys**: `~/.cloakmcp/keys/<project-slug>.key`
- **Vaults**: `~/.cloakmcp/vaults/<project-slug>.vault`
- **Audit**: `./audit/audit.jsonl`

**Slug**: First 16 chars of SHA-256(absolute project path)

---

## 🌐 API Server (Optional)

### Start server
```bash
openssl rand -hex 32 > keys/mcp_api_token  # Once
uvicorn mcp.server:app --host 127.0.0.1 --port 8765
```

### Health check
```bash
curl -H "Authorization: Bearer $(cat keys/mcp_api_token)" \
  http://127.0.0.1:8765/health
```

### Sanitize via API
```bash
curl -H "Authorization: Bearer $(cat keys/mcp_api_token)" \
  -H "Content-Type: application/json" \
  -d '{"text":"Email: test@example.com","dry_run":false}' \
  http://127.0.0.1:8765/sanitize
```

---

## 📝 Policy YAML Quick Reference

```yaml
version: 1
globals:
  default_action: redact
  audit:
    enabled: true
    path: ./audit/audit.jsonl

detection:
  - id: my_rule
    type: regex           # or: ipv4, ipv6, url, entropy
    pattern: 'regex_here'
    action: redact        # or: block, pseudonymize, hash, allow, replace_with_template
    template: '<TAG:{hash8}>'  # for replace_with_template
    whitelist: ['allowed@domain.com']
    whitelist_cidrs: ['10.0.0.0/8']
```

### Action Types

| Action                     | Effect                                    |
| -------------------------- | ----------------------------------------- |
| `redact`                   | Replace with `<REDACTED:rule_id>`         |
| `block`                    | Refuse to process (exit with error)       |
| `pseudonymize`             | Replace with HMAC-based token (`PZ-xxx`)  |
| `hash`                     | Replace with SHA-256 hash (`HASH-xxx`)    |
| `allow`                    | Keep unchanged                            |
| `replace_with_template`    | Use custom template with placeholders     |

### Rule Types

| Type      | Detects                         |
| --------- | ------------------------------- |
| `regex`   | Custom regex pattern            |
| `ipv4`    | IPv4 addresses                  |
| `ipv6`    | IPv6 addresses                  |
| `url`     | HTTP/HTTPS URLs                 |
| `entropy` | High-entropy strings (base64)   |

---

## 🛡️ Common Workflows

### Workflow 1: Before sharing code with LLM
```bash
mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG
# Share project with Claude/Codex/etc.
# After receiving modified code:
mcp unpack --dir .
```

### Workflow 2: Pre-commit check
```bash
for f in $(git diff --cached --name-only); do
  mcp scan --policy examples/mcp_policy.yaml --input "$f" || exit 1
done
```

### Workflow 3: Sanitize before commit
```bash
mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG
git add .
git commit -m "feat: new feature [MCP-SANITIZED]"
mcp unpack --dir .  # Restore for local work
```

---

## 🔍 Troubleshooting

| Problem                       | Solution                                          |
| ----------------------------- | ------------------------------------------------- |
| `mcp: command not found`      | Activate venv: `source .venv/bin/activate`        |
| `Missing API token`           | Create: `openssl rand -hex 32 > keys/mcp_api_token` |
| `Policy file not found`       | Use absolute path or check cwd                    |
| Secrets not detected          | Add custom rule to policy YAML                    |
| `InvalidToken` (vault error)  | Key mismatch; check `~/.cloakmcp/keys/`           |

---

## 📦 .mcpignore Example

```
# .mcpignore — similar to .gitignore

# Binaries
*.pyc
*.so

# Build artifacts
dist/
build/
__pycache__/

# Virtual environments
.venv/
venv/
node_modules/

# Media
*.png
*.jpg
*.pdf

# Already sensitive
audit/
keys/
.vscode/
```

---

## 📊 Audit Log Format

`audit/audit.jsonl` (one JSON per line):

```json
{
  "ts": "2025-11-11T16:30:00+01:00",
  "rule_id": "email",
  "action": "replace_with_template",
  "blocked": false,
  "start": 45,
  "end": 65,
  "value_hash": "a3b2c1d4e5f6..."
}
```

View recent events:
```bash
tail -20 audit/audit.jsonl | jq
```

---

## 🧪 Testing

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=mcp --cov-report=html

# View coverage
xdg-open htmlcov/index.html
```

---

## 📚 Documentation

- **Full manual**: `VSCODE_MANUAL.md`
- **Issues report**: `ISSUES_REPORT.md`
- **Deployment summary**: `DEPLOYMENT_SUMMARY.md`
- **Test docs**: `tests/README.md`
- **Project specs**: `CLAUDE.md`

---

## 🔗 Resources

- **API docs** (when server running): http://127.0.0.1:8765/docs
- **License**: MIT (see `LICENSE`)
- **Author**: Olivier Vitrac — Adservio Innovation Lab
- **Version**: 0.3.0 (alpha)

---

**💡 Remember**: Always `pack` before sharing, never commit `keys/`
