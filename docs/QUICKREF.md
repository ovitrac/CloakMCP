# CloakMCP Quick Reference

**Version**: 0.6.0 | **Cheat sheet for daily use**

---

## Setup (first time only)

```bash
pip install -e .
mkdir -p keys audit && openssl rand -hex 32 > keys/mcp_hmac_key && chmod 600 keys/*
```

---

## CLI Commands

### Core workflow

```bash
# Scan (detect, no changes)
cloak scan --policy examples/mcp_policy.yaml --input file.py

# Pack directory (replace secrets with tags)
cloak pack --policy examples/mcp_policy.yaml --dir . --prefix TAG

# Unpack directory (restore secrets from vault)
cloak unpack --dir .

# Verify (check no residual tags after unpack)
cloak verify --dir .
```

### Single-file operations

```bash
# Sanitize to stdout
cloak sanitize --policy examples/mcp_policy.yaml --input file.py --output -

# Sanitize in place
cloak sanitize --policy examples/mcp_policy.yaml --input file.py --output file.py

# Pack single file
cloak pack-file --policy examples/mcp_policy.yaml --file config.yaml --prefix TAG

# Unpack single file
cloak unpack-file --file config.yaml
```

### Incremental repack

```bash
# Re-scan and pack only new/changed files (no full re-pack needed)
cloak repack --policy examples/mcp_policy.yaml --dir .
```

### Policy management

```bash
# Validate policy (checks inheritance chain)
cloak policy validate --policy examples/mcp_policy.yaml

# Show merged policy after inheritance resolution
cloak policy show --policy examples/mcp_policy.yaml --format yaml
cloak policy show --policy examples/mcp_policy.yaml --format json
```

### Vault management

```bash
# Show vault stats (entry count, project slug)
cloak vault-stats --dir .

# Export vault to encrypted backup
cloak vault-export --dir . --output vault-backup.enc

# Import vault from backup
cloak vault-import --backup vault-backup.enc --dir .
```

### Session recovery

```bash
# Recover from crashed session (stale .cloak-session-state)
cloak recover --dir .
```

### Pipes and guards

```bash
# Sanitize from stdin (for pipes)
echo "secret: AKIAABCDEFGHIJKLMNOP" | cloak sanitize-stdin --policy examples/mcp_policy.yaml

# Guard: exit 1 if stdin contains secrets (for pre-commit)
echo "some text" | cloak guard --policy examples/mcp_policy.yaml
```

---

## VS Code Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Alt+S` | Sanitize current file (preview in terminal) |
| `Ctrl+Alt+A` | Scan current file (audit only) |

---

## Claude Code Hooks

### Install

```bash
scripts/install_claude.sh                    # default: secrets-only profile
scripts/install_claude.sh --profile hardened  # + Bash safety guard
scripts/install_claude.sh --dry-run           # preview only
scripts/install_claude.sh --uninstall         # remove hooks
```

### Hook lifecycle

| Event | When | What it does |
|-------|------|-------------|
| SessionStart | `claude` starts | `cloak pack`, writes session state + manifest |
| SessionEnd | `claude` exits | `cloak unpack`, verifies integrity, computes delta |
| UserPromptSubmit | Every prompt | Warns if prompt contains raw secrets |
| PreToolUse (Write/Edit) | Before file writes | Blocks writes containing secrets |
| PreToolUse (Bash) | Before shell commands | Blocks dangerous commands (hardened only) |
| PostToolUse | After tool runs | Audit log + optional repack |

### Verify hooks are active

```bash
ls .claude/hooks/                    # 5-6 scripts present?
cat .claude/settings.local.json      # hooks configured?
ls .cloak-session-state              # exists = session is packed
tail -5 .cloak-session-audit.jsonl   # recent audit events
```

---

## Environment Variables

| Variable | Default | Effect |
|----------|---------|--------|
| `CLOAK_POLICY` | `examples/mcp_policy.yaml` | Policy file for hooks/MCP |
| `CLOAK_PREFIX` | `TAG` | Tag prefix |
| `CLOAK_STRICT` | off | `1` = medium severity becomes blocking |
| `CLOAK_PROMPT_GUARD` | on | `off` = disable prompt guard |
| `CLOAK_REPACK_ON_WRITE` | off | `1` = auto-repack after Write/Edit |
| `CLOAK_AUDIT_TOOLS` | off | `1` = log all tool usage |

---

## Policy Profiles

| Profile | File | Rules |
|---------|------|-------|
| Default | `examples/mcp_policy.yaml` | 10 (AWS, GCP, SSH, PEM, JWT, email, IP, URL, entropy) |
| Enterprise | `examples/mcp_policy_enterprise.yaml` | 26 (+ GitHub, GitLab, Slack, Stripe, npm, Azure, ...) |

### Policy YAML structure

```yaml
version: 1

inherits:                          # Optional: inherit from parent policies
  - ~/.cloakmcp/policies/company-baseline.yaml
  - team-policy.yaml               # relative paths supported

globals:
  default_action: redact
  audit:
    enabled: true
    path: ./audit/audit.jsonl

detection:
  - id: my_rule
    type: regex                    # regex | ipv4 | ipv6 | url | entropy
    pattern: 'PATTERN'
    action: redact                 # redact | block | pseudonymize | hash | allow | replace_with_template
    severity: high                 # critical | high | medium | low
    template: '<TAG:{hash8}>'      # for replace_with_template action
    whitelist: ['safe@example.com']
    whitelist_cidrs: ['10.0.0.0/8']
    whitelist_patterns: ['pattern'] # entropy rules only
```

### Actions

| Action | Effect | Reversible? |
|--------|--------|-------------|
| `redact` | Replace with `<REDACTED:rule_id>` | No |
| `block` | Refuse to process (exit 1) | N/A |
| `pseudonymize` | HMAC-based token (`PZ-xxx`) | With key |
| `hash` | SHA-256 hash (`HASH-xxx`) | No |
| `allow` | Keep unchanged | N/A |
| `replace_with_template` | Custom template | Depends |

### Severity levels (hook enforcement)

| Severity | Default | With `CLOAK_STRICT=1` |
|----------|---------|----------------------|
| `critical` | Deny (block) | Deny |
| `high` | Deny (block) | Deny |
| `medium` | Warn | Deny |
| `low` | Warn | Warn |

### Inheritance rules

- Later policies override earlier ones (for rules with same `id`)
- `globals`: deep merge
- `whitelist` / `blacklist`: concatenated
- `detection`: same-ID replacement
- Policies share **rules**, not encryption keys

---

## Vault

```
~/.cloakmcp/
├── keys/
│   └── <slug>.key          # Fernet encryption key (chmod 600)
└── vaults/
    └── <slug>.vault        # Encrypted JSON: {TAG -> secret}
```

**Slug**: first 16 chars of `SHA-256(absolute_project_path)`

**Portability**: copy both `.key` and `.vault` to restore on another machine (same absolute path or adjust slug).

---

## .mcpignore

Controls which files are skipped during pack/unpack (same syntax as `.gitignore`):

```
*.pyc
*.so
__pycache__/
.venv/
venv/
node_modules/
dist/
build/
*.png
*.jpg
*.pdf
audit/
keys/
.vscode/
```

---

## MCP Server (tool integration)

Configured via `.mcp.json` at project root — Claude Code discovers it automatically.

6 tools available: `cloak_scan_text`, `cloak_sanitize_text`, `cloak_pack_dir`, `cloak_unpack_dir`, `cloak_policy_show`, `cloak_vault_stats`

---

## REST API Server (optional)

```bash
# Generate API token (once)
openssl rand -hex 32 > keys/mcp_api_token

# Start server (localhost only)
uvicorn cloakmcp.server:app --host 127.0.0.1 --port 8765
```

```bash
TOKEN=$(cat keys/mcp_api_token)

# Health check
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/health

# Sanitize text
curl -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"Email: test@example.com","dry_run":false}' \
  http://127.0.0.1:8765/sanitize
```

API docs (when running): http://127.0.0.1:8765/docs

---

## Audit Log

Location: `audit/audit.jsonl` (CLI) or `.cloak-session-audit.jsonl` (hooks)

```bash
# View recent events
tail -20 audit/audit.jsonl | python3 -m json.tool

# View hook audit
tail -10 .cloak-session-audit.jsonl | python3 -m json.tool
```

---

## Common Workflows

### Before sharing code with any LLM

```bash
cloak pack --policy examples/mcp_policy.yaml --dir . --prefix TAG
# Share packed code (copy/paste, upload, git push packed branch)
# After receiving LLM output:
cloak unpack --dir .
cloak verify --dir .
```

### Claude Code (automatic)

```bash
scripts/install_claude.sh    # once
claude                       # hooks handle pack/unpack automatically
```

### Pre-commit secret scan

```bash
for f in $(git diff --cached --name-only); do
  cloak scan --policy examples/mcp_policy.yaml --input "$f" || exit 1
done
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `cloak: command not found` | `source .venv/bin/activate` |
| No secrets detected | Check policy path and `.mcpignore` |
| Hooks not firing | Run `scripts/install_claude.sh`, check `.claude/settings.local.json` |
| `InvalidToken` on unpack | Vault key mismatch — check `~/.cloakmcp/keys/` |
| Tags remain after unpack | `cloak verify --dir .` to find them |
| Session stuck (packed) | `cloak recover --dir .` |
| Double-tagging | Safe since v0.6.0 (idempotency guard) |

---

## Testing

```bash
pip install -e ".[test]"     # install test dependencies
pytest -v                     # run all tests (214+)
pytest --cov=cloakmcp         # with coverage
```

---

## Links

- [QUICKSTART.md](QUICKSTART.md) — first-time setup guide with FAQ
- [VSCODE_MANUAL.md](VSCODE_MANUAL.md) — VS Code integration
- [SERVER.md](SERVER.md) — REST API server details
- [GROUP_POLICY_IMPLEMENTATION.md](GROUP_POLICY_IMPLEMENTATION.md) — policy inheritance
- [THREAT_MODEL.md](THREAT_MODEL.md) — security analysis
- [../SECURITY.md](../SECURITY.md) — security policy and disclosure
- [../demo/README.md](../demo/README.md) — live demo scripts

---

*CloakMCP v0.6.0 — Olivier Vitrac, Adservio Innovation Lab*
