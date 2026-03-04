# CloakMCP Quick Reference

**Version**: 0.13.0 | **Cheat sheet for daily use**

---

## Setup (first time only)

```bash
pip install -e .
cloak doctor              # verify installation health
```

> Vault keys are auto-generated on first use — no manual key setup required.

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

# Set per-project policy (persists in .cloak/policy.yaml)
cloak policy use examples/mcp_policy.yaml
cloak policy use --show          # display active policy
cloak policy use --clear         # remove per-project policy
cloak policy use POL --link      # symlink instead of copy (Unix only)
cloak policy use POL --force     # allow policy downgrade

# Reload policy mid-session (re-resolve + update pinned hash)
cloak policy reload --dir .
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

### Key management

```bash
# Wrap key with passphrase (Tier 0 → Tier 1, requires CLOAK_PASSPHRASE)
cloak key wrap --dir .

# Unwrap key back to raw format (Tier 1 → Tier 0)
cloak key unwrap --dir .
```

### Backup management

```bash
# Encrypt legacy plaintext backups → .enc files
cloak backup migrate --dir .                  # dry-run (default)
cloak backup migrate --dir . --apply          # execute migration
cloak backup migrate --dir . --quarantine     # move originals instead of deleting

# Prune old backups
cloak backup prune --dir . --ttl 30d --keep-last 10       # dry-run (default)
cloak backup prune --dir . --ttl 30d --keep-last 10 --apply
cloak backup prune --dir . --include-legacy                # include plaintext dirs
```

### Session management

```bash
# Session diagnostics (state, manifest, delta, vault, tags, backups, audit)
cloak status --dir .
cloak status --dir . --json                   # machine-readable output

# Restore secrets from vault (default) or backup
cloak restore --dir .
cloak restore --dir . --from-backup --force   # restore from backup

# Recover from crashed session (stale .cloak-session-state)
cloak recover --dir .
```

### Installation and diagnostics

```bash
# Cross-platform hook installer
cloak install                          # default: secrets-only, cli method
cloak install --profile hardened       # + Bash safety guard + read guard
cloak install --method copy            # copy .sh scripts (Unix only)
cloak install --dry-run                # preview only
cloak install --uninstall              # remove hooks

# Installation health check
cloak doctor                           # platform, hook method, policy, vault state

# Toolbox discovery contract
cloak hooks-path --format py           # print path to bundled .py hooks
cloak hooks-path --format sh           # print path to bundled .sh hooks
cloak hooks-path --format cli          # returns "cloak hook"
```

### Pipes and guards

```bash
# Sanitize from stdin (for pipes)
echo "secret: MY_AWS_KEY_HERE" | cloak sanitize-stdin --policy examples/mcp_policy.yaml

# Guard: exit 1 if stdin contains secrets (for pre-commit)
echo "some text" | cloak guard --policy examples/mcp_policy.yaml
```

### MCP server

```bash
# FastMCP server (stdio, default)
cloak serve

# FastMCP server (SSE transport)
cloak serve --transport sse --port 8766

# Validate configuration and exit
cloak serve --check
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
# Cross-platform (recommended)
cloak install                          # default: secrets-only
cloak install --profile hardened       # + Bash safety guard
cloak install --dry-run                # preview only
cloak install --uninstall              # remove hooks

# Diagnostics
cloak doctor                           # check installation health
cloak hooks-path --format py           # print path to bundled .py hooks
```

### Hook lifecycle

| Event | When | What it does |
|-------|------|-------------|
| SessionStart | `claude` starts | `cloak pack`, writes session state + manifest |
| SessionEnd | `claude` exits | `cloak unpack`, verifies integrity, computes delta |
| UserPromptSubmit | Every prompt | Warns if prompt contains raw secrets |
| PreToolUse (Write/Edit) | Before file writes | Blocks writes containing secrets |
| PreToolUse (Read/Grep/Glob) | Before file reads | Blocks access to sensitive paths (hardened only) |
| PreToolUse (Bash) | Before shell commands | Blocks dangerous commands (hardened only) |
| PostToolUse | After tool runs | Audit log + optional repack |

### Verify hooks are active

```bash
cloak doctor                           # comprehensive check
cat .claude/settings.local.json        # hooks configured?
ls .cloak-session-state                # exists = session is packed
tail -5 .cloak-session-audit.jsonl     # recent audit events
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
| `CLOAK_FAIL_CLOSED` | off | `1` = deny writes and refuse sessions when no policy found |
| `CLOAK_PASSPHRASE` | *(unset)* | Passphrase for Tier 1 key wrapping (scrypt) |

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
├── vaults/
│   └── <slug>.vault        # Encrypted JSON: {TAG -> secret}
└── backups/
    └── <slug>/
        └── <timestamp>.enc # Encrypted backup (Fernet + HKDF-derived key)
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
cloak install   # once (cross-platform)
claude          # hooks handle pack/unpack automatically
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
| Hooks not firing | Run `cloak install`, check `.claude/settings.local.json` |
| `InvalidToken` on unpack | Vault key mismatch — check `~/.cloakmcp/keys/` |
| Tags remain after unpack | `cloak verify --dir .` to find them |
| Session stuck (packed) | `cloak recover --dir .` |
| Double-tagging | Safe since v0.6.0 (idempotency guard) |
| Windows symlink errors | Use `--method cli` (default) or `--method copy` |

---

## Testing

```bash
pip install -e ".[test]"     # install test dependencies
pytest -v                     # run all tests (394+)
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

*CloakMCP v0.13.0 — Olivier Vitrac, Adservio Innovation Lab*
