# CloakMCP Quickstart

**Version**: 0.6.0 | **Time to first pack: ~5 minutes**

CloakMCP replaces secrets in your code with opaque tags before anything leaves your machine. LLMs see `TAG-2f1a8e3c9b12` instead of your actual API keys, tokens, and credentials. You get them back with one command.

---

## 1. Install and Verify

```bash
git clone https://github.com/ovitrac/CloakMCP.git && cd CloakMCP
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Generate HMAC key (required for deterministic tags)
mkdir -p keys audit
openssl rand -hex 32 > keys/mcp_hmac_key
chmod 600 keys/*
```

**Verify it works:**

```bash
cloak scan --policy examples/mcp_policy.yaml --input examples/client_sanitize.py
```

You should see detection output listing found secrets (emails, tokens). If you see `cloak: command not found`, your venv is not activated.

---

## 2. Your First Pack / Unpack

The `demo/src/` directory contains a realistic Spring Boot banking service with 10+ fake secrets. Use it to test:

```bash
# See what secrets exist
cloak scan --policy examples/mcp_policy.yaml --input demo/src/application.properties

# Pack the demo directory (replaces secrets with tags)
cloak pack --policy examples/mcp_policy.yaml --dir demo/src --prefix TAG

# Inspect the result — secrets are now TAG-xxxxxxxxxxxx
cat demo/src/application.properties

# Restore originals
cloak unpack --dir demo/src

# Verify nothing was lost
cloak verify --dir demo/src
```

**What happened:**
- `pack` scanned every file, replaced secrets with deterministic tags
- The mapping `TAG-xxx -> real_secret` was stored in `~/.cloakmcp/vaults/`
- `unpack` read the vault and restored every secret in place
- `verify` confirmed no residual tags remain

---

## 3. Where Does CloakMCP Work?

| Platform | Integration | Workflow |
|----------|------------|----------|
| **Claude Code (terminal)** | Hooks: auto pack/unpack per session | Install hooks, then just run `claude` |
| **Claude Code in VS Code** | Same hooks via Claude Code extension | Same as terminal — extension uses CLI |
| **VS Code (no Claude)** | Keybindings + tasks | `Ctrl+Alt+S` to sanitize, manual pack/unpack |
| **Claude Web (claude.ai)** | None (browser only) | Pack locally, copy/paste packed code, unpack after |
| **ChatGPT / Gemini / Copilot** | None | Pack locally, share packed repo or text, unpack after |
| **CI/CD pipelines** | Pre-commit hook | `cloak scan` to block commits with raw secrets |

### Key rule

CloakMCP works with **any** LLM. The only difference is automation:
- **Claude Code**: fully automatic (hooks handle everything)
- **Everything else**: you run `cloak pack` before and `cloak unpack` after

---

## 4. Claude Code Setup

### Install hooks

```bash
cd /path/to/your-project   # must have CloakMCP installed
scripts/install_claude.sh
```

This installs the `secrets-only` profile (default). For the hardened profile which also blocks dangerous shell commands:

```bash
scripts/install_claude.sh --profile hardened
```

Preview what the installer will do without changing anything:

```bash
scripts/install_claude.sh --dry-run
```

### What the installer creates

```
your-project/
└── .claude/
    ├── hooks/                      # 6 shell scripts
    │   ├── cloak-session-start.sh  # Packs on session start
    │   ├── cloak-session-end.sh    # Unpacks on session end
    │   ├── cloak-prompt-guard.sh   # Warns if you paste secrets in prompts
    │   ├── cloak-guard-write.sh    # Blocks writes containing secrets
    │   ├── cloak-safety-guard.sh   # Blocks dangerous commands (hardened only)
    │   └── cloak-audit-logger.sh   # Logs tool usage
    └── settings.local.json         # Hook configuration
```

### Session lifecycle

When you run `claude` in a CloakMCP-enabled project:

1. **SessionStart** fires: `cloak pack` replaces all secrets with tags, writes session manifest
2. **During session**: Claude sees only tagged code. Write/Edit guard blocks secret injection
3. **Prompt guard**: if you paste a raw secret in a prompt, you get a warning
4. **SessionEnd** fires: `cloak unpack` restores secrets, verifies integrity

### Verify hooks are active

```bash
# Check hook files exist
ls .claude/hooks/

# Check settings are configured
cat .claude/settings.local.json | python3 -m json.tool

# Check session state after starting Claude Code
ls -la .cloak-session-state          # exists = session is packed

# Check audit log
cat .cloak-session-audit.jsonl | python3 -m json.tool
```

### Uninstall hooks

```bash
scripts/install_claude.sh --uninstall
```

---

## 5. MCP Server (Tool Integration)

CloakMCP also exposes 6 tools via the MCP protocol (JSON-RPC 2.0 over stdio). This lets Claude Code call CloakMCP functions directly as tools.

The `.mcp.json` file at project root configures this automatically:

```json
{
  "mcpServers": {
    "cloakmcp": {
      "type": "stdio",
      "command": "cloak-mcp-server",
      "env": { "CLOAK_POLICY": "examples/mcp_policy.yaml" }
    }
  }
}
```

**Available MCP tools**: `cloak_scan_text`, `cloak_sanitize_text`, `cloak_pack_dir`, `cloak_unpack_dir`, `cloak_policy_show`, `cloak_vault_stats`

No configuration needed — Claude Code discovers `.mcp.json` automatically.

---

## 6. Environment Variables

| Variable | Default | Effect |
|----------|---------|--------|
| `CLOAK_POLICY` | `examples/mcp_policy.yaml` | Policy file used by hooks and MCP server |
| `CLOAK_PREFIX` | `TAG` | Prefix for generated tags (`TAG-xxxxxxxxxxxx`) |
| `CLOAK_STRICT` | *(off)* | Set to `1`: medium-severity matches become blocking |
| `CLOAK_PROMPT_GUARD` | *(on)* | Set to `off` to disable prompt secret detection |
| `CLOAK_REPACK_ON_WRITE` | *(off)* | Set to `1`: auto-repack after each Write/Edit |
| `CLOAK_AUDIT_TOOLS` | *(off)* | Set to `1`: log all tool invocations to audit |

---

## 7. Policy Profiles

CloakMCP ships with two policy profiles:

| Profile | File | Rules | Coverage |
|---------|------|-------|----------|
| **Default** | `examples/mcp_policy.yaml` | 10 | AWS, GCP, SSH, PEM, JWT, email, IP, URL, entropy |
| **Enterprise** | `examples/mcp_policy_enterprise.yaml` | 26 | Default + GitHub PAT, GitLab, Slack, Stripe, npm, Heroku, Twilio, SendGrid, Azure, PKCS#8, generic password/secret |

Switch profiles:

```bash
# CLI
cloak pack --policy examples/mcp_policy_enterprise.yaml --dir .

# Hooks (set in environment or .claude/hooks/cloak-session-start.sh)
export CLOAK_POLICY=examples/mcp_policy_enterprise.yaml
```

---

## 8. FAQ

### How do I check that CloakMCP is active during a Claude Code session?

Look for the `.cloak-session-state` file in your project root. It exists only while a session is packed. You can also check:
```bash
ls .cloak-session-state         # exists = active
cat .cloak-session-manifest.json | python3 -m json.tool   # file hashes at pack time
tail -5 .cloak-session-audit.jsonl                         # recent audit events
```

### Does it work in VS Code?

**Yes, two ways:**

1. **With Claude Code extension**: same hooks fire automatically, identical to terminal
2. **Without Claude Code**: use VS Code tasks and keybindings (`Ctrl+Alt+S` to sanitize, `Ctrl+Alt+A` to scan). Manual pack/unpack via terminal. See [VSCODE_MANUAL.md](VSCODE_MANUAL.md).

### Does it work with Claude Web (claude.ai)?

**Manually only.** Claude Web has no hook or MCP support:
1. `cloak pack --dir .` in your terminal
2. Copy/paste packed code into Claude Web
3. Copy Claude's output back to your files
4. `cloak unpack --dir .` to restore secrets

The tags (`TAG-xxxxxxxxxxxx`) are safe to paste — they are meaningless without your vault.

### Can I use the MCP server from a different computer?

**The MCP stdio server**: no. It communicates over stdin/stdout with the local Claude Code process. No network involved.

**The REST API server** (`uvicorn cloakmcp.server:app`): by default it binds to `127.0.0.1` (localhost only). You *can* start it with `--host 0.0.0.0` to expose on your LAN, but:

- The **vault stays local** — the remote machine can scan/sanitize text but cannot unpack (it has no vault access)
- You must share the API token securely
- Restrict access with firewall rules
- This is explicitly **not recommended** for production use

This is by design: secrets should never leave the machine that owns the vault.

### Can I use the same vault on multiple machines?

Yes. Copy both files from `~/.cloakmcp/`:
```
~/.cloakmcp/keys/<slug>.key
~/.cloakmcp/vaults/<slug>.vault
```
to the same paths on the other machine. The slug is derived from the project's absolute path, so the path must match or you need to adjust.

Use `cloak vault-export` and `cloak vault-import` for secure transfer.

### What does CloakMCP NOT protect against?

CloakMCP prevents **exfiltration** of raw secret values. It does **not** prevent:
- **Inference**: an LLM can guess what a tagged value represents from context (e.g., `password = TAG-xxx` is obviously a password)
- **Structural leakage**: file names, directory structure, and code logic remain visible
- **User error**: pasting raw secrets in prompts (prompt guard warns but does not block by default)

See [../SECURITY.md](../SECURITY.md) for the full threat model.

### My session crashed — how do I recover?

```bash
cloak recover --dir .
```

This detects stale `.cloak-session-state` files and runs unpack to restore secrets.

---

## 9. Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `cloak: command not found` | Venv not activated | `source .venv/bin/activate` |
| No secrets detected | Wrong policy or file excluded | Check policy path, check `.mcpignore` |
| Hooks not firing | Not installed or wrong directory | Run `scripts/install_claude.sh`, verify `.claude/settings.local.json` |
| `InvalidToken` on unpack | Wrong vault key | Check `~/.cloakmcp/keys/` — slug matches project path |
| Tags remain after unpack | Incomplete unpack | Run `cloak verify --dir .` to find residual tags |
| Session stuck (packed) | Crash without SessionEnd | `cloak recover --dir .` |
| Double-tagging | Pack ran twice | Safe since v0.6.0 — idempotency guard prevents re-packing |
| Prompt guard too noisy | False positives | `export CLOAK_PROMPT_GUARD=off` or tune policy |

---

## 10. Next Steps

| Want to... | Read |
|-----------|------|
| See all CLI commands at a glance | [QUICKREF.md](QUICKREF.md) |
| Set up VS Code integration | [VSCODE_MANUAL.md](VSCODE_MANUAL.md) |
| Run the REST API server | [SERVER.md](SERVER.md) |
| Configure group policies | [GROUP_POLICY_IMPLEMENTATION.md](GROUP_POLICY_IMPLEMENTATION.md) |
| Understand the security model | [../SECURITY.md](../SECURITY.md) |
| Try the live demo | [../demo/README.md](../demo/README.md) |
| Write custom detection rules | [QUICKREF.md](QUICKREF.md) (Policy YAML section) |

---

*CloakMCP v0.6.0 — Olivier Vitrac, Adservio Innovation Lab*
