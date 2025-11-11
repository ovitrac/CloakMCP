# CloakMCP — Complete VS Code Integration Manual

**Version**: 0.2.0
**Author**: Olivier Vitrac — Adservio Innovation Lab
**Date**: November 2025

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation & Setup](#installation--setup)
4. [VS Code Integration Overview](#vs-code-integration-overview)
5. [Quick Start Guide](#quick-start-guide)
6. [Feature Reference](#feature-reference)
7. [Keyboard Shortcuts](#keyboard-shortcuts)
8. [Tasks Reference](#tasks-reference)
9. [API Server Mode](#api-server-mode)
10. [Workflow Examples](#workflow-examples)
11. [Troubleshooting](#troubleshooting)
12. [Advanced Configuration](#advanced-configuration)

---

## Introduction

This manual provides complete instructions for using CloakMCP within Visual Studio Code. CloakMCP protects your secrets, credentials, and PII before code is shared with LLMs (Large Language Models) like Claude, Codex, or Copilot.

**Key capabilities in VS Code**:
- 🔒 One-keystroke sanitization of current file (`Ctrl+Alt+S`)
- 🔍 Silent audit scanning (`Ctrl+Alt+A`)
- 📦 Batch processing with `pack`/`unpack` commands
- 🌐 Optional local API for real-time sanitization
- ✅ Integrated with VS Code tasks and terminal

---

## Prerequisites

### Required

- **VS Code**: Version 1.70 or later
- **Python**: 3.10 or later
- **CloakMCP**: Installed in the project (`pip install -e .`)
- **Terminal**: Bash or compatible shell (Linux/macOS/WSL)

### Recommended Extensions

- **Python** (ms-python.python) — for Python development
- **REST Client** (humao.rest-client) — for testing API endpoints
- **GitLens** (eamonn.gitlens) — for reviewing sanitized commits
- **Better Comments** (aaron-bond.better-comments) — for marking sensitive sections

---

## Installation & Setup

### Step 1: Install CloakMCP

```bash
cd /path/to/CloakMCP
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

Verify installation:

```bash
mcp --help
```

Expected output:

```
usage: mcp [-h] {scan,sanitize,pack,unpack} ...

Micro-Cleanse Preprocessor (local secret-removal)
...
```

### Step 2: Generate Encryption Keys

CloakMCP requires two keys:

1. **HMAC key** (for pseudonymization)
2. **API token** (optional, for server mode)

```bash
# Create keys directory
mkdir -p keys

# Generate HMAC key (32 bytes hex = 64 chars)
openssl rand -hex 32 > keys/mcp_hmac_key

# Generate API token (optional, for server mode)
openssl rand -hex 32 > keys/mcp_api_token

# Secure permissions
chmod 600 keys/*
```

**Important**: Add `keys/` to `.gitignore` to prevent accidental commits.

### Step 3: Configure Policy

Edit `examples/mcp_policy.yaml` to customize detection rules:

```yaml
version: 1
globals:
  default_action: redact
  audit:
    enabled: true
    path: ./audit/audit.jsonl
  pseudonymization:
    secret_key_file: ./keys/mcp_hmac_key

detection:
  - id: email
    type: regex
    pattern: '(?i)[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9.-]+'
    action: replace_with_template
    template: '<EMAIL:{hash8}>'

  - id: aws_key
    type: regex
    pattern: '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    action: block  # Refuse to process if detected

  # Add more rules as needed...
```

See `examples/mcp_policy.yaml` for full reference.

### Step 4: Verify VS Code Configuration

CloakMCP includes pre-configured VS Code integration. Verify files exist:

```bash
ls -la .vscode/
```

Expected files:

```
.vscode/
├── keybindings.json    # Keyboard shortcuts
├── settings.json       # Project settings
└── tasks.json          # Task definitions
```

If missing, see [Advanced Configuration](#advanced-configuration) to create them.

---

## VS Code Integration Overview

CloakMCP integrates with VS Code through:

1. **Tasks** (`.vscode/tasks.json`) — shell commands for sanitize/scan/pack/unpack
2. **Keybindings** (`.vscode/keybindings.json`) — keyboard shortcuts for common tasks
3. **Settings** (`.vscode/settings.json`) — project-specific configuration
4. **Terminal** — direct CLI access for batch operations

### Architecture

```
┌─────────────────────────────────────────────┐
│  VS Code Editor                             │
│  ┌─────────────────────────────────────┐    │
│  │  file.py (contains secrets)         │    │
│  └─────────────────────────────────────┘    │
│            │                                 │
│            │ Ctrl+Alt+S                      │
│            ▼                                 │
│  ┌─────────────────────────────────────┐    │
│  │  Task: "MCP Sanitize"               │    │
│  │  → mcp sanitize --input file.py     │    │
│  └─────────────────────────────────────┘    │
│            │                                 │
│            ▼                                 │
│  ┌─────────────────────────────────────┐    │
│  │  Terminal Output (sanitized text)   │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## Quick Start Guide

### Scenario 1: Sanitize a Single File (Preview Only)

1. Open a file containing secrets (e.g., `config.py`)
2. Press `Ctrl+Alt+S` (Windows/Linux) or `Cmd+Alt+S` (macOS)
3. View sanitized output in terminal (file is **not modified**)

**What happens**:
- CloakMCP scans the file for secrets
- Replaces detected values with tags/pseudonyms
- Prints result to terminal for review

### Scenario 2: Scan File for Secrets (Audit Only)

1. Open a file
2. Press `Ctrl+Alt+A`
3. No output is shown; check `audit/audit.jsonl` for detections

**What happens**:
- CloakMCP scans the file
- Logs all detections to audit log
- Does **not** modify the file

### Scenario 3: Sanitize and Overwrite File

1. Open VS Code Command Palette (`Ctrl+Shift+P`)
2. Type "Tasks: Run Task"
3. Select "MCP: Sanitize current file → preview"
4. Review output
5. If satisfied, manually run:
   ```bash
   mcp sanitize --policy examples/mcp_policy.yaml --input yourfile.py --output yourfile.py
   ```

### Scenario 4: Pack Entire Project Before Sharing

Before uploading to GitHub or sharing with an LLM:

1. Open terminal in VS Code (`` Ctrl+` ``)
2. Run:
   ```bash
   mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG
   ```
3. All secrets replaced with `TAG-xxxxxxxxxxxx` tags
4. Vault created in `~/.cloakmcp/vaults/`

**After work is done**:

```bash
mcp unpack --dir .
```

Secrets are restored from vault.

---

## Feature Reference

### 1. File Sanitization (Preview)

**Task**: `MCP: Sanitize current file → preview`
**Shortcut**: `Ctrl+Alt+S`
**Command**:

```bash
mcp sanitize --policy ${workspaceFolder}/examples/mcp_policy.yaml --input ${file} --output -
```

**Behavior**:
- Reads current file
- Applies policy rules
- Prints sanitized version to terminal
- **Does not modify** the original file

**Use when**:
- You want to preview what secrets will be removed
- Checking if a file is safe to share
- Testing policy rules

**Example**:

*File: `database.py`*

```python
DB_HOST = "db.internal.company.com"
DB_USER = "admin"
DB_PASS = "SuperSecret123!"
```

*After `Ctrl+Alt+S` (preview in terminal)*:

```python
DB_HOST = "PZ-Ab3Cd5Ef7"
DB_USER = "admin"
DB_PASS = "PZ-Gh9Ij1Kl3"
```

### 2. File Scanning (Audit Only)

**Task**: `MCP: Scan current file (audit only)`
**Shortcut**: `Ctrl+Alt+A`
**Command**:

```bash
mcp scan --policy ${workspaceFolder}/examples/mcp_policy.yaml --input ${file}
```

**Behavior**:
- Scans file for secrets
- Logs detections to `audit/audit.jsonl`
- Does **not** print output or modify file
- Silent operation (runs in background)

**Use when**:
- Pre-commit checks
- Regular security audits
- Building detection metrics

**Audit log format** (`audit/audit.jsonl`):

```json
{"ts": "2025-11-11T16:30:00+01:00", "rule_id": "email", "action": "replace_with_template", "blocked": false, "start": 45, "end": 65, "value_hash": "a3b2c1d4e5..."}
{"ts": "2025-11-11T16:30:01+01:00", "rule_id": "aws_key", "action": "block", "blocked": true, "start": 120, "end": 140, "value_hash": "f6g7h8i9j0..."}
```

### 3. API-Based Sanitization (Advanced)

**Task**: `MCP: Sanitize selection via API`
**Requires**: Running API server (see [API Server Mode](#api-server-mode))

**Behavior**:
- Sends selected text to localhost API
- Receives sanitized version
- Prints result to terminal

**Use when**:
- Real-time sanitization in custom workflows
- Integrating with other IDE extensions
- Processing clipboard content

### 4. Directory Pack/Unpack

**Not bound to shortcuts**; run via terminal.

#### Pack (Anonymize Project)

```bash
mcp pack --policy examples/mcp_policy.yaml --dir /path/to/project --prefix TAG
```

**What it does**:
- Scans all files in directory (respects `.mcpignore`)
- Replaces secrets with deterministic tags like `TAG-a1b2c3d4e5f6`
- Stores mapping in encrypted vault (`~/.cloakmcp/vaults/<slug>.vault`)
- Modifies files **in place**

**Example**:

*Before pack:*

```python
# config.py
API_KEY = "sk_live_1234567890abcdef"
EMAIL = "admin@company.com"
```

*After pack:*

```python
# config.py
API_KEY = "TAG-9f8e7d6c5b4a"
EMAIL = "TAG-3a2b1c0d9e8f"
```

#### Unpack (Restore Secrets)

```bash
mcp unpack --dir /path/to/project
```

**What it does**:
- Scans all files for tags (`PREFIX-[0-9a-f]{12}`)
- Looks up original values in vault
- Replaces tags with original secrets
- Modifies files **in place**

**Example**:

*After unpack:*

```python
# config.py (restored)
API_KEY = "sk_live_1234567890abcdef"
EMAIL = "admin@company.com"
```

**Important**: Pack/unpack operations are **idempotent**. Running twice has no additional effect.

---

## Keyboard Shortcuts

CloakMCP defines the following shortcuts in `.vscode/keybindings.json`:

| Shortcut         | Action                            | Description                          |
| ---------------- | --------------------------------- | ------------------------------------ |
| `Ctrl+Alt+S`     | Sanitize current file (preview)   | Print sanitized version to terminal  |
| `Ctrl+Alt+A`     | Scan current file (audit only)    | Log detections without modification  |

**To customize**:

1. Open `.vscode/keybindings.json`
2. Change `"key"` values
3. Save file

Example (change to `Ctrl+Shift+S`):

```json
[
  { "key": "ctrl+shift+s", "command": "workbench.action.tasks.runTask", "args": "MCP: Sanitize current file → preview" }
]
```

---

## Tasks Reference

CloakMCP defines three tasks in `.vscode/tasks.json`:

### Task 1: Sanitize Current File (Preview)

```json
{
  "label": "MCP: Sanitize current file → preview",
  "type": "shell",
  "command": "mcp sanitize --policy ${workspaceFolder}/examples/mcp_policy.yaml --input ${file} --output -",
  "presentation": { "reveal": "always", "panel": "shared" }
}
```

**Variables**:
- `${workspaceFolder}`: Project root directory
- `${file}`: Currently open file

**Output**: Printed to terminal.

### Task 2: Scan Current File (Audit Only)

```json
{
  "label": "MCP: Scan current file (audit only)",
  "type": "shell",
  "command": "mcp scan --policy ${workspaceFolder}/examples/mcp_policy.yaml --input ${file}",
  "presentation": { "reveal": "never", "panel": "shared" }
}
```

**Output**: Written to `audit/audit.jsonl` (no terminal output).

### Task 3: Sanitize Selection via API

```json
{
  "label": "MCP: Sanitize selection via API",
  "type": "shell",
  "command": "python - <<'PY'\n...\nPY",
  "options": { "cwd": "${workspaceFolder}" }
}
```

**Requirements**:
- API server running (`uvicorn mcp.server:app --host 127.0.0.1 --port 8765`)
- Valid API token in `keys/mcp_api_token`

**Note**: This task reads from stdin (for selected text), but VS Code tasks don't support selection input by default. Use the Command Palette to run manually.

---

## API Server Mode

CloakMCP includes an optional **local-only FastAPI server** for real-time sanitization.

### Starting the Server

```bash
# Generate API token (if not done)
openssl rand -hex 32 > keys/mcp_api_token

# Start server (bind to localhost only)
uvicorn mcp.server:app --host 127.0.0.1 --port 8765
```

**Output**:

```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8765 (Press CTRL+C to quit)
```

**Important**: Server binds to `127.0.0.1` (localhost only) by default. Do **not** expose to public networks.

### API Endpoints

| Endpoint        | Method | Description                            |
| --------------- | ------ | -------------------------------------- |
| `/health`       | GET    | Server status and policy hash          |
| `/sanitize`     | POST   | Sanitize text (modify secrets)         |
| `/scan`         | POST   | Scan text (audit only, no modification)|

All endpoints require **Bearer token** authentication.

### Example: Using REST Client Extension

Create `api/test_requests.http`:

```http
@token = {{$dotenv keys/mcp_api_token}}
@base = http://127.0.0.1:8765

### Health Check
GET {{base}}/health
Authorization: Bearer {{token}}

### Sanitize Text
POST {{base}}/sanitize
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "text": "Email: alice@example.com\nKey: AKIAIOSFODNN7EXAMPLE",
  "policy_path": "examples/mcp_policy.yaml",
  "dry_run": false
}

### Scan Text (Dry-Run)
POST {{base}}/scan
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "text": "Email: bob@company.com",
  "policy_path": "examples/mcp_policy.yaml"
}
```

Click "Send Request" in VS Code to test.

### Using with Python

```python
import json
import urllib.request

TOKEN = open("keys/mcp_api_token").read().strip()
url = "http://127.0.0.1:8765/sanitize"

payload = {
    "text": "Password: SuperSecret123!",
    "policy_path": "examples/mcp_policy.yaml",
    "dry_run": False
}

req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", f"Bearer {TOKEN}")

response = urllib.request.urlopen(req)
print(response.read().decode())
```

---

## Workflow Examples

### Workflow 1: Safe Code Review with Claude

**Scenario**: You want Claude to review your code, but it contains API keys.

**Steps**:

1. **Pack the project**:
   ```bash
   mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG
   ```

2. **Verify secrets removed**:
   ```bash
   grep -r "AKIA" .  # Should return nothing
   grep -r "TAG-" .  # Should find tags
   ```

3. **Upload to Claude** (via web UI or API)

4. **Receive reviewed code** from Claude (tags preserved)

5. **Unpack to restore secrets**:
   ```bash
   mcp unpack --dir .
   ```

6. **Verify restoration**:
   ```bash
   git diff  # Should show no changes (secrets restored)
   ```

### Workflow 2: Pre-Commit Hook

**Goal**: Block commits containing un-sanitized secrets.

**Setup** (`.git/hooks/pre-commit`):

```bash
#!/bin/bash
# CloakMCP pre-commit hook

echo "🔒 CloakMCP: Scanning for secrets..."

# Scan all staged files
for file in $(git diff --cached --name-only --diff-filter=ACM); do
  if [ -f "$file" ]; then
    mcp scan --policy examples/mcp_policy.yaml --input "$file" || {
      echo "❌ Secrets detected in $file. Commit blocked."
      echo "   Run: mcp sanitize --policy examples/mcp_policy.yaml --input $file --output $file"
      exit 1
    }
  fi
done

echo "✅ No secrets detected."
exit 0
```

Make executable:

```bash
chmod +x .git/hooks/pre-commit
```

**Test**:

```bash
echo "AWS_KEY=AKIAIOSFODNN7EXAMPLE" > test.txt
git add test.txt
git commit -m "test"  # Should fail
```

### Workflow 3: Sanitize Before CI/CD

**Goal**: Ensure CI/CD pipelines never see secrets.

**In `.github/workflows/test.yml`**:

```yaml
name: Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install CloakMCP
        run: |
          pip install -e .
          mkdir -p keys
          echo "${{ secrets.MCP_HMAC_KEY }}" > keys/mcp_hmac_key

      - name: Pack secrets
        run: |
          mcp pack --policy examples/mcp_policy.yaml --dir . --prefix CI_TAG

      - name: Run tests
        run: pytest

      # Do NOT unpack; CI should never see real secrets
```

**Important**: Store HMAC key in GitHub Secrets, not in repo.

---

## Troubleshooting

### Problem: "mcp: command not found"

**Cause**: CloakMCP not installed or virtual environment not activated.

**Solution**:

```bash
source .venv/bin/activate  # Activate venv
pip install -e .           # Reinstall if needed
which mcp                  # Should show path in .venv/
```

### Problem: "Missing API token file"

**Cause**: `keys/mcp_api_token` not created.

**Solution**:

```bash
mkdir -p keys
openssl rand -hex 32 > keys/mcp_api_token
```

### Problem: Keyboard shortcuts not working

**Cause**: Keybindings not loaded or conflicting with other extensions.

**Solution**:

1. Open Command Palette (`Ctrl+Shift+P`)
2. Type "Preferences: Open Keyboard Shortcuts (JSON)"
3. Verify CloakMCP bindings are present
4. Check for conflicts (search for `ctrl+alt+s`)

### Problem: Policy file not found

**Error**: `FileNotFoundError: [Errno 2] No such file or directory: 'examples/mcp_policy.yaml'`

**Cause**: Running command from wrong directory.

**Solution**:

```bash
cd /path/to/CloakMCP  # Ensure you're in project root
mcp sanitize --policy $(pwd)/examples/mcp_policy.yaml --input file.py --output -
```

Or use absolute path:

```bash
mcp sanitize --policy /full/path/to/CloakMCP/examples/mcp_policy.yaml --input file.py --output -
```

### Problem: Secrets not detected

**Cause**: Policy rules may not cover your secret format.

**Solution**:

1. Check policy file: `cat examples/mcp_policy.yaml`
2. Test regex patterns: [regex101.com](https://regex101.com)
3. Add custom rule:

```yaml
detection:
  - id: custom_secret
    type: regex
    pattern: 'your_pattern_here'
    action: redact
```

### Problem: Vault decryption fails

**Error**: `cryptography.fernet.InvalidToken`

**Cause**: Vault key mismatch (wrong key or corrupted vault).

**Solution**:

1. **If key is lost**: Vault cannot be recovered (by design)
2. **If key exists**: Check permissions:
   ```bash
   ls -l ~/.cloakmcp/keys/
   chmod 600 ~/.cloakmcp/keys/*.key
   ```
3. **Last resort**: Delete vault and re-pack:
   ```bash
   rm ~/.cloakmcp/vaults/<slug>.vault
   rm ~/.cloakmcp/keys/<slug>.key
   mcp pack --policy examples/mcp_policy.yaml --dir . --prefix TAG
   ```

---

## Advanced Configuration

### Custom Policy Per Project

Create project-specific policy:

```bash
cp examples/mcp_policy.yaml .mcp_policy.yaml
```

Edit `.vscode/tasks.json` to use `.mcp_policy.yaml`:

```json
{
  "label": "MCP: Sanitize current file → preview",
  "command": "mcp sanitize --policy ${workspaceFolder}/.mcp_policy.yaml --input ${file} --output -"
}
```

### Adding Custom Task: Pack/Unpack via Command Palette

Edit `.vscode/tasks.json` and add:

```json
{
  "label": "MCP: Pack project (anonymize)",
  "type": "shell",
  "command": "mcp pack --policy ${workspaceFolder}/examples/mcp_policy.yaml --dir ${workspaceFolder} --prefix TAG",
  "problemMatcher": []
},
{
  "label": "MCP: Unpack project (restore secrets)",
  "type": "shell",
  "command": "mcp unpack --dir ${workspaceFolder}",
  "problemMatcher": []
}
```

Usage:

1. `Ctrl+Shift+P` → "Tasks: Run Task"
2. Select "MCP: Pack project" or "MCP: Unpack project"

### Integrating with GitLens

Mark sanitized commits in GitLens:

1. After packing, commit with marker:
   ```bash
   git add .
   git commit -m "feat: new feature [MCP-SANITIZED]"
   ```

2. In GitLens history, you'll see `[MCP-SANITIZED]` tags

3. Before pushing:
   ```bash
   mcp unpack --dir .
   git commit --amend --no-edit  # Update commit with real secrets (if needed)
   ```

**Note**: Only sanitize commits for **external** review. Internal commits should contain real secrets (in private repos).

### Setting Up `.mcpignore`

Create `.mcpignore` in project root to exclude files/directories from pack/unpack:

```
# .mcpignore (similar to .gitignore)

# Binaries
*.pyc
*.so
*.dll
*.exe

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

# Already sanitized
audit/
keys/
.vscode/
```

**Important**: `.mcpignore` must use **glob patterns** (not regex).

---

## Best Practices

1. **Always pack before sharing**: Never share code with LLMs without packing first
2. **Backup vaults**: Regularly backup `~/.cloakmcp/` directory
3. **Use separate policies**: Development vs. production policies may differ
4. **Audit regularly**: Review `audit/audit.jsonl` for unexpected detections
5. **Test policies**: Use dry-run mode to test new rules before applying
6. **Document custom rules**: Add comments in `mcp_policy.yaml` explaining each rule
7. **Rotate keys**: Periodically regenerate HMAC keys (requires re-packing)
8. **Never commit keys**: Ensure `keys/` is in `.gitignore`
9. **Use pre-commit hooks**: Automate scanning before commits
10. **Monitor false positives**: Adjust policies to reduce noise

---

## FAQ

**Q: Can I use CloakMCP with other IDEs (PyCharm, Sublime)?**
A: Yes! CloakMCP is CLI-based. Configure external tools in your IDE to call `mcp` commands.

**Q: Does packing preserve file encoding?**
A: Yes, UTF-8 is used. Non-UTF-8 files may be skipped (logged in future versions).

**Q: Can I pack only specific files?**
A: Use `.mcpignore` to exclude files. For selective packing, create a subdirectory.

**Q: What happens if I lose the vault key?**
A: **Vault is unrecoverable**. Secrets are encrypted with AES-128. Backup keys securely.

**Q: Can I share vaults between machines?**
A: Yes. Copy `~/.cloakmcp/keys/<slug>.key` and `~/.cloakmcp/vaults/<slug>.vault` to new machine. Ensure same project path or re-generate slug.

**Q: Does CloakMCP work with Git submodules?**
A: Yes. Pack each submodule independently or pack the entire parent directory.

**Q: How do I update VS Code tasks after changing policy?**
A: Tasks use `${workspaceFolder}/examples/mcp_policy.yaml` by default. No update needed unless you change the policy path.

---

## Support & Resources

- **Documentation**: `CLAUDE.md`, `README.md`, `SECURITY.md`
- **Issues**: Report bugs to Olivier Vitrac (Adservio Innovation Lab)
- **Examples**: See `examples/` directory for policy templates and client scripts
- **API Reference**: OpenAPI docs at `http://127.0.0.1:8765/docs` (when server running)

---

## Conclusion

CloakMCP provides **local-first, deterministic secret protection** for VS Code workflows. By integrating tightly with tasks, keybindings, and terminal, it enables seamless secure collaboration with LLMs without exposing sensitive data.

**Remember**: Always pack before sharing, and never commit keys to version control.

---

*Manual prepared for Olivier Vitrac — Adservio Innovation Lab*
*CloakMCP v0.3.0 — MIT License*
