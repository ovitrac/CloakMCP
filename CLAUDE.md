# CLAUDE.md
**Project:** CloakMCP v0.3.2 — Micro-Cleanse Preprocessor (Local Secret & PII Removal + Vaulted Re-injection)
**Maintainer:** Olivier Vitrac (Adservio Innovation Lab)
**Date:** November 2025
**Version:** 0.3.2-alpha

---

## 1. Purpose

CloakMCP is a **local-first anonymization layer** designed to protect secrets, credentials, and personal data **before any content leaves a developer’s workstation** for analysis by LLMs such as Claude, Codex, or Gemini.

It provides:
- 🔒 **Deterministic, reversible redaction** using an encrypted *vault* stored outside the project;
- ⚙️ **Policy-driven scanning** (regex / entropy / IP / URL / email / JWT / SSH keys / certificates …);
- 🏢 **Group policy inheritance** (company → team → project) for organizational compliance (v0.3.2);
- 📦 **Batch "pack" and "unpack" modes** to anonymize or restore whole codebases;
- 🧩 Optional localhost REST API for integration in IDEs or automated pipelines.

The system guarantees that an external LLM **never sees the true secrets** and that the original content can be **reconstructed safely and deterministically** afterwards.

---

## 2. Core Principles

| Principle | Description |
|------------|--------------|
| **Local-first** | All operations (scan / sanitize / pack / unpack) are executed locally on developer machines. No network dependency. |
| **Policy-driven** | A YAML file (`examples/mcp_policy.yaml`) defines what to detect and how to act (block / redact / pseudonymize / replace). |
| **Reversible** | During `pack`, real secrets are replaced by deterministic tags like `TAG-2f1a8e3c9b12`; the mapping is stored in an **encrypted vault**. |
| **External vault** | Vaults and keys live in `~/.cloakmcp/{vaults,keys}` — outside any git repository or workspace shared with the LLM. |
| **Deterministic tags** | Same secret → same tag across sessions, allowing stable diffs and reproducibility. |
| **Auditable** | Each replacement event is logged to `audit/audit.jsonl` (timestamp + rule + hash + action). |

---

## 3. How Claude (or any LLM) should operate

1. **Receive only packed data.**
   When a repository is processed with `cloak pack`, all sensitive information is replaced by opaque tags.
   LLMs can view, analyze, and modify these files freely.

2. **Never access or modify the vault.**
   The vault (`~/.cloakmcp/vaults/<slug>.vault`) and its key are local to the user and must never be uploaded, read, or rewritten by Claude.

3. **Respect tag boundaries.**
   Tags have the form `PREFIX-[0-9a-f]{12}`.
   Do not alter their content or syntax. You may move or duplicate them as plain tokens, but never re-generate them manually.

4. **Post-processing.**
   When user work is done (e.g., code review, refactor, or generation), the user runs:
```bash
   cloak unpack --dir /path/to/project
```

This restores all secrets safely using the encrypted local vault.

---

## 4. CLI Overview

| Command                                               | Description                                              |
| ----------------------------------------------------- | -------------------------------------------------------- |
| `cloak scan --policy POL --input FILE`                  | Scan file, log detections (no modification).             |
| `cloak sanitize --policy POL --input FILE --output OUT` | Sanitize a single file (one-shot).                       |
| `cloak pack --policy POL --dir DIR`                     | Replace secrets by deterministic tags across directory.  |
| `cloak unpack --dir DIR`                                | Restore original secrets from local vault.               |
| `cloak policy validate --policy POL`                    | Validate policy file (including inheritance chain).      |
| `cloak policy show --policy POL [--format yaml|json]`   | Show merged policy after inheritance resolution.         |
| `cloak server` (via uvicorn)                            | Optional localhost REST API (`127.0.0.1:8765/sanitize`). |

---

## 5. Vault Architecture

```
~/.cloakmcp/
├── keys/
│   └── <project-slug>.key        # Fernet encryption key (600 perms)
└── vaults/
    └── <project-slug>.vault      # Encrypted JSON mapping {TAG → secret}
```

* **Slug:** 16-character SHA-256 prefix of the project’s absolute path.
* **Encryption:** AES-128 / Fernet (symmetric); key created automatically at first pack.
* **Permissions:** 0600 where possible.
* **Portability:** Copying both `.key` and `.vault` restores decryption capability elsewhere.

---

## 6. Example Workflow (Claude-safe)

```bash
# 1. User prepares environment
pip install -e .
openssl rand -hex 32 > keys/mcp_hmac_key

# 2. User anonymizes repo before upload
cloak pack --policy examples/mcp_policy.yaml --dir my_project

# 3. Claude performs code review / refactor / documentation
#    (no access to vault, only sees TAG-xxxxxx placeholders)

# 4. User restores secrets locally
cloak unpack --dir my_project
```

---

## 7. Integration Notes

* **VS Code:** Keybindings (`Ctrl + Alt + S`/`A`) and tasks are pre-configured for quick sanitize/scan.
* **API mode:** Localhost FastAPI server (`uvicorn cloak.server:app --host 127.0.0.1 --port 8765`) for on-the-fly sanitization by IDE extensions.
* **CI/CD:** Add a pre-commit hook invoking `cloak scan` to block commits with un-sanitized secrets.
* **`.mcpignore`:** Controls which files or directories are skipped during pack/unpack (similar to `.gitignore`).

---

## 8. Limitations & Safety

* CloakMCP protects **content confidentiality**, not **intent semantics** — meaning it hides values, not project logic.
* Vault integrity relies on local filesystem security; keep `~/.cloakmcp` private and backed up securely.
* Always run LLM operations on the **packed version** only.
* If tags appear inside generated output from the LLM, do not replace or reinterpret them manually.

---

## 9. Credits & License

* **Design & implementation:** Olivier Vitrac — Adservio Innovation Lab, 2025.
* **License:** MIT License (see `LICENSE`).
* **Acknowledgements:** inspired by OpenAI Red Team practices, GitGuardian CLI, and Mozilla SOPS.

---

> *“Claude may read, refactor, or reason on tagged data —
> but never unmask what the vault keeps safe.”*



---

Technical details associated with the specifications of the different maturing versions:

- without restoring secrets (drying): Annex 1
- API: Annex 2
- with restoration of secrets (rehydration): Annex 2

---

## ANNEX 1 – Technical Specifications of the removal part

**Project:** MCP (Micro-Cleanse Preprocessor) — local secret-removal agent
 **Purpose:** specification and developer guide for an advanced open-source agent that **removes or neutralizes secrets locally** before any text is forwarded to an unsecured MLM (local LLM / remote LLM). The agent runs only locally (CLI, desktop app, or optional local server behind the user's control) and is delivered under an MIT license with authorship preserved.

> Short summary: MCP is a deterministic, auditable pre-processor that *detects, classifies and neutralizes* secrets (emails, URLs, IPs, tokens, keys, PII, etc.) using a configurable allow/deny policy (YAML or “Apache style” lists). The system is explicitly designed so **no unfiltered data ever reaches an unsecured MLM**.
>
> ATTENTION: these drafted  technical specifications cover only the first par removal and does not discuss the rehydration when secrets are reinjected.

------

### 1. Threat model & design constraints

**Assumptions**

- Adversary = any third party that can read data once it leaves the local host / network (i.e., the MLM host or network path).
- The local machine and MCP process are trusted. MCP will not phone home.
- User wants to keep all secret handling local. No remote telemetry, no external API keys in repo.

**Threats addressed**

- Accidental leakage of credentials, tokens, personally identifiable info (PII), IP addresses, internal hostnames, non-public URLs.
- Leakage via transformed text (e.g., tokens embedded inside code snippets or base64 blobs).

**Threats out of scope**

- Compromised local machine or insider attacks.
- Side-channel attacks on the MLM once data leaves MCP (those need separate protections).

**Goals**

- Deterministic, auditable redaction/pseudonymization.
- Configurable policy (blacklist / whitelist / rules).
- Strong defaults for common secrets (AWS keys, JWT, OAuth tokens, API keys).
- Local-first: zero external dependencies for detection or decision making.
- Easy to audit / test / extend.

------

### 2. High-level architecture

1. **Input** — text (plain, markdown, code blocks) or files (optional).
2. **Normalizer** — canonicalize line endings, unicode NFC, remove zero-width chars, extract embedded data (base64, urls inside code).
3. **Tokenizer / Scanner** — run fast deterministic detectors:
   - regex detectors (email, URL, IP, hex tokens),
   - entropy detectors for high-entropy strings,
   - heuristic detectors (looks like JWT, AWS key patterns),
   - dictionary / Aho-Corasick match for known secrets (internal hostnames).
4. **Policy Engine** — consults YAML config (whitelist/blacklist + actions) to decide per match:
   - `allow`, `redact`, `pseudonymize`, `hash`, `encrypt_local`, `block` (reject).
5. **Action Engine** — apply action; produce audit record of what was changed.
6. **Output** — sanitized text + optional audit log (locally stored, encrypted if requested).
7. **Optional local server** — small Flask/FastAPI service bound to localhost only (or local LAN with access control) for apps that prefer HTTP API.

Flow (text):

```
Input -> Normalizer -> Scanner -> Policy Engine -> Action Engine -> Output (+ Audit)
```

------

### 3. Policy configuration (YAML)

Use YAML (human readable) for default policy. It resembles Apache allow/deny lists with richer rules.

**File:** `mcp_policy.yaml` (example)

```
version: 1
globals:
  pseudonymization:
    method: hmac-sha256     # or reversible-aes-gcm
    secret_key_file: ./keys/mcp_hmac_key  # MUST be local, not in repo
    salt: session           # 'session' or 'permanent' or a configurable string

detection:
  # Ordered list. First match wins.
  - id: aws_access_key_like
    type: regex
    pattern: '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    action: redact
    severity: high

  - id: jwt_token
    type: pattern
    pattern: '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$'
    context: "inside code or inline"
    action: pseudonymize

  - id: email
    type: regex
    pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    action: replace_with_template
    template: '<EMAIL:{hash}>'
    whitelist: ['*@company.com']   # allow company addresses

  - id: ip_v4
    type: ip
    action: pseudonymize
    whitelist: ['10.0.0.0/8', '192.168.0.0/16']

  - id: high_entropy_token
    type: entropy
    min_entropy: 4.5  # configurable threshold
    min_length: 16
    action: redact
    note: "catch long base64-like blobs / keys"

blacklist:
  emails:
    - secret@internal.company
  urls:
    - internal-service.company.local
  ips:
    - 203.0.113.42

whitelist:
  urls:
    - https://public.example.com
```

**Notes**

- `action` values: `allow`, `redact`, `pseudonymize`, `hash`, `encrypt_local`, `block`, `replace_with_template`.
- `pseudonymize` uses deterministic HMAC or mapping DB so the same secret maps to same pseudonym within a session or permanently (configurable).
- `secret_key_file` must be kept locally and not checked into git. Recommend `.gitignore` and a secure secret store.

------

### 4. Detection & heuristics

**Detectors (recommended set)**

- **Regex**: emails, URLs, IPv4, IPv6, MAC addresses, credit card formats (masked detection only), common API key formats (AWS, GCP, Azure patterns).
- **Pattern**: JWT (3-part base64), PEM blocks, SSH private key headers.
- **Entropy**: Shannon entropy per character. High entropy strings often indicate keys or tokens (configurable threshold).
- **Contextual rules**:
  - If a candidate is inside a code fence (```), treat differently (less aggressive redaction but still actionable).
  - If preceded/followed by known labels (`password=`, `api_key:`), escalate action to `block` or `redact`.
- **Dictionary**: user-supplied list of internal hostnames, product codenames, emails. Use Aho-Corasick implementation for many terms.

**Avoiding false positives**

- Respect `whitelist` entries and allow exact/regex whitelists.
- Allow per-project allow rules (scoped to project roots).
- Provide a `dry-run` mode that only logs potential redactions (for tuning policies).

------

### 5. Neutralization strategies

**Redaction**

- Replace with `<REDACTED:type>` or user template. Non-reversible.

**Deterministic pseudonymization**

- HMAC-SHA256 of the secret with a local key; for readability optionally base62 encode and shorten:

  ```
  pseudonym = <TYPE>-<first8(base62(hmac(secret, key)))>
  ```

- This keeps uniqueness while making the original unrecoverable without the key (if HMAC only). If reversibility is required, use local AES-GCM with key stored in `keys/` and access controlled.

**Hashing**

- Non-salted or salted SHA256 — note: unsalted easily brute-forced. Prefer HMAC with secret key.

**Tokenization (surrogate mapping)**

- Store mapping table in local encrypted SQLite (SQLCipher) or an encrypted JSON file.
- Useful when reversible mapping is required for later internal processing.

**Rewriting with templates**

- `'<EMAIL:{hash}>'` or `USER_0001` style for readability.

**Blocking**

- For extreme cases (e.g., very likely secrets that must not be forwarded), fail the request and return an error to the caller. Configurable global or per-rule.

**Logging / Audit**

- For compliance, write an audit record of:
  - original hash (SHA256),
  - detection rule id,
  - action taken,
  - timestamp,
  - user/process id
- Audit logs must be stored locally and can be encrypted.

------

### 6. Implementation guidance (Python)

**Project layout (suggested)**

```
CloakMCP/
├── .gitignore
├── AUTHORS.md
├── CLAUDE.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── api/
│   └── requests.http
├── audit/
│   └── .gitkeep
├── deploy/
│   └── cloak-local.service
├── examples/
│   ├── client_sanitize.py
│   └── mcp_policy.yaml
├── keys/
│   └── .gitkeep
├── mcp/
│   ├── __init__.py
│   ├── actions.py
│   ├── audit.py
│   ├── cli.py
│   ├── normalizer.py
│   ├── policy.py
│   ├── scanner.py
│   └── server.py
├── pyproject.toml
├── SECURITY.md
├── tests/
│   └── test_smoke.py
└── .vscode/
    ├── keybindings.json
    ├── settings.json
    └── tasks.json
```

**Recommended libraries**

- `regex` or Python built-in `re` (use `regex` for advanced features)
- `email_validator` (validate addresses)
- `tldextract` (for URL analysis)
- `ipaddress` (stdlib) for CIDR checks
- `cryptography` for HMAC/AES
- `pyahocorasick` for dictionary matching (optional)
- `sqlcipher` / `pysqlcipher3` or `sqlcipher3` for encrypted sqlite (optional)
- `pyyaml` for config
- `pytest`, `mypy`, `black`, `pre-commit`, `bandit` for security linting

**Coding standards**

- Type hints throughout (mypy).
- Strict unit tests for every detector and action. Cover edge cases and Unicode.
- Use `black` + `isort`. Enforce with `pre-commit`.
- Use `bandit` to scan for security issues.
- CI runs locally (since remote CI may reveal secrets): provide sample GitHub Action templated, but clearly state in README that keys must be injected with repository secrets if used. Prefer local CI for secret handling.

------

### 7. CLI & server

**CLI**

- `cloak scan --policy ./mcp_policy.yaml --input file.md --dry-run`
- `cloak sanitize --policy ./mcp_policy.yaml --input file.md --output file.sanitized.md`
- `cloak watch --dir ./project --policy ./mcp_policy.yaml` (optional)

**Local server (optional)**

- Minimal FastAPI app listening on `127.0.0.1:PORT` with token protection (local token file). Default bind to `localhost` only, with `--allow-lan` explicit flag.
- Endpoints:
  - `POST /sanitize` — accept text payload, return sanitized text and audit.
  - `GET /status` — basic local status, policy hash check.
- **Important:** server must only start after explicit local consent. Do not enable remote access by default.

------

### 8. Testing & evaluation

**Unit tests**

- Detector tests: true positives/negatives on curated corpus.
- Action tests: ensure pseudonyms are deterministic (given same key), redaction is one-way.
- Integration tests: end-to-end policies.

**Fuzz testing**

- Generate random long base64 strings, random unicode, mixed scripts to find false positives/negatives.

**Metrics & monitoring (local)**

- False positive rate, false negative rate (manually labelled corpus).
- Count of blocked vs pseudonymized vs redacted items.
- Audit log size and rotation policy.

**Security tests**

- Static analysis (bandit).
- Dependency vulnerability scan (safety / pip-audit) — run locally.

------

### 9. Privacy & compliance

- Keep `keys/` out of repo. Provide `keys/README.md` with secure generation instructions:
  - `openssl rand -hex 32 > keys/mcp_hmac_key` (user runs locally)
- Authors and CONTRIBUTING:
  - Place `AUTHORS.md` and `LICENSE` (MIT) at repo root.
  - Keep a clear `CODE_OF_CONDUCT` and `CONTRIBUTING.md`.
- Provide a `SECURITY.md` with disclosure instructions for local issues; ensure all communication channels are local/secure.

------

### 10. Packaging & distribution

- Provide `pyproject.toml` / Poetry or setuptools.
- Publish as source on GitHub under MIT, but **do not publish any default keys or example keys** — provide generation scripts instead.
- Provide Dockerfile for a fully local containerized deployment (bind mount for `keys/` and `audit/` directories). Document in README that container must not be exposed publicly.

------

### 11. Example: sample detection rule set (concise)

- Emails: redact unless whitelisted domain.
- URL: redact internal hostnames, pseudonymize public ones.
- IPs: pseudonymize external IPs; allow RFC1918 internal ranges if whitelisted.
- JWT: treat as token → redact/pseudonymize.
- Keys matching provider patterns (AKIA,AIza, etc.) → block or redact.
- High entropy > configurable threshold → redact (if not whitelisted).

------

### 12. Audit trail & reproducibility

- Keep audit logs locally in `audit/` as compressed JSONL with fields:

  ```
  {
    "timestamp": "2025-11-06T07:00:00+01:00",
    "rule_id": "aws_access_key_like",
    "action": "redact",
    "file": "notes.md",
    "location": {"line": 12, "char": 45},
    "value_hash": "sha256:... (original value hashed for traceability)",
    "session_id": "..."
  }
  ```

- Allow `cloak audit --export --decrypt` for authorized local users only (if reversible mapping used).

------

### 13. Authorship & licensing (MIT)

**LICENSE**: Use MIT. Add at top of each source file a short header preserving authorship:

```
# MCP: Micro-Cleanse Preprocessor
# Copyright (c) 2025 Olivier Vitrac and contributors
# Licensed under the MIT License. See LICENSE file.
```

Keep `AUTHORS.md` listing contributors. Encourage PRs but require contributors to confirm they have right to contribute under MIT.

------

### 14. Developer checklist (minimum viable secure release)

1. Implement core detectors: email, url, ipv4/6, jwt, common provider keys.
2. Implement YAML policy parser + rule engine.
3. Implement deterministic pseudonymization (HMAC) & simple redaction.
4. Implement CLI with `--dry-run`.
5. Implement tests covering each detector and action.
6. Add pre-commit hooks: black, isort, mypy.
7. Add `SECURITY.md`, `CONTRIBUTING.md`, `AUTHORS.md`, `LICENSE`.
8. Provide clear `keys/` generation script and `.gitignore` entries.
9. Run static scan (bandit) and fix issues.
10. Document run modes: `local-only` (default) and `local-server` (explicit opt-in).

------

### 15. Example quickstart (user)

1. Clone repo.
2. Create key: `mkdir keys && openssl rand -hex 32 > keys/mcp_hmac_key`
3. Edit `mcp_policy.yaml` (examples provided).
4. Dry run: `cloak scan --policy examples/mcp_policy.yaml --input notes.md --dry-run`
5. If satisfied: `cloak sanitize --policy examples/mcp_policy.yaml --input notes.md --output notes.sanitized.md`

------

### 16. Additional recommendations & hardening

- Ship with a curated detection ruleset, but encourage site/project customization.
- Provide a GUI extension (VSCode extension, local plugin) that calls the CLI via localhost, with explicit consent before any upward send to MLM.
- Consider integrating a minimal local KMS (e.g., key protected by OS user-password) for reversible encryption if needed.
- Keep default behavior conservative: **block** or **redact** rather than allow.
- Periodically review and update rules because token formats evolve.

------

### 17. Appendix — Useful regex snippets (examples)

> These are starter examples. Use tests to adapt to your needs.

- Email: `(?i)([a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+)`
- IPv4: `\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b`
- JWT: `\b[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b`
- AWS key: `\b(AKIA|ASIA)[A-Z0-9]{16}\b`
- Generic base64 blob (heuristic): `(?:[A-Za-z0-9+/]{40,}={0,2})`

------

### 18. Final notes

- Your core concern is correct: **do not use the MLM to help remove secrets** because that would expose data prior to sanitization. The correct pattern is local first: sanitize first, then (if allowed by policy) forward sanitized data to MLMs.
- This CLAUDE.md is a full developer blueprint — you can turn each section into an issue or milestone.
- If you want, I can now generate:
  - a ready-to-use `mcp_policy.yaml` with more comprehensive rules,
  - a minimal Python prototype of `scanner.py` + `policy.py` with tests,
  - or a `SECURITY.md` and `CONTRIBUTING.md` templates to include in the repo.


-----

## Annex 2 – **local-only FastAPI server** + a **VS Code integration** (tasks + keybindings) 

### 1) `pyproject.toml` — add server deps

```toml
[project]
# ... (unchanged)
dependencies = [
  "pyyaml>=6.0.1",
  "fastapi>=0.115.0",
  "uvicorn>=0.30.0",
  "pydantic>=2.7.0",
]
```

------

### 2) `mcp/server.py` — localhost API (token-protected)

```python
from __future__ import annotations
import hashlib
import os
from typing import Optional

from fastapi import FastAPI, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from .policy import Policy
from .cli import sanitize_text
from .normalizer import normalize

# ---------- Security helpers ----------

def load_api_token(path: str = "./keys/mcp_api_token") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            tok = f.read().strip()
    except FileNotFoundError:
        raise RuntimeError(
            "Missing API token file ./keys/mcp_api_token "
            "(create with: openssl rand -hex 32 > keys/mcp_api_token)"
        )
    if len(tok) < 16:
        raise RuntimeError("API token too short; require >= 16 chars.")
    return tok

API_TOKEN = load_api_token()
DEFAULT_POLICY = os.getenv("MCP_POLICY", "examples/mcp_policy.yaml")

def bearer_auth(authorization: Optional[str] = Header(None)) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
    token = authorization[7:].strip()
    if token != API_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")

# ---------- Models ----------

class SanitizeRequest(BaseModel):
    text: str = Field(..., description="Raw text to sanitize")
    policy_path: str = Field(DEFAULT_POLICY, description="Path to YAML policy", examples=[DEFAULT_POLICY])
    dry_run: bool = Field(False, description="If true, do not modify text; only audit")

class SanitizeResponse(BaseModel):
    sanitized: str
    blocked: bool
    policy_sha256: str

class StatusResponse(BaseModel):
    status: str
    policy_path: str
    policy_sha256: str

# ---------- App ----------

app = FastAPI(
    title="MCP (Micro-Cleanse Preprocessor) — Local API",
    description="Local-only secret removal proxy. Bind to 127.0.0.1 by default. DO NOT expose publicly.",
    version="0.1.0",
)

def policy_hash(path: str) -> str:
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

@app.get("/health", response_model=StatusResponse)
def health(_: None = Depends(bearer_auth)):
    pol_path = DEFAULT_POLICY
    return StatusResponse(status="ok", policy_path=pol_path, policy_sha256=policy_hash(pol_path))

@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(req: SanitizeRequest, _: None = Depends(bearer_auth)):
    pol = Policy.load(req.policy_path)
    out, blocked = sanitize_text(req.text, pol, dry_run=req.dry_run)
    return SanitizeResponse(sanitized=out, blocked=blocked, policy_sha256=policy_hash(req.policy_path))

@app.post("/scan", response_model=SanitizeResponse)
def scan(req: SanitizeRequest, _: None = Depends(bearer_auth)):
    pol = Policy.load(req.policy_path)
    # dry_run scan: no modifications
    out, blocked = sanitize_text(req.text, pol, dry_run=True)
    return SanitizeResponse(sanitized=out, blocked=blocked, policy_sha256=policy_hash(req.policy_path))
```

**Run locally (loopback only):**

```bash
# one-time
mkdir -p keys
openssl rand -hex 32 > keys/mcp_api_token

# run (bind to localhost)
uvicorn cloak.server:app --host 127.0.0.1 --port 8765
```

**Curl test (replace TOKEN):**

```bash
TOKEN="$(cat keys/mcp_api_token)"
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"text":"Email: alice@example.org, Key: AKIAABCDEFGHIJKLMNOP","dry_run":false}' \
  http://127.0.0.1:8765/sanitize | jq
```

> Default binding is **127.0.0.1**. Only enable LAN access explicitly and knowingly (e.g., `--host 0.0.0.0` on a **trusted** local network).

------

### 3) Optional: `systemd` unit (local machine)

```
deploy/mcp-local.service
[Unit]
Description=MCP local sanitizer (FastAPI)
After=network-online.target

[Service]
WorkingDirectory=%h/your-repo
ExecStart=/usr/bin/env uvicorn cloak.server:app --host 127.0.0.1 --port 8765
Restart=on-failure
Environment=MCP_POLICY=examples/mcp_policy.yaml
User=%i

[Install]
WantedBy=default.target
```

Enable for your user:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/mcp-local.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now cloak-local.service
systemctl --user status cloak-local.service
```

------

### 4) VS Code integration (tasks + keybindings)

Create a `.vscode/` folder with the following:

## `.vscode/tasks.json`

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "MCP: Sanitize current file → preview",
      "type": "shell",
      "command": "cloak sanitize --policy ${workspaceFolder}/examples/mcp_policy.yaml --input ${file} --output -",
      "problemMatcher": [],
      "group": "none",
      "presentation": { "reveal": "always", "panel": "shared" }
    },
    {
      "label": "MCP: Scan current file (audit only)",
      "type": "shell",
      "command": "cloak scan --policy ${workspaceFolder}/examples/mcp_policy.yaml --input ${file}",
      "problemMatcher": [],
      "group": "none",
      "presentation": { "reveal": "never", "panel": "shared" }
    },
    {
      "label": "MCP: Sanitize selection via API",
      "type": "shell",
      "command": "python - <<'PY'\nimport json,sys,os,urllib.request\ntext=''.join(sys.stdin.read())\nbody=json.dumps({'text':text,'dry_run':False}).encode()\nreq=urllib.request.Request('http://127.0.0.1:8765/sanitize', data=body, method='POST')\nreq.add_header('Content-Type','application/json')\nreq.add_header('Authorization', 'Bearer ' + open('keys/mcp_api_token').read().strip())\nprint(urllib.request.urlopen(req).read().decode())\nPY",
      "problemMatcher": [],
      "presentation": { "reveal": "always", "panel": "shared" },
      "options": { "cwd": "${workspaceFolder}" }
    }
  ]
}
```

> The first task runs the **CLI** and prints sanitized output in the terminal (without overwriting your file).
>  The second task runs **scan** (no modification) and records detections into `audit/*.jsonl`.
>  The third task sends **selected text** to the **local API** and returns sanitized JSON (requires the server running).

## `.vscode/keybindings.json`

```json
[
  { "key": "ctrl+alt+s", "command": "workbench.action.tasks.runTask", "args": "MCP: Sanitize current file → preview" },
  { "key": "ctrl+alt+a", "command": "workbench.action.tasks.runTask", "args": "MCP: Scan current file (audit only)" }
]
```

## `.vscode/settings.json`

```json
{
  "files.trimTrailingWhitespace": true,
  "editor.rulers": [100],
  "editor.formatOnSave": true,
  "python.formatting.provider": "black",
  "python.analysis.typeCheckingMode": "strict",
  "terminal.integrated.env.linux": {
    "PYTHONUTF8": "1"
  }
}
```

------

### 5) Optional: simple “sanitize selection” Code Snippet (REST Client)

If you use the VS Code **REST Client** extension, add `api/requests.http`:

```http
@token={{$dotenv keys/mcp_api_token}}
@base=http://127.0.0.1:8765

### Health
GET {{base}}/health
Authorization: Bearer {{token}}

### Sanitize (paste your text below, between the triple quotes)
POST {{base}}/sanitize
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "text": """Email: jane@internal.company
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def
AKIAABCDEFGHIJKLMNOP
""",
  "dry_run": false
}
```

------

### 6) Optional: LAN mode (with care)

If you **must** expose over LAN (e.g., several dev machines on a trusted subnet):

- start with explicit host and a stronger token:

  ```bash
  uvicorn cloak.server:app --host 0.0.0.0 --port 8765
  ```

- use a host firewall to restrict to your subnet

- rotate `keys/mcp_api_token` frequently

------

### 7) Minimal client example (`examples/client_sanitize.py`)

```python
from __future__ import annotations
import json, urllib.request

TOKEN = open("keys/mcp_api_token").read().strip()
url = "http://127.0.0.1:8765/sanitize"
payload = {"text": "Email: bob@internal.company\nToken: AKIAABCDEFGHIJKLMNOP\n", "dry_run": False}
req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", f"Bearer {TOKEN}")
print(urllib.request.urlopen(req).read().decode())
```

Run:

```bash
python examples/client_sanitize.py
```

------

### Notes & hardening

- Server is **stateless** aside from writing audit logs; policy is read fresh per request (keep it that way for auditability).
- Default behavior remains **conservative**: block/redact high-risk detectors.
- Keep `keys/` out of VCS and with restrictive `chmod 600`.
- For desktop UX, you can later add a tiny tray app that toggles server on/off.

If you want, I can also add a **Dockerfile (local only)** and a **VS Code Command Palette extension scaffold** (TypeScript) later — but the tasks/keybindings above already give you one-keystroke integration inside VS Code.

---

### Technical notes

- Package name remains `cloak` for short CLI (`cloak sanitize ...`), while the repo name is **CloakMCP**.

- To run:

  ```
  cd CloakMCP
  python -m venv .venv && . .venv/bin/activate
  pip install -e .
  mkdir -p keys audit && openssl rand -hex 32 > keys/mcp_hmac_key
  cloak sanitize --policy examples/mcp_policy.yaml --input examples/client_sanitize.py --output -
  ```

- Local API:

  ```
  openssl rand -hex 32 > keys/mcp_api_token
  uvicorn cloak.server:app --host 127.0.0.1 --port 8765
  ```

- VS Code: press `Ctrl+Alt+S` to preview sanitize current file, `Ctrl+Alt+A` to scan & audit.

-----



## Annex 3 –  Extend CloakMCP with batch "pack/unpack" (vaulted reversible tags) and produce a new ZIP



Here’s an updated **`CLAUDE.md`** tailored for the new version of **CloakMCP v2** — fully describing how Claude (or any LLM-based code reviewer like Codex or Sonnet) should use it safely on large repositories.

The system guarantees that an external LLM **never sees the true secrets** and that the original content can be **reconstructed safely and deterministically** afterwards.

This restores all secrets safely using the encrypted local vault.

------

## 1. Updated file tree (updates only)

```text
CloakMCP/
├── .gitignore
├── .mcpignore
├── LICENSE
├── README.md
├── examples/
│   └── mcp_policy.yaml
├── mcp/
│   ├── __init__.py
│   ├── actions.py
│   ├── audit.py
│   ├── cli.py                # now with: scan, sanitize, pack, unpack
│   ├── dirpack.py            # directory walker + pack/unpack logic
│   ├── normalizer.py
│   ├── policy.py
│   ├── scanner.py
│   └── storage.py            # encrypted vault (Fernet), lives in ~/.cloakmcp/
└── pyproject.toml            # + cryptography dep

```



#### **How to use (quick)**

```bash
# install
python -m venv .venv && . .venv/bin/activate
pip install -e .
mkdir -p keys audit && openssl rand -hex 32 > keys/mcp_hmac_key   # for pseudonymization

# pack an entire repo (replace secrets by tags)
cloak pack --policy examples/mcp_policy.yaml --dir /path/to/your/repo --prefix TAG

# ...send packed repo to Claude/Codex, work freely...

# restore secrets locally
cloak unpack --dir /path/to/your/repo

```

#### How it keeps secrets safe

- **Vault is outside the repo:** `~/.cloakmcp/{keys,vaults}` (per-project slug from absolute path).
- **Encrypted vault:** `cryptography.Fernet` symmetric encryption; file perms tightened when possible.
- **Deterministic tags:** `PREFIX-<12 hex>` (SHA-256 of the secret) → stable edits across sessions.
- **LLM sees only tags:** Reversible only on your machine (or any machine that has the vault files you explicitly copy).

#### Tips

- Put common noise/binaries in **`.mcpignore`** (already included): venv, node_modules, images, PDFs, etc.
- You can set `--prefix SEC` or `--prefix KEY` per project to namespace tags.
- The YAML policy still governs **what counts as a secret** (regex/entropy/JWT/IP/URL/email/etc.).
- For CI or teammates, **share only the packed repo**. If someone needs to restore, you can hand them the *vault + key* via a secure channel; otherwise tags remain harmless strings.

---

## 2. CLI Overview

| Command                                               | Description                                              |
| ----------------------------------------------------- | -------------------------------------------------------- |
| `cloak scan --policy POL --input FILE`                  | Scan file, log detections (no modification).             |
| `cloak sanitize --policy POL --input FILE --output OUT` | Sanitize a single file (one-shot).                       |
| `cloak pack --policy POL --dir DIR`                     | Replace secrets by deterministic tags across directory.  |
| `cloak unpack --dir DIR`                                | Restore original secrets from local vault.               |
| `cloak server` (via uvicorn)                            | Optional localhost REST API (`127.0.0.1:8765/sanitize`). |

------

## 3. Vault Architecture

```
~/.cloakmcp/
├── keys/
│   └── <project-slug>.key        # Fernet encryption key (600 perms)
└── vaults/
    └── <project-slug>.vault      # Encrypted JSON mapping {TAG → secret}
```

- **Slug:** 16-character SHA-256 prefix of the project’s absolute path.
- **Encryption:** AES-128 / Fernet (symmetric); key created automatically at first pack.
- **Permissions:** 0600 where possible.
- **Portability:** Copying both `.key` and `.vault` restores decryption capability elsewhere.

------

## 4. Example Workflow (Claude-safe)

```bash
# 1. User prepares environment
pip install -e .
openssl rand -hex 32 > keys/mcp_hmac_key

# 2. User anonymizes repo before upload
cloak pack --policy examples/mcp_policy.yaml --dir my_project

# 3. Claude performs code review / refactor / documentation
#    (no access to vault, only sees TAG-xxxxxx placeholders)

# 4. User restores secrets locally
cloak unpack --dir my_project
```

------

## 5. Integration Notes

- **VS Code:** Keybindings (`Ctrl + Alt + S`/`A`) and tasks are pre-configured for quick sanitize/scan.
- **API mode:** Localhost FastAPI server (`uvicorn cloak.server:app --host 127.0.0.1 --port 8765`) for on-the-fly sanitization by IDE extensions.
- **CI/CD:** Add a pre-commit hook invoking `cloak scan` to block commits with un-sanitized secrets.
- **`.mcpignore`:** Controls which files or directories are skipped during pack/unpack (similar to `.gitignore`).

------

## 6. Limitations & Safety

- CloakMCP protects **content confidentiality**, not **intent semantics** — meaning it hides values, not project logic.
- Vault integrity relies on local filesystem security; keep `~/.cloakmcp` private and backed up securely.
- Always run LLM operations on the **packed version** only.
- If tags appear inside generated output from the LLM, do not replace or reinterpret them manually.

------

## 7. Credits & License

- **Design & implementation:** Olivier Vitrac — Adservio Innovation Lab, 2025.
- **License:** MIT License (see `LICENSE`).
- **Acknowledgements:** inspired by OpenAI Red Team practices, GitGuardian CLI, and Mozilla SOPS.

------

> *“Claude may read, refactor, or reason on tagged data —
>  but never unmask what the vault keeps safe.”*

