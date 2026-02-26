# Threat Model — CloakMCP

**Version**: 0.12.0
**Date**: 2026-02-26
**Maintainer**: Olivier Vitrac (Adservio Innovation Lab)

---

## Purpose

This document defines the security assumptions, threats in scope, threats out of scope, and trust boundaries for CloakMCP. It is intended for security reviewers, adopters, and contributors to understand what CloakMCP protects against and what it does not.

---

## Summary

CloakMCP is a **local-first anonymization layer** that protects secrets before they are shared with Large Language Models (LLMs) or external parties. It operates under the assumption that:

- **The local machine is trusted** (filesystem security, OS integrity).
- **The vault environment (`~/.cloakmcp/`) is secure** (proper permissions, encrypted at rest by OS if required).
- **Users follow operational best practices** (key management, backup procedures).
- **On Windows, NTFS ACLs replace POSIX permission bits** — CloakMCP applies best-effort permission hardening via `_safe_chmod()`, but cannot enforce POSIX semantics (see [Platform-Specific Security](#platform-specific-security)).

CloakMCP provides three layers of protection:

| Layer | Protection | Availability |
|-------|-----------|--------------|
| **Core CLI** | `cloak pack/unpack/scan` — deterministic HMAC-based secret replacement | Any LLM, any platform |
| **Claude Code hooks** | Automated session lifecycle (pack/unpack), guard-write, prompt-guard, safety-guard, audit | Claude Code only |
| **Vault hardening** | Encrypted backups (HKDF-derived keys), passphrase-wrapped keys (scrypt Tier 1) | Any workflow |

CloakMCP **does not** protect against:
- Compromised developer machines.
- Adversaries with physical or root access to the local system.
- Brute-force attacks by parties who already have access to vault keys.
- **Secret inference** — if the LLM can deduce, guess, or regenerate a secret from surrounding context.

---

## Trust Boundaries

### Trusted Zone
- **Local developer machine** (laptop, workstation).
- **Vault directory** (`~/.cloakmcp/keys/`, `~/.cloakmcp/vaults/`, `~/.cloakmcp/backups/`).
- **User's filesystem** (project directories).
- **Encryption keys** (stored locally in `~/.cloakmcp/keys/`, optionally passphrase-wrapped).

### Untrusted Zone
- **LLM providers** (Claude, Codex, Gemini, etc.) — honest-but-curious.
- **Public repositories** (GitHub, GitLab, Bitbucket) if packed code is accidentally pushed.
- **CI/CD systems** if packed code is shared.
- **Collaborators** who receive packed repositories without vault access.
- **LLM tool arguments and responses** — CloakMCP does not filter model output or tool inputs.

### Trust Boundary Line

The boundary is crossed when:
- A user runs `cloak pack` and the packed repository is **sent to an LLM**.
- Packed files are **committed to a public repository**.
- Packed files are **shared with unauthorized parties**.
- During a **Claude Code session**, the Anthropic API channel carries only tagged content (dried channel architecture — see `SECURITY.md`).

**After crossing the boundary:**
- Secrets are replaced by deterministic HMAC-based tags (e.g., `TAG-2f1a8e3c9b12`).
- Tags **cannot be reversed** without access to the vault and encryption key.
- LLMs and external parties see only opaque identifiers.

### Claude Code Session Boundary

Within a Claude Code session protected by CloakMCP hooks:

```
TRUSTED ZONE                              UNTRUSTED ZONE
┌─────────────────────────────────┐       ┌──────────────────────────┐
│  Local Machine                  │       │  Anthropic API           │
│                                 │       │                          │
│  ~/.cloakmcp/ (vault+keys)      │       │  Only sees TAG-xxxx      │
│  Project files (dried)          │ ──►   │  No cleartext secrets    │
│  .cloak-session-state           │       │  Dried conversation      │
│  .cloak-session-audit.jsonl     │       │                          │
│                                 │       │  Claude responses stay   │
│  SessionStart: pack             │       │  in tag-space            │
│  SessionEnd: unpack + verify    │       │                          │
└─────────────────────────────────┘       └──────────────────────────┘
```

---

## Threats In Scope

### T1. Accidental Secret Disclosure to LLMs

**Threat**: Developer accidentally shares unredacted code/config with an LLM, leaking API keys, credentials, PII.

**Mitigation**:
- CloakMCP **detects** secrets via configurable policy (regex, entropy, JWT, AWS keys, emails, IPs, URLs — 10 default rules, 26 in enterprise profile).
- CloakMCP **replaces** secrets with deterministic tags before sharing.
- Tags are HMAC-SHA256 with vault key (not reversible without vault).
- **Claude Code hooks** (v0.5.0+): `SessionStart` automatically packs the project directory; `SessionEnd` unpacks.
- **Prompt guard** (v0.5.1+): `UserPromptSubmit` hook blocks prompts containing critical/high-severity secrets.

**Residual Risk**: LOW
*Detection depends on policy completeness. Users must maintain up-to-date detection rules for new secret formats.*

---

### T2. Secret Leakage via Public Repositories

**Threat**: Developer accidentally commits unredacted secrets to GitHub/GitLab.

**Mitigation**:
- Use `cloak pack` before committing to replace secrets by tags.
- Add pre-commit hook invoking `cloak scan` to block commits with unredacted secrets.
- **Claude Code hooks** (v0.5.0+): automatic pack on session start prevents most accidental commits during AI-assisted sessions.
- **Guard-write hook** (v0.5.0+): `PreToolUse` blocks Write/Edit operations that would inject secrets into files.

**Residual Risk**: MEDIUM
*Users must remember to pack before committing outside of Claude Code sessions. CloakMCP does not enforce this automatically in non-hooked environments.*

---

### T3. Honest-But-Curious LLM Provider

**Threat**: LLM provider logs all inputs and attempts to extract secrets from context.

**Mitigation**:
- Tags are HMAC-based (keyed with vault key).
- Without vault access, provider sees only `TAG-xxxxxx` strings.
- Provider cannot reverse tags or correlate tags across sessions without vault key.
- **Dried-channel architecture** (v0.5.0+): the entire Claude Code conversation transcript operates in tag-space; secrets never transit through the Anthropic API in cleartext.
- **Policy pinning** (v0.9.0, G1): the pinned policy cannot be downgraded by LLM-initiated requests.

**Residual Risk**: LOW
*Assumes HMAC-SHA256 is computationally infeasible to brute-force. True for high-entropy secrets (AWS keys, JWTs). Lower entropy secrets (emails, IPs) still benefit from deterministic pseudonymization.*

---

### T4. Insider Threat (Unauthorized Collaborator)

**Threat**: Team member receives packed repository and attempts to reconstruct secrets.

**Mitigation**:
- Vault and keys are stored in `~/.cloakmcp/`, **not** in the project directory.
- Only users with explicit vault access can unpack.
- Vault is encrypted with Fernet (AES-128-CBC + HMAC).
- **Encrypted backups** (v0.10.0): backups stored as `.enc` files (tar.gz compressed, Fernet-encrypted with HKDF-derived subkey). Even if backup files are obtained, they cannot be read without the vault key.
- **Passphrase-wrapped keys** (v0.11.0, optional): key files can be encrypted at rest with a passphrase-derived wrapping key (scrypt, 128 MiB memory cost). An attacker who copies the key file but does not know the passphrase cannot decrypt it.
- **External backup storage** (v0.7.0): pre-redaction backups stored in `~/.cloakmcp/backups/` outside the project tree, preventing LLM tools from reading raw secrets during active sessions.

**Residual Risk**: LOW
*Assumes vault/key files are not shared via insecure channels. With Tier 1 key wrapping, risk is further reduced to passphrase compromise.*

---

### T5. Side-Channel Information Leakage

**Threat**: Attacker infers secret structure from tag patterns or code logic.

**Mitigation**:
- Tags are deterministic but reveal no information about secret content (HMAC output is cryptographically random).
- Code logic remains visible (e.g., `if API_KEY == TAG-xxxxx`), revealing intent but not value.
- **Same secret → same tag** everywhere in the codebase (consistency prevents correlation attacks based on tag variation).

**Residual Risk**: MEDIUM
*CloakMCP protects **content confidentiality**, not **intent semantics**. Adversary may infer "this is an API key" but cannot learn the key itself. See [Known Limitations: Secret Inference](#1-secret-inference) for details.*

---

### T6. Vault Corruption or Loss

**Threat**: Vault file corrupted, deleted, or lost; secrets unrecoverable.

**Mitigation**:
- CloakMCP provides `cloak vault-export` to create encrypted backups.
- **Automatic external backups** (v0.7.0+): `SessionStart` creates a pre-redaction backup in `~/.cloakmcp/backups/{slug}/{timestamp}.enc`.
- **Encrypted backups at rest** (v0.10.0): backups are Fernet-encrypted with an HKDF-derived subkey. Raw secrets are not readable even if backup files are obtained.
- **Backup lifecycle management** (v0.11.0): `cloak backup prune` removes old backups based on TTL and keep-last policy; `cloak backup migrate` converts legacy plaintext backups to encrypted format.
- **Session end cleanup** (v0.7.0+): backup removed after successful unpack to minimize exposure window.
- **Session manifest** (v0.5.1+): SHA-256 hashes at pack time enable integrity verification and delta detection at session end.
- **`cloak recover`** (v0.8.0+): restores from vault or backup after a crash.

**Residual Risk**: LOW (with backups), MEDIUM (without)
*Users must follow backup procedures. `cloak backup prune` prevents unbounded disk growth.*

---

### T7. Policy Manipulation / Downgrade

**Threat**: Attacker or compromised prompt tricks CloakMCP into using a weaker detection policy, allowing secrets to pass undetected.

**Mitigation** (v0.9.0, guardrails G1–G5):
- **G1 — Policy pinning**: SessionStart resolves the policy **once** and pins the path + SHA-256 hash in session state. All subsequent hook handlers use the pinned path, ignoring any runtime suggestions.
- **G4 — Downgrade protection**: `cloak policy use <new-policy>` detects when the new policy has fewer rules or lowered severity; requires `--force` to proceed.
- **G5 — MCP server isolation**: The 6 MCP tools do not accept a `policy_path` parameter. Policy is resolved and pinned at server startup. A compromised prompt cannot request a permissive policy.
- **G2 — Explicit mid-session changes only**: `cloak policy reload` requires explicit user action to change policy during a session.
- **G3 — Visibility + fail-closed**: SessionStart banner clearly reports ACTIVE/INACTIVE + policy hash. `CLOAK_FAIL_CLOSED=1` refuses to start unprotected sessions.

**Residual Risk**: LOW
*Requires physical access or pre-existing code execution on the developer's machine to substitute policy files outside of CloakMCP's control.*

---

### T8. Secret Re-injection During Claude Code Session

**Threat**: The LLM writes a secret value (from training data, hallucination, or user instruction) into a file during an active session.

**Mitigation**:
- **Guard-write hook** (v0.5.0+): `PreToolUse` handler scans the content of all Write/Edit operations for secrets matching the active policy. Critical/high-severity matches are blocked; medium/low produce warnings.
- **`CLOAK_STRICT=1`** (v0.5.1+): escalates medium-severity to blocking.
- **Repack-on-write** (v0.6.0+, opt-in): `CLOAK_REPACK_ON_WRITE=1` triggers `repack_file()` after each Write/Edit to re-tag any new secrets.

**Residual Risk**: MEDIUM
*Guard-write depends on policy completeness. If the secret format is not covered by detection rules, it will not be caught. Model responses and tool arguments are not filtered.*

---

### T9. Cross-Platform Permission Gaps (Windows)

**Threat**: On Windows, NTFS ACLs do not support POSIX permission bits. File permissions (`0o600`) that protect vault keys and backup files on Linux/macOS cannot be enforced.

**Mitigation** (v0.12.0):
- **`_safe_chmod()` guard**: All 12 `os.chmod()` call sites route through `_safe_chmod()`, which is a no-op on Windows. This prevents `PermissionError` or silently incorrect behavior.
- **`_verify_permissions()` guard**: Returns `False` on Windows without attempting to check or correct POSIX bits, avoiding spurious warnings from NTFS's arbitrary `st_mode` values.
- **Passphrase-wrapped keys (Tier 1)**: Provides defense-in-depth on Windows where filesystem permissions are weaker. A stolen key file cannot be used without the passphrase.

**Residual Risk**: MEDIUM (Windows), LOW (Linux/macOS)

*On Windows, vault security depends on:*
1. *NTFS ACLs being properly configured (user profile directory inheritance).*
2. *Full-disk encryption (BitLocker) for at-rest protection.*
3. *Tier 1 key wrapping (recommended for Windows) as compensation for weaker filesystem permission controls.*

*See [Platform-Specific Security](#platform-specific-security) for a detailed comparison.*

---

### T10. Backup Exfiltration via LLM Tools

**Threat**: During an active Claude Code session, the LLM uses Read/Grep/Glob tools to access pre-redaction backup files containing raw secrets.

**Mitigation** (v0.7.0+):
- **External backup storage**: Backups stored in `~/.cloakmcp/backups/` outside the project tree, not in `.cloak-backups/`.
- **Guard-read hook** (v0.7.0, hardened profile): `PreToolUse` handler for Read/Grep/Glob blocks access to sensitive paths (`.cloak-session-state`, `.cloak-session-manifest.json`, `.cloak-session-audit.jsonl`, `~/.cloakmcp/`).
- **Encrypted backups** (v0.10.0): even if backup files are somehow accessed, they are Fernet-encrypted and unreadable without the vault key.
- **Legacy backup warnings**: SessionStart and recovery detect in-tree `.cloak-backups/` directories and emit security warnings.

**Residual Risk**: LOW
*Defense-in-depth: external storage + guard-read + encryption. All three must be bypassed for exfiltration.*

---

## Threats Out of Scope

### 1. Compromised Developer Machine

**Threat**: Attacker gains root/admin access to developer's machine.

**Out of Scope**: CloakMCP assumes the local machine is trusted. If an attacker has root access:
- They can read `~/.cloakmcp/keys/` and decrypt vaults (unless Tier 1 key wrapping is enabled with a strong passphrase stored externally).
- They can intercept keystrokes, read memory, or install keyloggers.
- **No local-first tool can protect against this.**

**Recommendation**: Use full-disk encryption (BitLocker, FileVault, LUKS), strong OS passwords, and secure boot.

**Partial Mitigation** (v0.11.0): Tier 1 key wrapping with scrypt adds a layer. Attacker must know the passphrase even after obtaining the key file. This defends against offline key file theft but not against a live compromise where the passphrase is in memory.

---

### 2. Brute-Force Attacks with Vault Access

**Threat**: Attacker obtains both vault file and encryption key, attempts to brute-force HMAC tags.

**Out of Scope**: If attacker has both vault and key:
- They can decrypt the vault and read all secrets directly.
- Brute-forcing tags is unnecessary.

**Recommendation**: Protect `~/.cloakmcp/` with OS-level encryption and filesystem permissions (`0o600` on POSIX; NTFS ACLs + BitLocker on Windows).

---

### 3. Network-Based Attacks on Server Mode

**Threat**: Attacker exploits CloakMCP server over the network.

**Out of Scope**: CloakMCP server is designed for **localhost-only** use (`127.0.0.1`). Exposing it to LAN or internet:
- Transmits secrets over the network (defeats local-first model).
- Introduces network attack surface (DoS, token brute-force, RCE).

**Note**: The FastMCP server (`cloak serve`, v0.8.1+) supports stdio (default, no network), SSE, and streamable-http transports. Only stdio preserves the local-first security model.

**Recommendation**: **DO NOT expose server to untrusted networks.** If required, use TLS + VPN + firewall. See `SERVER.md` for comprehensive warnings.

---

### 4. Quantum Computing Attacks

**Threat**: Future quantum computers break AES-128 or SHA-256.

**Out of Scope**: CloakMCP uses:
- Fernet (AES-128-CBC + HMAC-SHA256): 64-bit quantum security (Grover's algorithm)
- SHA-256: 128-bit quantum security
- scrypt (Tier 1 key wrapping): resistant to quantum speedup

**Recommendation**: If quantum threat becomes imminent, CloakMCP can migrate to AES-256 (trivial vault re-encryption).

---

### 5. Detection Evasion by Adversary

**Threat**: Attacker crafts secret formats that bypass CloakMCP detection rules.

**Out of Scope**: CloakMCP detects secrets via regex, entropy, and heuristics. Adversary with knowledge of detection rules can:
- Obfuscate secrets (base64 encode, split across lines).
- Use non-standard formats.

**Recommendation**:
- Regularly update detection rules.
- Use the enterprise policy profile (26 rules) for broader coverage.
- Use entropy detectors to catch obfuscated secrets.
- Add custom rules for organization-specific secret formats.

---

### 6. Physical Security

**Threat**: Attacker steals developer's laptop and extracts secrets from disk.

**Out of Scope**: CloakMCP stores secrets in encrypted vaults, but keys are on disk.

**Partial Mitigation** (v0.11.0): Tier 1 key wrapping with a passphrase not stored on disk (memorized or in external password manager) protects against offline key theft.

**Recommendation**: Use full-disk encryption and strong OS passwords.

---

## Attack Scenarios

### Scenario 1: Honest Developer, Curious LLM

**Setup**: Developer uses CloakMCP correctly: packs repository, sends to Claude, unpacks locally.

**Attack**: Claude (or provider) logs all inputs and attempts to reconstruct secrets.

**Outcome**:
- **PROTECTED**: Claude sees only `TAG-xxxxxx` strings.
- Tags are HMAC-based (cannot reverse without vault key).
- Developer unpacks locally; secrets never leave machine.

**Result**: **Attack fails.**

---

### Scenario 2: Automatic Claude Code Session

**Setup**: Developer has `cloak install` hooks configured. Runs `claude` in project directory.

**Attack**: LLM provider logs all conversation turns, tool calls, and file reads.

**Outcome**:
- **PROTECTED**: `SessionStart` hook fires automatically, packs all files. LLM reads only tagged content.
- Prompt guard blocks accidental secret pasting. Guard-write blocks secret injection.
- `SessionEnd` restores secrets locally. The API transcript contains zero cleartext secrets.
- Policy pinning (G1) prevents prompt injection from downgrading protection.

**Result**: **Attack fails. Zero human intervention required.**

---

### Scenario 3: Accidental Public Commit

**Setup**: Developer forgets to pack, commits secrets to GitHub.

**Attack**: GitHub secret scanning detects AWS keys, notifies AWS, keys revoked.

**Outcome**:
- **NOT PROTECTED**: Secrets leaked to public repository.
- CloakMCP does not prevent this (user error outside a hooked session).

**Recommendation**: Add pre-commit hook: `cloak guard --policy examples/mcp_policy.yaml < staged_diff`

**Result**: **Attack succeeds (user error).**

---

### Scenario 4: Malicious Collaborator

**Setup**: Team member receives packed repository, no vault access.

**Attack**: Attempts to reverse tags by:
1. Brute-forcing HMAC (infeasible without vault key).
2. Correlating tags across multiple packed repositories (deterministic, but HMAC-protected).
3. Social engineering vault key from teammate.

**Outcome**:
- **PROTECTED** (attacks 1 & 2): HMAC prevents reversal.
- **NOT PROTECTED** (attack 3): Social engineering vault key succeeds.

**Additional protection** (v0.11.0): If Tier 1 key wrapping is enabled, the attacker needs both the key file **and** the passphrase.

**Result**: **Attack fails (unless social engineering succeeds).**

---

### Scenario 5: Compromised Developer Machine

**Setup**: Attacker gains root access via malware (keylogger, RAT).

**Attack**: Reads `~/.cloakmcp/keys/` and `~/.cloakmcp/vaults/`, decrypts all secrets.

**Outcome**:
- **NOT PROTECTED**: Local machine compromise defeats all local-first tools.
- **Partial mitigation** (v0.11.0): Tier 1 key wrapping requires passphrase knowledge. Attacker with file access but not passphrase is blocked (until they capture the passphrase from memory or keystrokes).

**Result**: **Attack succeeds (out of scope).**

---

### Scenario 6: Policy Downgrade via Prompt Injection

**Setup**: Attacker crafts a prompt that attempts to make the LLM call MCP tools with a permissive policy.

**Attack**: LLM calls `cloak_pack_dir` with `policy_path=/dev/null` (empty policy — no detections).

**Outcome**:
- **PROTECTED** (v0.9.0, G5): MCP tools do not accept a `policy_path` parameter. Policy is pinned at server startup.
- Even if the LLM attempts to pass the parameter, it is ignored.

**Result**: **Attack fails.**

---

### Scenario 7: Windows Key File Theft

**Setup**: Windows developer uses CloakMCP. Attacker copies `~/.cloakmcp/keys/slug.key` from the machine (e.g., via a shared folder misconfiguration or USB access).

**Attack**: Uses the key file to decrypt vault contents.

**Outcome (Tier 0 — raw key)**:
- **NOT PROTECTED**: The key file is a raw Fernet key. Attacker decrypts vault directly.

**Outcome (Tier 1 — passphrase-wrapped key)**:
- **PROTECTED**: The key file is encrypted with scrypt (128 MiB memory cost). Attacker must brute-force the passphrase.
- With a strong passphrase (20+ characters), brute-force cost is prohibitive.

**Recommendation**: On Windows, always enable Tier 1 key wrapping (`CLOAK_PASSPHRASE`).

**Result**: **Depends on key wrapping tier.**

---

## Cryptographic Guarantees

### Vault Encryption

- **Algorithm**: Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation**: Random 32-byte key (256-bit entropy)
- **Authentication**: HMAC-SHA256 prevents tampering
- **Security Level**: 128-bit symmetric security (NIST approved through 2030+)

**Guarantees**:
- Vault contents confidential (AES-128).
- Vault integrity protected (HMAC-SHA256).
- No tampering possible without key.

**Assumptions**:
- Vault key stored securely (filesystem permissions `0o600` on POSIX, NTFS ACLs on Windows).
- No key leakage via logs, environment variables, or insecure channels.

---

### Tag Generation

- **Algorithm**: HMAC-SHA256 (keyed with vault encryption key)
- **Output**: Truncated to 12 hex characters (48-bit space)
- **Collision Probability**: ~1 in 16 million per vault

**Guarantees**:
- Tags deterministic (same secret → same tag).
- Tags cryptographically random (HMAC output indistinguishable from random).
- Tags non-reversible without vault key.

**Assumptions**:
- Vault key not leaked.
- HMAC-SHA256 remains secure (no practical pre-image attacks).

---

### Backup Encryption (v0.10.0)

- **Key Derivation**: HKDF-SHA256 from vault Fernet key
  - `salt = b"cloakmcp-backup"` (domain separation)
  - `info = project_slug` (per-project isolation)
- **Encryption**: Fernet (AES-128-CBC + HMAC-SHA256) on gzip-compressed tar archive
- **Atomicity**: Atomic write with `0o600` permissions

**Guarantees**:
- Backup contents confidential — not readable with standard tools (`cat`, `grep`, etc.).
- **Key separation**: vault compromise does not expose backup contents, and vice versa (HKDF domain separation).
- Integrity protected (Fernet HMAC).

**Assumptions**:
- Vault key not leaked (backups are derived from same root key).

---

### Key Wrapping — Tier 1 (v0.11.0)

- **Algorithm**: scrypt → Fernet
  - `n = 2^17` (~128 MiB memory), `r = 8`, `p = 1`
  - 32-byte random salt per key file
- **Format**: `CLOAKKEY1\n<salt_hex>\n<fernet_encrypted_key>\n`
- **Derivation Cost**: ~0.5s per attempt, 128 MiB RAM required

**Guarantees**:
- Key file encrypted at rest — unreadable without passphrase.
- Memory-hard: resists GPU-based brute-force (128 MiB per thread).
- Salt prevents precomputation.
- Auto-detected on load (raw Tier 0 and wrapped Tier 1 coexist).

**Assumptions**:
- Passphrase has sufficient entropy (recommended: 20+ characters or diceware phrase).
- Passphrase not stored on the same machine as the key file.

---

## Platform-Specific Security

### POSIX (Linux / macOS)

CloakMCP enforces strict file permissions via `os.chmod()`:

| Resource | Permission | Effect |
|----------|-----------|--------|
| `~/.cloakmcp/` | `0o700` | Owner-only directory access |
| `~/.cloakmcp/keys/*.key` | `0o600` | Owner-only read/write |
| `~/.cloakmcp/vaults/*.vault` | `0o600` | Owner-only read/write |
| `~/.cloakmcp/backups/*.enc` | `0o600` | Owner-only read/write |

**`_verify_permissions()`** checks and auto-corrects permissions on every key access. If permissions were wrong (indicating external tampering or manual change), a warning is printed to stderr:

```
[CloakMCP] WARNING: Permissions on /home/user/.cloakmcp/keys/abc123.key were 0o644, corrected to 0o600.
```

**Security level**: HIGH — filesystem permissions are enforced by the kernel.

### Windows (NTFS)

NTFS does not use POSIX permission bits. The `st_mode` field returned by `os.stat()` on Windows returns arbitrary values that do not reflect actual access control. Calling `os.chmod()` on Windows has limited effect:
- It can toggle the read-only attribute, but **cannot set owner-only access**.
- NTFS access control is managed through ACLs (Access Control Lists), which require the `win32security` API or `icacls` commands.

**CloakMCP's approach** (v0.12.0):

| Function | Behavior on Windows |
|----------|-------------------|
| `_safe_chmod(path, 0o600)` | **No-op** — returns immediately without calling `os.chmod()` |
| `_verify_permissions(path, 0o600)` | Returns `False` — skips all POSIX permission checks |
| `_ensure_dirs()` | Creates directories but does not set permissions |

**Security level**: MEDIUM — relies on Windows defaults:

1. **User profile inheritance**: `~/.cloakmcp/` inherits ACLs from the user's home directory (`C:\Users\<username>\`), which by default grants access only to the owner and `SYSTEM`.
2. **No multi-user isolation guarantee**: If the Windows machine has weak ACL defaults (shared folders, relaxed inheritance), vault files may be accessible to other local users.

### Windows Hardening Recommendations

For Windows deployments, compensate for the permission gap:

| Measure | Protection | How |
|---------|-----------|-----|
| **Tier 1 key wrapping** | At-rest key encryption | `export CLOAK_PASSPHRASE=<strong-passphrase>` then `cloak key wrap` |
| **BitLocker** | Full-disk encryption | Windows Settings → Device encryption |
| **Explicit ACLs** | Owner-only access | `icacls %USERPROFILE%\.cloakmcp /inheritance:r /grant:r %USERNAME%:F` |
| **Windows Credential Manager** | Passphrase storage | Store `CLOAK_PASSPHRASE` in Credential Manager instead of plaintext env var |

**Minimum recommended configuration for Windows**: Tier 1 key wrapping + BitLocker.

---

## Operational Assumptions

### Users Will:
1. **Pack before sharing**: Run `cloak pack` before sending code to LLMs (or use Claude Code hooks for automation).
2. **Secure vault**: Keep `~/.cloakmcp/` with strict permissions (`0o600` for keys on POSIX; ACLs + BitLocker on Windows).
3. **Backup vault**: Regularly export vaults (`cloak vault-export`) and store backups securely.
4. **Manage backups**: Run `cloak backup prune` periodically to clean old backups.
5. **Update policies**: Maintain up-to-date detection rules for new secret formats.
6. **Use hooks on Claude Code**: Install hooks (`cloak install`) for automatic protection.
7. **Enable Tier 1 on Windows**: Use passphrase-wrapped keys as compensation for weaker filesystem permissions.

### Users Will Not:
1. **Share vault keys**: Never commit keys to repos, share via email/Slack, or log to files.
2. **Expose server**: Never run CloakMCP server with network-facing transport on untrusted networks.
3. **Ignore warnings**: Heed dry-run previews, backup recommendations, and policy downgrade alerts.
4. **Bypass hooks**: Never use `--no-verify` or similar mechanisms to skip hook execution.

---

## Known Limitations

### 1. Secret Inference

CloakMCP prevents **exfiltration** of secrets from disk to the LLM API channel. It does **not** and **cannot** prevent **inference** — if the LLM can deduce, guess, or regenerate a secret from surrounding context, structure, or naming patterns.

Examples:
- `DB_PASSWORD = TAG-xxxxx` next to `DB_HOST = prod-db.company.com` reveals the secret's purpose and target.
- `.env.example` with `STRIPE_SECRET_KEY=sk_test_...` reveals provider and format.
- Commit messages or comments describing what a secret does.

**Mitigation (user responsibility)**:
- Use generic variable names when sharing with LLMs.
- Use `cloak pack --prefix SEC` with context-free prefixes.
- Review packed output before sharing: `cloak scan --dry-run`.

| Threat | CloakMCP Coverage |
|--------|-------------------|
| Raw secret in source file | **Protected** |
| Secret pasted in prompt | **Mitigated** (prompt-guard hook) |
| LLM guesses secret from context | **Not covered** |
| Secret embedded in filenames | **Not covered** |
| Secret in tool arguments | **Not covered** |

---

### 2. Policy Completeness

Detection depends on regex/entropy rules. New secret formats may not be detected.

**Mitigation**: Use the enterprise policy (26 rules). Add custom rules for organization-specific formats. Contribute new detectors to the project.

---

### 3. False Positives / Negatives

Regex detectors may match non-secrets (e.g., version numbers matching JWT pattern). Entropy detectors may miss structured low-entropy secrets.

**Mitigation**: Use `cloak scan --dry-run` to preview. Tune policy thresholds. Use whitelists (`whitelist`, `whitelist_patterns`) for known false positives.

---

### 4. Intent Semantics

CloakMCP hides **values**, not **logic**. Code like `if API_KEY == TAG-xxxxx` reveals intent but not the key.

**Mitigation**: Accept this trade-off. Semantic obfuscation is out of scope.

---

### 5. Vault Portability

Vaults are per-project (based on absolute path hash). Moving a project directory breaks vault linkage.

**Mitigation**: Use `cloak vault-export` before moving. After moving, use `cloak vault-import` to restore.

---

### 6. Windows Permission Enforcement

On Windows, `os.chmod()` cannot set POSIX-style owner-only permissions. CloakMCP's `_safe_chmod()` is a no-op on Windows. Vault key files may be accessible to other local users unless NTFS ACLs are explicitly configured.

**Mitigation**: Enable Tier 1 key wrapping. Use BitLocker for full-disk encryption. Apply explicit ACLs via `icacls`. See [Platform-Specific Security](#platform-specific-security).

---

### 7. Model Response Filtering

CloakMCP does not filter LLM responses or tool arguments. If the LLM generates, hallucinates, or reconstructs a secret value in its output, it will appear in the conversation transcript.

**Mitigation**: The guard-write hook catches secrets in Write/Edit operations. Conversation transcript filtering is architecturally infeasible (see dried-channel discussion in `SECURITY.md`).

---

### 8. Demo Scripts Are Unix-Only

The `demo/` directory contains 4 bash scripts (`llm_demo.sh`, `mcp_demo.sh`, `transcript.sh`, `run_demo.sh`) that require bash and are not supported on Windows. The underlying `cloak` CLI commands work on all platforms.

---

## Compliance Notes

### GDPR / PII

CloakMCP can redact PII (emails, IP addresses, names) using policy rules. However:
- CloakMCP does not classify data automatically (user must configure detection rules).
- CloakMCP does not log PII to audit logs (only SHA-256 hashes).
- **Encrypted backups** (v0.10.0) ensure that backup copies of PII are not readable without the vault key.

**Recommendation**: Add organization-specific PII patterns to policy.

---

### SOC 2 / ISO 27001

CloakMCP supports security controls:
- **Access Control**: Vault keys separate from project data. Optional passphrase wrapping (Tier 1).
- **Audit Logging**: All detections logged to `audit/audit.jsonl` (CLI) and `.cloak-session-audit.jsonl` (hooks). Session manifest provides file-level integrity tracking.
- **Encryption at Rest**: Vault encrypted with Fernet (AES-128). Backups encrypted with HKDF-derived key. Keys optionally wrapped with scrypt.
- **Policy Management**: Auditable policy resolution chain with pinning, downgrade protection, and fail-closed mode.

**Recommendation**: Document CloakMCP usage in security policies. Implement key rotation procedures. Enable `CLOAK_FAIL_CLOSED=1` for regulated environments.

---

### NIST / FIPS

CloakMCP uses NIST-approved algorithms:
- AES-128-CBC (FIPS 197)
- HMAC-SHA256 (FIPS 198-1)
- scrypt (NIST SP 800-132 compliant key derivation)
- HKDF-SHA256 (NIST SP 800-56C)

**Limitation**: Fernet implementation (`cryptography.io`) is not FIPS-validated.

**Recommendation**: For FIPS compliance, replace Fernet with FIPS-validated library (e.g., OpenSSL FIPS module).

---

## Version History of Security Features

| Version | Feature | Category |
|---------|---------|----------|
| 0.3.0 | HMAC-SHA256 tags, vault `0o600` permissions | Core |
| 0.3.2 | Group policy inheritance | Policy |
| 0.5.0 | Claude Code hooks (session, guard-write), MCP server | Automation |
| 0.5.1 | Prompt guard, safety guard, session manifest, `CLOAK_STRICT` | Hooks |
| 0.6.0 | Tag idempotency, enterprise policy (26 rules), repack | Detection |
| 0.7.0 | External backup storage, guard-read hook, backup exfiltration fix | Storage |
| 0.8.1 | JWT false positive fix, FastMCP server | Detection, MCP |
| 0.9.0 | Policy pinning (G1), downgrade protection (G4), MCP isolation (G5), fail-closed (G3) | Policy |
| 0.10.0 | Encrypted backups (HKDF), permission hardening | Storage |
| 0.11.0 | Passphrase-wrapped keys (scrypt Tier 1), backup lifecycle (migrate, prune) | Keys |
| 0.12.0 | Cross-platform hooks, `_safe_chmod()`, Windows guards, UTF-8 stdin/stdout | Platform |

---

## References

- **Fernet Specification**: https://github.com/fernet/spec/blob/master/Spec.md
- **NIST Cryptographic Standards**: https://csrc.nist.gov/publications
- **NIST SP 800-132** (password-based key derivation): https://csrc.nist.gov/pubs/sp/800/132/final
- **NIST SP 800-56C** (HKDF): https://csrc.nist.gov/pubs/sp/800/56c/r2/final
- **OWASP Secrets Management**: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- **CloakMCP GitHub**: https://github.com/ovitrac/CloakMCP
- **CloakMCP Security Policy**: [`../SECURITY.md`](../SECURITY.md)
- **CloakMCP Documentation**: [`QUICKSTART.md`](QUICKSTART.md), [`QUICKREF.md`](QUICKREF.md), [`SERVER.md`](SERVER.md)

---

## Contact

For security issues, please email: `olivier.vitrac@adservio.com` (PGP key available on request).

For general questions, open a GitHub issue: https://github.com/ovitrac/CloakMCP/issues

---

**Last Updated**: 2026-02-26
**Version**: 0.12.0
**Author**: Olivier Vitrac (Adservio Innovation Lab)
