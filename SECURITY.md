# Security Policy

**Local-first:** Do not expose any service publicly by default.

## Reporting a vulnerability
Open a private issue or email the maintainers (without real secrets). Provide version, OS, Python version, and steps to reproduce.

## Scope of this document

CloakMCP's core CLI (`cloak pack/unpack/scan/sanitize`) is **LLM-agnostic** — it works with any LLM. The security properties of the vault (encryption, HMAC-based tags, local-only storage) apply universally regardless of which LLM you use.

This document additionally describes the security model of the **Claude Code integration**, which uses Claude Code hooks (`SessionStart`, `SessionEnd`, `PreToolUse`, `UserPromptSubmit`) to automate secret protection within Claude Code sessions. The hook-based protections described below (guard-write, safety-guard, prompt-guard, dried-channel architecture) are **specific to the Claude Code integration** and require the hooks to be installed via `cloak install` (or the legacy `bash "$(cloak scripts-path)/install_claude.sh"`).

## Protection scope

### Core protection (any LLM)

- Files are packed (secrets replaced by tags) before the LLM reads them, via `cloak pack`.
- Vault encryption (Fernet AES-128) and HMAC-based tags ensure secrets cannot be recovered without the local key.
- Unpacking (`cloak unpack`) restores secrets locally after LLM work is complete.

### Claude Code hook protection

The following protections require the Claude Code hooks to be installed:

- **Session lifecycle**: `SessionStart` hook packs files automatically; `SessionEnd` hook unpacks.
- **Write/Edit guard**: `PreToolUse` hook blocks Write/Edit operations containing high-severity secrets (PEM keys, AWS keys).
- **Safety guard**: `PreToolUse` hook blocks dangerous Bash commands (`rm -rf /`, `git push --force`, etc.).
- **Prompt guard**: `UserPromptSubmit` hook scans every user prompt — critical/high secrets block the prompt; medium/low produce a warning.
- Model responses and tool arguments are NOT filtered — do not embed secrets in filenames or tool inputs.

## Dried-channel architecture (Claude Code integration)

Within a Claude Code session protected by CloakMCP hooks, the Anthropic API channel is a **dried channel**. Rehydration happens only locally, only on disk, only at session boundaries or on explicit user command.

### Why the conversation stays dried

Claude Code has a `Stop` hook (fires when Claude finishes responding), but it provides no mechanism to rewrite Claude's text output — the response is already streamed to the user. There is no output-side transform hook.

But the deeper reason is architectural, not technical. The conversation transcript is cumulative: every new API call sends the full history. If CloakMCP were to rehydrate Claude's output before display, a split would emerge:

- **What the user sees**: rehydrated (cleartext secrets)
- **What the API receives on the next turn**: the original dried response (tags)

The moment the user quotes or refers to a rehydrated value in their next prompt, raw secrets re-enter the API channel. The `UserPromptSubmit` hook would then have to re-dry the prompt, building a full bidirectional proxy on the conversation — with all the fragility that entails (partial matches, broken context, tag-inside-tag nesting).

Keeping everything dried avoids this entirely. The security invariant is clean:

> **Secrets never transit through the Anthropic API in cleartext. The conversation operates entirely in tag-space.**

This is consistent with how `pack_dir` / `unpack_dir` already works: the LLM workspace is a dried projection of the real workspace. The conversation is just another surface of that same projection.

### Domain state summary

| Domain | State | Mechanism |
|--------|-------|-----------|
| Files on disk (during session) | Dried | `pack_dir` at `SessionStart` |
| Files on disk (after session) | Rehydrated | `unpack_dir` at `SessionEnd` |
| User prompts | Blocked if raw secrets detected | `UserPromptSubmit` hook |
| Claude's responses | Dried (tags visible) | No output hook; consistent security boundary |
| Conversation transcript | Dried | Never contains cleartext secrets |
| Local reading | Rehydrated on demand | `cloak rehydrate-transcript` (offline, planned) |

### UX cost and mitigation

The user sees `TAG-a1b2c3d4e5f6` instead of the actual credential value in Claude's responses. In practice this is less disruptive than it sounds:

1. **Claude rarely needs to display a secret** — it manipulates files, writes configs, runs commands. File-level rehydration at `SessionEnd` handles the real output.
2. **When Claude references a secret in conversation** (e.g., "I used `TAG-a1b2c3d4e5f6` in the config"), the user can mentally map it or run `cloak unpack-text` locally.
3. **A local display helper** (`cloak rehydrate-transcript`) can post-process the conversation log (`.jsonl` transcript) for human reading — offline, never sent to the API.

### Context window and compaction

Claude Code compacts long conversations via internal summarization. The compacted summary stays dried. If Claude carries forward "the AWS key is `TAG-a1b2c3d4e5f6`", that is safe — the tag is opaque to anyone reading the transcript or to Anthropic's servers. The secret only materializes on disk, locally, at unpack time.

## Post-session verification (Claude Code hooks)

At `SessionEnd`, the CloakMCP hook performs two automatic checks:

1. **Tag residue scan (R4)**: Rescans all files for remaining `TAG-xxxxxxxxxxxx` patterns. Any tags not found in the vault are reported as *unresolvable* — these may come from another project or a corrupted state. Run `cloak verify --dir .` manually at any time.

2. **Session manifest delta (R5)**: At `SessionStart`, a manifest records the SHA-256 hash of every file in the project. At `SessionEnd`, CloakMCP compares the current state against this snapshot and reports:
   - **New files** created during the session
   - **Deleted files** removed during the session
   - **Changed files** modified during the session
   - **Unchanged files** for completeness

Both results are written to the session audit log (`.cloak-session-audit.jsonl`). This turns "it should be fine" into provable evidence of what happened during each session.

## Fundamental limitations

These limitations apply universally, regardless of which LLM is used or whether Claude Code hooks are installed.

### Secret inference (non-fixable)

CloakMCP prevents **exfiltration** of secrets from disk to the LLM API channel. It does **not** and **cannot** prevent **inference** — if the LLM can deduce, guess, or regenerate a secret from surrounding context, structure, or naming patterns.

Examples of inference risks:
- A variable named `DB_PASSWORD` with value `TAG-xxxx` next to `DB_HOST=prod-db.company.com` lets the LLM infer *what kind* of secret it is and where it connects.
- A `.env.example` with `STRIPE_SECRET_KEY=sk_test_...` reveals the provider and key format.
- Commit messages or comments describing what a secret does.

**Mitigation (user responsibility):**
- Avoid descriptive variable names adjacent to secrets when sharing with LLMs.
- Use `pack --prefix SEC` with generic prefixes.
- Review packed output before sharing: `cloak pack --dry-run --dir .`

CloakMCP's threat model covers **exfiltration**, not **inference**. The distinction is:

| Threat | CloakMCP coverage | Example |
|--------|-------------------|---------|
| Raw secret in source file | **Protected** | AWS key in code → replaced by tag |
| Secret pasted in prompt | **Mitigated** (Claude Code prompt-guard hook only) | User types API key → prompt blocked |
| LLM guesses secret from context | **Not covered** | LLM infers "password is company name" |
| Secret embedded in filenames | **Not covered** | File named `aws_AKIAEXAMPLE.conf` |
| Secret in tool arguments | **Not covered** | Secret passed as CLI argument |

## Policy configuration

### Resolution chain

CloakMCP uses a prioritized resolution chain to find the active policy:

| Priority | Source | Who sets it |
|----------|--------|-------------|
| 1 | Explicit `--policy` CLI flag | Operator (command line) |
| 2 | `CLOAK_POLICY` environment variable | Operator (shell/CI) |
| 3 | `.cloak/policy.yaml` (per-project) | Operator (`cloak policy use`) |
| 4 | `examples/mcp_policy.yaml` (development fallback) | Repository default |
| 5 | Fail: error or empty (see fail-closed mode) | — |

### Policy pinning (G1)

At `SessionStart`, the hook resolves the policy **once** and pins the path + SHA-256 hash in the session state marker. All subsequent hook handlers (guard-write, prompt-guard, audit-log) use the **pinned policy path**, ignoring any incoming suggestions. This prevents policy drift during a session.

### Choosing a policy

| Profile | File | Rules | Coverage |
|---------|------|-------|----------|
| Default | `mcp_policy.yaml` | 10 | AWS, GCP, SSH, PEM, JWT, email, IP, URL, entropy |
| Enterprise | `mcp_policy_enterprise.yaml` | 26 | Default + GitHub, GitLab, Slack, Stripe, npm, etc. |
| Custom | Your own YAML | N | Inherit from default or enterprise, add project rules |

### Setting the policy

```bash
# Per-project (recommended for pip-installed CloakMCP):
cloak policy use examples/mcp_policy.yaml         # copy to .cloak/policy.yaml
cloak policy use --link examples/mcp_policy.yaml   # symlink
cloak policy use --show                            # view active policy + hash
cloak policy use --clear                           # remove per-project policy

# Via environment:
export CLOAK_POLICY=/path/to/policy.yaml

# Via installer (cross-platform):
cloak install --policy examples/mcp_policy.yaml

# MCP server (auto-discovers .cloak/policy.yaml):
cloak serve
```

### Fail-closed mode (G3)

By default, CloakMCP fails open: if no policy is found, guards are inactive and the session proceeds unprotected (with a visible banner). For regulated environments:

```bash
export CLOAK_FAIL_CLOSED=1
```

With `CLOAK_FAIL_CLOSED=1`:
- `SessionStart` refuses to start without a policy
- Guard-write denies all writes if no policy is available
- The `find_policy()` resolver raises instead of returning empty

### Downgrade protection (G4)

When running `cloak policy use <new-policy>` and a `.cloak/policy.yaml` already exists:
1. Both policies are loaded and compared
2. A **downgrade** is detected if the new policy has fewer rules or any rule's severity is lowered
3. If downgrade detected: warning printed, `--force` required to proceed
4. A `policy_downgrade` audit event is logged

### MCP server isolation (G5)

The 6 MCP tools (`cloak_scan_text`, `cloak_pack_text`, etc.) do **not** accept a `policy_path` parameter. The policy is resolved and pinned at server startup. This prevents a compromised prompt from downgrading protection by requesting a permissive policy.

The `--allow-policy-override` flag (default off) restores the old behavior for controlled environments that need per-call policy selection.

### Mid-session policy changes (G2)

By default, policy changes take effect at the **next session**. To apply a change mid-session:

```bash
cloak policy reload --dir .
```

This re-resolves the policy, updates the pinned hash in session state, prints the old → new diff, and logs a `policy_reload` audit event.

### Third-party integration

When CloakMCP is pip-installed into another project (e.g., a toolbox), the development fallback (`examples/mcp_policy.yaml`) does not exist. Projects must anchor a policy:

```bash
cloak policy use "$(python3 -c "
import cloakmcp, os
print(os.path.join(os.path.dirname(cloakmcp.__file__),
      '..', 'examples', 'mcp_policy.yaml'))
")"
```

Or ship a custom policy and use `cloak policy use <custom-policy.yaml>`.

### Visibility (G3)

The `SessionStart` banner always reports the policy state:
- **ACTIVE**: `Guard ACTIVE: policy=<path> (N rules, sha256=<hash>)`
- **INACTIVE**: `Guard INACTIVE: no policy found (writes not protected)`

Use `cloak policy use --show` at any time to verify the active policy.

## Vault and key security

### Permission model

CloakMCP protects vault keys and backup files with filesystem permissions:

| Resource | POSIX (Linux/macOS) | Windows (NTFS) |
|----------|-------------------|----------------|
| `~/.cloakmcp/` | `0o700` (owner-only) | Inherits user profile ACLs |
| `~/.cloakmcp/keys/*.key` | `0o600` (owner read/write) | **Not enforced** — see below |
| `~/.cloakmcp/vaults/*.vault` | `0o600` (owner read/write) | **Not enforced** — see below |
| `~/.cloakmcp/backups/*.enc` | `0o600` (owner read/write) | **Not enforced** — see below |

### POSIX permission enforcement

On Linux and macOS, CloakMCP calls `os.chmod()` to set strict permissions on every key and vault file. The `_verify_permissions()` function checks and auto-corrects permissions on every key access. If permissions were wrong (indicating external tampering or manual change), a warning is printed:

```
[CloakMCP] WARNING: Permissions on ~/.cloakmcp/keys/abc123.key were 0o644, corrected to 0o600.
```

### Windows limitation: `0o600` cannot be enforced

**NTFS does not support POSIX permission bits.** The `st_mode` field returned by `os.stat()` on Windows returns arbitrary values unrelated to actual access control. Calling `os.chmod()` on Windows:
- Can only toggle the **read-only** attribute
- **Cannot** set owner-only access
- **Cannot** restrict access to the current user

CloakMCP handles this explicitly (v0.12.0):

| Function | Behavior on Windows |
|----------|-------------------|
| `_safe_chmod(path, 0o600)` | **No-op** — returns immediately |
| `_verify_permissions(path, 0o600)` | Returns `False` — skips all checks |
| `_ensure_dirs()` | Creates directories without permission setting |

This means that on Windows, vault keys rely on **NTFS ACL inheritance** from the user's home directory (`C:\Users\<username>\`) for access control. By default, this grants access only to the owner and `SYSTEM`, but this is not guaranteed on all Windows configurations (domain-joined machines, shared profiles, relaxed inheritance).

### Compensating controls for Windows

| Measure | Purpose | How |
|---------|---------|-----|
| **Tier 1 key wrapping** | Encrypt keys at rest with a passphrase | `CLOAK_PASSPHRASE=... cloak key wrap` |
| **BitLocker** | Full-disk encryption | Windows Settings → Device encryption |
| **Explicit NTFS ACLs** | Owner-only access on vault directory | `icacls %USERPROFILE%\.cloakmcp /inheritance:r /grant:r %USERNAME%:F` |
| **Windows Credential Manager** | Avoid storing passphrase in env var | Store `CLOAK_PASSPHRASE` in Credential Manager |

**Minimum recommended configuration for Windows**: Tier 1 key wrapping + BitLocker.

For a comprehensive analysis, see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — sections *Platform-Specific Security* and *T9. Cross-Platform Permission Gaps*.

### Encrypted backups

Since v0.10.0, backups are stored as encrypted `.enc` files using an HKDF-SHA256–derived subkey (separate from the vault encryption key). This ensures:
- Backup contents are not readable with standard tools (`cat`, `grep`, `strings`)
- Vault compromise does not expose backup contents (HKDF domain separation)
- Backup files at `~/.cloakmcp/backups/` are encrypted at rest regardless of filesystem permissions

Legacy plaintext backups can be migrated: `cloak backup migrate --apply`.

### Passphrase-wrapped keys (Tier 1)

Since v0.11.0, key files can be encrypted at rest using a passphrase-derived wrapping key:
- **Algorithm**: scrypt (n=2^17, r=8, p=1 — 128 MiB memory cost, ~0.5s per derivation)
- **Format**: `CLOAKKEY1\n<salt_hex>\n<fernet_encrypted_key>\n`
- **Auto-detection**: CloakMCP detects raw (Tier 0) and wrapped (Tier 1) key formats transparently

This is the **recommended defense-in-depth measure for Windows**, where filesystem permissions cannot isolate vault keys from other local users.

## Operating recommendations

### General
- Keep `keys/` outside version control, strict permissions.
- Tune your policy before use; prefer `block`/`redact` for new detectors.
- Run `mypy`, `black`, `bandit`, `pip-audit` locally before releases.

### Windows-specific
- Enable Tier 1 key wrapping: `export CLOAK_PASSPHRASE=<strong-passphrase> && cloak key wrap`.
- Enable BitLocker for full-disk encryption.
- Consider explicit NTFS ACLs: `icacls %USERPROFILE%\.cloakmcp /inheritance:r /grant:r %USERNAME%:F`.
- Store `CLOAK_PASSPHRASE` in Windows Credential Manager rather than plaintext environment variables.

### Backup hygiene
- Run `cloak backup prune --ttl 30d --keep-last 10 --apply` periodically.
- Migrate legacy plaintext backups: `cloak backup migrate --apply`.
- Verify backup integrity: `cloak vault-export` creates independent encrypted exports.
