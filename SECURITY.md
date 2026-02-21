# Security Policy

**Local-first:** Do not expose any service publicly by default.

## Reporting a vulnerability
Open a private issue or email the maintainers (without real secrets). Provide version, OS, Python version, and steps to reproduce.

## Scope of this document

CloakMCP's core CLI (`cloak pack/unpack/scan/sanitize`) is **LLM-agnostic** — it works with any LLM. The security properties of the vault (encryption, HMAC-based tags, local-only storage) apply universally regardless of which LLM you use.

This document additionally describes the security model of the **Claude Code integration**, which uses Claude Code hooks (`SessionStart`, `SessionEnd`, `PreToolUse`, `UserPromptSubmit`) to automate secret protection within Claude Code sessions. The hook-based protections described below (guard-write, safety-guard, prompt-guard, dried-channel architecture) are **specific to the Claude Code integration** and require the hooks to be installed via `scripts/install_claude.sh`.

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

## Operating recommendations
- Keep `keys/` outside version control, strict permissions.
- Tune your policy before use; prefer `block`/`redact` for new detectors.
- Run `mypy`, `black`, `bandit`, `pip-audit` locally before releases.
