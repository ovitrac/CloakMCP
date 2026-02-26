# Changelog

All notable changes to CloakMCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.1] - 2026-02-26

### Documentation
- **THREAT_MODEL.md** rewritten for v0.12.0 (456 → 760 lines): 10 in-scope threats (T1–T10),
  6 out-of-scope, 7 attack scenarios, platform-specific security section (POSIX vs Windows),
  cryptographic guarantees (vault, tags, HKDF backups, scrypt Tier 1), security version history
- **SECURITY.md**: added vault/key security section documenting Windows `0o600` limitation,
  `_safe_chmod()` no-op behavior, compensating controls (Tier 1 + BitLocker + NTFS ACLs),
  encrypted backup details, operating recommendations split (general / Windows / backup hygiene)

## [0.12.0] - 2026-02-26

### Added
- **Cross-platform hooks**: All 7 hook scripts now ship as both `.sh` (POSIX) and `.py` (Python)
  in `scripts/hooks/`. Settings templates use `cloak hook <event>` CLI commands instead of `.sh`
  file paths — works on Windows without Git Bash
- **`cloak install`** command: Pure-Python installer replaces `install_claude.sh` as the primary
  hook installation method. Supports `--profile`, `--method cli|copy|symlink`, `--policy`,
  `--dry-run`, `--uninstall`. Cross-platform (no bash dependency)
- **`cloak hooks-path`** command: Toolbox discovery contract — returns path to bundled hook scripts
  in requested format (`--format sh|py|cli`). Enables AdservioToolbox to select OS-appropriate
  hook scripts at install time
- **`cloak doctor`** command: Installation health check reporting platform, Python version, CLI
  availability, hook method, policy status, and vault state
- **`python -m cloakmcp.hooks <event>`**: Fallback entrypoint when `cloak` is not in PATH
- CLI-based settings templates (`hooks-cli.json`, `hooks-cli-hardened.json`) that reference
  `cloak hook <event>` commands instead of `.sh` file paths

### Changed
- **hooks.py → hooks/ package**: `cloakmcp/hooks.py` converted to `cloakmcp/hooks/__init__.py` +
  `__main__.py` package. All existing imports (`from cloakmcp.hooks import ...`) continue to work
- **`_safe_chmod()` platform guard**: All 12 `os.chmod()` calls in `storage.py` and `dirpack.py`
  now route through `_safe_chmod()` which is a no-op on Windows (NTFS uses ACLs, not POSIX bits)
- **`_verify_permissions()` Windows guard**: Skipped on Windows to avoid spurious warnings from
  POSIX mode bit checks on NTFS filesystems
- **`_read_stdin_json()` / `_emit_json()` UTF-8 safety**: On Windows, reads stdin via
  `sys.stdin.buffer` and writes stdout via `sys.stdout.buffer` to bypass codepage encoding issues
- Default hook installation method changed from `.sh` wrappers to `cloak hook <event>` CLI commands

### Fixed
- Lazy import `from .dirpack import repack_file` in hooks module updated to `from ..dirpack`
  after package migration (would have caused `ModuleNotFoundError` on repack-on-write)

## [0.11.0] - 2026-02-25

### Security
- **Passphrase-wrapped keys (Tier 1)**: Key files at `~/.cloakmcp/keys/` can now be encrypted
  at rest using a passphrase-derived wrapping key (scrypt, n=2^17, 128 MiB memory cost). Set
  `CLOAK_PASSPHRASE` env var to enable. Wrapping format uses `CLOAKKEY1` magic header for
  unambiguous format detection. Raw key (Tier 0) remains the default for backward compatibility
- **Permission verification**: `_verify_permissions()` checks and auto-corrects file permissions
  on every key access. Logs a warning if permissions were wrong (indicates external tampering)

### Added
- `cloak key wrap` — Wrap existing raw key with passphrase (Tier 0 → Tier 1)
- `cloak key unwrap` — Unwrap key back to raw format (Tier 1 → Tier 0)
- `cloak backup migrate` — Encrypt legacy plaintext backup directories into `.enc` files with
  integrity verification (decrypt → SHA-256 compare before deleting original). Supports
  `--dry-run` (default) and `--quarantine` modes
- `cloak backup prune` — Remove old backups based on TTL and keep-last policy. Supports `--ttl`
  (default: 30d), `--keep-last` (default: 10), `--apply` (dry-run without), `--include-legacy`
- `_derive_wrapping_key()`, `_wrap_key()`, `_unwrap_key()`, `_detect_key_format()` in
  `storage.py` — scrypt-based key wrapping primitives
- `wrap_keyfile()`, `unwrap_keyfile()` — High-level key file wrapping/unwrapping with
  verify-before-write safety
- `migrate_legacy_backup()`, `migrate_all_legacy_backups()` in `dirpack.py` — per-backup and
  batch migration of plaintext directories to encrypted tarballs
- `prune_backups()`, `_parse_ttl()` in `dirpack.py` — TTL-based backup pruning with keep-last
  safety net
- `CLOAK_PASSPHRASE` environment variable for Tier 1 key wrapping
- SessionStart: warns when legacy plaintext backups exist in external store; emits prune hint
  when backup count exceeds 20
- 46 new tests: `tests/test_key_wrapping.py` (25 tests), `tests/test_backup_lifecycle.py`
  (21 tests)

## [0.10.1] - 2026-02-25

### Fixed
- **Test artifact pollution**: Added `tests/conftest.py` with autouse fixture that snapshots
  `~/.cloakmcp/{keys,vaults,backups}/` before each test and removes new entries on teardown.
  Previously, every pytest run leaked orphaned key/vault/backup files (one per `tmp_path`
  slug), accumulating thousands of entries over time (observed: 3,699 keys, 2,539 vaults,
  1,234 backup dirs from repeated test runs)

## [0.10.0] - 2026-02-25

### Security
- **Encrypted backups at rest (G6 Phase 2)**: Backups are now stored as encrypted `.enc` files
  (gzip-compressed tar, Fernet-encrypted) instead of plaintext directory trees. Raw secrets in
  `~/.cloakmcp/backups/` are no longer readable with standard tools (`cat`, `grep`, etc.)
- **HKDF key separation**: Backup encryption uses an HKDF-SHA256–derived subkey
  (`salt=b"cloakmcp-backup"`, `info=project_slug`) instead of the raw vault Fernet key.
  Vault compromise does not expose backup contents and vice versa
- **Permission hardening**: `_ensure_dirs()` now sets `0o700` on all managed directories
  (`~/.cloakmcp/`, `vaults/`, `keys/`, `backups/`). Backup files are created with `0o600`

### Added
- `_derive_backup_key()`, `encrypt_backup()`, `decrypt_backup()`, `backup_path_for()` in
  `storage.py` — HKDF-based backup encryption primitives
- `list_backups()` in `dirpack.py` — enumerates both encrypted (`.enc`) and legacy plaintext
  backup formats with size, timestamp, and format metadata
- `_restore_from_backup_dir()` — legacy plaintext directory restore (factored out for
  backward compatibility)
- `_dir_size()` helper for directory-based backup size calculation
- 26 new tests in `tests/test_backup_encryption.py`: HKDF derivation, round-trip
  create/restore, permissions, backward compat, path traversal rejection, wrong-key
  rejection, corrupt data handling

### Changed
- `create_backup()`: now produces a single encrypted `.enc` file (tar.gz → Fernet encrypt →
  atomic write with `0o600`). Legacy `external=False` mode retained for testing
- `restore_from_backup()`: auto-detects format — encrypted file (new) or plaintext directory
  (legacy) — and dispatches accordingly
- `cleanup_backup()`: handles both file and directory removal (EAFP pattern, race-safe)
- `list_backups()` in `hooks.py`: delegates to new `dirpack.list_backups()` which handles
  both formats. Output format changed: `file_count` → `size` + `format` fields
- CLI `cloak status` backup listing: shows format (`encrypted`/`legacy_plaintext`) and size

## [0.9.2] - 2026-02-24

### Fixed
- **TOCTOU race in session cleanup**: `_remove_state()` and `_remove_manifest()` used
  `if os.path.isfile(path): os.remove(path)` which races on abrupt exit (double Ctrl+C).
  Replaced with `try: os.remove() except FileNotFoundError: pass` (EAFP pattern)
- **CloakMCP self-packing prevention**: tightened `.mcpignore` to exclude the package source
  (`cloakmcp/`), tests, examples, docs, configs, and metadata files. The protector must not
  mutate its own detection logic during active sessions. Only `demo/src/` (user-facing demo
  content) remains in scope

### Changed
- **Pack/unpack banners**: `pack_dir()` and `unpack_dir()` now report three distinct counters:
  modified, ignored (via `.mcpignore`), and errors (read/write failures). `iter_files()` accepts
  an optional `on_ignored` callback for callers that need the count

## [0.9.1] - 2026-02-23

### Fixed
- **Stale session auto-recovery**: `handle_session_start()` now auto-recovers from stale
  session state (crash, Ctrl+C, network drop) instead of silently skipping pack with exit 0.
  Previous behavior left secrets exposed with no visible warning. New behavior: unpack stale
  session → re-pack fresh → append "(auto-recovered from stale session)" to banner
- **`tests/` excluded from `.mcpignore`**: test files containing intentional secrets for
  validation are no longer packed by session hooks

### Added
- `session_auto_recover` audit event logged on stale session recovery
- 5 new tests: T1 (stale → auto-recover + pack), T2 (recovery failure → error),
  T3 (stale + already unpacked → clean), T4 (no stale → unchanged), audit event

## [0.9.0] - 2026-02-23

### Security
- **Policy pinning per session (G1)**: SessionStart resolves policy once, stores path + SHA-256
  in session state; all hook handlers use the pinned policy path, never caller input
- **MCP server isolation (G5)**: Removed `policy_path` parameter from all 6 MCP tool definitions
  in both FastMCP and raw JSON-RPC servers; policy pinned at server startup
- **Policy downgrade protection (G4)**: `cloak policy use` detects when the new policy has fewer
  rules or lowered severity; requires `--force` to proceed with downgrade
- **Fail-closed mode (G3)**: `CLOAK_FAIL_CLOSED=1` causes SessionStart to refuse unprotected
  sessions and guard-write to deny all writes when no policy is found

### Added
- **`cloak policy use <path>`**: set per-project policy (copies to `.cloak/policy.yaml`)
  - `--show`: display active policy path, SHA-256, and rule count
  - `--clear`: remove per-project policy
  - `--link`: symlink instead of copy
  - `--force`: allow policy downgrade (G4)
- **`cloak policy reload`**: re-resolve and update pinned policy mid-session (G2), prints
  old→new diff, logs `policy_reload` audit event
- **`resolve_policy()`** in `policy.py`: single source-of-truth resolver with 4-level chain
  (explicit → CLOAK_POLICY env → `.cloak/policy.yaml` → `examples/` fallback)
- **`find_policy()`**: non-raising wrapper (fail-open default, fail-closed with env)
- **`policy_sha256()`**: SHA-256 hash for policy pinning and comparison
- **`compare_policies()`**: downgrade detection (fewer rules / lowered severity)
- **SessionStart banner (G3)**: `Guard ACTIVE: policy=<path> (N rules, sha256=…)` or
  `Guard INACTIVE: no policy found`
- **`--policy` flag** in `install_claude.sh`: anchors policy at install time via Phase 4c
- **`--allow-policy-override`** flag on FastMCP server (default off, backwards compat)
- New `CLOAK_FAIL_CLOSED` environment variable
- Policy configuration section in `SECURITY.md` (10 subsections)

### Changed
- **Policy resolution unified**: 3 duplicate resolvers (hooks.py, fastmcp_server.py, mcp_server.py)
  replaced by shared `resolve_policy()` / `find_policy()` from `policy.py`
- Session state marker now includes `policy_path`, `policy_sha256`, `policy_rule_count` fields
- Guard-write, prompt-guard, and repack hooks read pinned policy from session state (G1)
- `.cloak/` added to `.gitignore`

## [0.8.1] - 2026-02-23

### Added
- **`cloak serve`**: FastMCP-based MCP server with zero-config stdio transport (default) and
  optional SSE/streamable-http network transport. Wraps all 6 CloakMCP tools via the MCP SDK's
  FastMCP framework. Supports `--policy`, `--prefix`, `--transport`, `--host`, `--port`, `--check`.
  Requires optional dependency: `pip install cloakmcp[mcp]`.
- **`cloak --version`**: prints version string for the CLI
- **`cloakmcp/fastmcp_server.py`**: new module with FastMCP server, 6 tools, server instructions,
  and CloakMCP version injection into MCP server info

### Fixed
- **JWT regex false positives**: The JWT detection rule matched version numbers (e.g., `0.8.0`),
  Python attribute chains (`os.path.isfile`), and IP addresses (`127.0.0.1`) — caused guard-write
  hook to block legitimate edits. Fixed by requiring 20+ characters per segment (`{20,}` instead
  of `+`), matching only real JWTs while eliminating all false positives
- **Stale version strings**: MCP server and FastAPI server had hardcoded old version — now read
  dynamically from package metadata at runtime

## [0.8.0] - 2026-02-22

### Added
- **`cloak status`**: read-only session diagnostics — session state, manifest summary,
  file delta, vault stats, tag residue, available backups, legacy backup warnings, recent
  audit events. Supports `--json` and `--audit-lines N`.
- **`cloak restore`**: two restore modes:
  - **Vault-based** (default): replaces tags with secrets, runs R4 verification + R5 delta,
    cleans session state. Works even without session state if vault has data.
  - **Backup-based** (`--from-backup`): copies pre-redaction files from external backup. Requires
    `--force` for execution. Without `--force`, shows dry-run preview. Lists available backups
    when no `--backup-id` specified.
- `restore_from_backup()` in dirpack.py: file-copy restore with dry-run support
- `_read_audit_tail()`, `list_backups()` helpers in hooks.py
- New audit events: `restore_vault`, `restore_backup`
- ~37 new tests across 5 test classes

## [0.7.0] - 2026-02-22

### Security
- **Backup exfiltration fix (G6)**: pre-redaction backups moved from in-tree `.cloak-backups/`
  to `~/.cloakmcp/backups/{slug}/` — prevents LLM tools from reading raw secrets via
  Read/Grep/Glob during active sessions (severity: High)
- **Guard-read hook (P3)**: new `PreToolUse` guard for Read/Grep/Glob blocks access to
  `.cloak-backups/`, `.cloak-session-state`, `.cloak-session-manifest.json`,
  `.cloak-session-audit.jsonl`, and `~/.cloakmcp/` (hardened profile, defense-in-depth)
- **Legacy backup warning**: session start and recovery detect in-tree `.cloak-backups/`
  and emit security warnings

### Added
- `create_backup(external=True)` — external backup to `~/.cloakmcp/backups/{slug}/{ts}/`
- `cleanup_backup()` — removes timestamped backup after successful session end
- `warn_legacy_backups()` — returns warning if legacy `.cloak-backups/` exists in project
- `handle_guard_read()` — PreToolUse hook handler for Read/Grep/Glob sensitive paths
- `cloak hook guard-read` CLI event + `cloak-guard-read.sh` wrapper script
- `hooks-hardened.json`: `Read|Grep|Glob` PreToolUse entry for hardened profile
- Installer Phase 4b: ensures `.cloak-backups/` in `.gitignore` and `.mcpignore`
- `.cloak-backups/` added to `.gitignore` and `.mcpignore` (explicit, was only programmatic)
- `BACKUPS_DIR` constant in `storage.py`
- Session state marker now includes `backup_path` field
- 28 new tests: `TestExternalBackup` (8), `TestGuardRead` (16), `TestStateMarker` updates (2)

### Changed
- `create_backup()` default changed to external storage (`external=True`)
- `handle_session_start()` creates external backup, passes `backup=False` to `pack_dir()`
- `handle_session_end()` cleans up external backup after successful unpack
- `handle_recover()` warns about legacy in-tree backups
- `__version__` synced to `0.7.0` (was stale at `0.5.0`)

## [0.6.3] - 2026-02-22

### Added
- **PyPI distribution**: first release on PyPI (`pip install cloakmcp`)
- **`cloak scripts-path`** CLI subcommand: prints the path to bundled installer scripts
  (works from both `pip install` and git clone)
- **GitHub Actions workflow** (`.github/workflows/publish.yml`): automated test (Python
  3.10–3.13) → build → publish via OIDC Trusted Publisher on tagged releases
- **PyPI badge** in README (dynamic, auto-updates with each release)

### Changed
- **Scripts bundled in wheel**: `scripts/` moved to `cloakmcp/scripts/` with
  `[tool.setuptools.package-data]` — hook installer, 6 hook shells, and 2 settings
  templates are now included in the PyPI distribution
- **`install_claude.sh`**: `PROJECT_DIR` uses `pwd` instead of `SCRIPT_DIR/..` — works
  correctly when invoked from pip-installed location
- **`pyproject.toml`**: added `[project.urls]` (Homepage, Repository, Issues, Changelog)
- All documentation updated to use `bash "$(cloak scripts-path)/install_claude.sh"`

### Documentation
- **`docs/QUICKSTART.md`** (new): first-time setup guide with compatibility matrix (Claude
  Code, VS Code, Claude Web, other LLMs, CI/CD), FAQ, and troubleshooting
- **`docs/QUICKREF.md`**: rewritten for v0.6.x — all 17 CLI commands, hooks lifecycle,
  env vars, severity levels, MCP tools, vault management
- Root cleanup: 5 developer docs moved to `docs/`, 12 historical artifacts archived,
  `.backups/` removed from git tracking, `CLAUDE.md` removed from tracking
- README project structure tree updated to reflect actual layout

## [0.6.0] - 2026-02-21

### Added
- **Enterprise policy profile** (`mcp_policy_enterprise.yaml`): 16 new provider-specific rules
  (GitHub PAT, GitLab, Slack, Stripe, npm, Heroku, Twilio, SendGrid, Azure, PKCS#8, generic
  password/secret patterns) — inherits from default via `inherits: [mcp_policy.yaml]`
- **Incremental repack** (`cloak repack --dir .`): manifest-aware re-scan that skips unchanged
  files via SHA-256 content hashing
- **Single-file repack hook** (`CLOAK_REPACK_ON_WRITE=1`): opt-in auto-repack after Write/Edit
  tool calls
- **Tag idempotency guard**: `pack_text()` filters matches overlapping existing tags — prevents
  double-tagging on repack
- **`whitelist_patterns`** field on entropy rules: per-rule allowlists to reduce false positives
  (e.g., `data:image/` URIs)
- 41 new tests: enterprise policy (26), repack and idempotency (15)

### Changed
- **LLM-agnostic framing**: README restructured to present CloakMCP as LLM-agnostic with Claude
  Code as one (first-class) integration
- **Protection boundary clarification**: split into "Core protection (any LLM)" and "Claude Code
  hooks" in both README and SECURITY.md
- Session banner updated to clarify exfiltration vs inference distinction
- Test suite expanded: 173 → 214 tests across 7 files
- Changelog extracted from README into standalone `CHANGELOG.md`

### Documentation
- **SECURITY.md**: new "Scope" section distinguishing universal vs Claude Code hook protections;
  new "Fundamental limitations" section (exfiltration vs inference)
- **README.md**: LLM-agnostic overview, enterprise policy section, inference limitation row,
  `CLOAK_REPACK_ON_WRITE` env var

## [0.5.1] - 2026-02-21

### Added
- **Prompt guard** (`UserPromptSubmit` hook): blocks prompts containing critical/high-severity
  secrets, warns on medium/low
- **Post-unpack verification** (`cloak verify --dir .`): scans for residual tags after unpack
- **Session manifest** (`.cloak-session-manifest.json`): SHA-256 hashes of packed content for
  incremental operations
- **`sanitize-stdin`** CLI command: pipe helper for stdin-to-stdout sanitization
- **Safety guard** (`PreToolUse Bash` hook): blocks dangerous commands (`rm -rf /`,
  `git push --force`, `chmod -R 777`, etc.)
- **Two-tier audit logging**: always-on Tier 1 (session/guard events) + opt-in Tier 2
  (`CLOAK_AUDIT_TOOLS=1` for tool metadata with hashed file paths)

### Changed
- Hook infrastructure restructured: source-of-truth moved to `scripts/hooks/`, idempotent
  installer with `--profile`, `--method`, `--dry-run`, `--uninstall` flags
- `CLOAK_STRICT=1` env var escalates medium-severity matches to blocking in both guard-write
  and prompt-guard hooks

## [0.5.0] - 2026-02-20

### Added
- **MCP tool server** (`cloak-mcp-server`): 6 tools via JSON-RPC 2.0 over stdio
  (`cloak_scan_text`, `cloak_pack_text`, `cloak_unpack_text`, `cloak_vault_stats`,
  `cloak_pack_dir`, `cloak_unpack_dir`)
- **Claude Code hooks** (`cloakmcp/hooks.py`): automatic session protection via `SessionStart`
  (pack), `SessionEnd` (unpack), and `PreToolUse` (guard-write) with session state management
  and stale state recovery
- **File-level pack/unpack** (`cloakmcp/filepack.py`): text-level operations with overlapping
  match deduplication algorithm (longest-span-wins)
- **Live demo suite** (`demo/`): 4 scripts — `llm_demo.sh` (Ollama/Claude), `mcp_demo.sh`
  (MCP protocol + hook lifecycle), `transcript.sh` (6-phase before/after), `run_demo.sh`
  (interactive 5-act)
- Demo banking microservice: Spring Boot `BankTransferService.java` with 10+ fake secrets
  across 3 config files
- MCP server tests (18), hook tests (17), filepack round-trip tests
- `.mcp.json` for Claude Code MCP server discovery

### Changed
- **Package renamed**: `mcp/` → `cloakmcp/` to avoid conflict with Anthropic's `mcp` SDK
- Entry points updated: `cloak = cloakmcp.cli:main`, `cloak-mcp-server = cloakmcp.mcp_server:main`
- Test suite expanded: 90 → 173 tests across 6 files

### Fixed
- **Overlapping match corruption**: `_dedup_overlapping()` prevents round-trip data loss when
  multiple scanner rules match overlapping text spans
- **URL regex backtracking**: negative lookbehind prevents trailing punctuation consumption
- **Email regex catastrophic backtracking**: bounded quantifiers replace unbounded `+`

## [0.3.3] - 2026-02-20

### Fixed
- Email regex catastrophic backtracking on large inputs (10 MB: ~38 s → <0.1 s)
- API endpoints return proper HTTP 500 JSON responses instead of raw exceptions
- Test reliability: HMAC key path resolution and lazy vault creation

### Changed
- Performance tests marked `@pytest.mark.slow` and excluded from default runs
- API test suite rewritten with unified `api_env` fixture

### Added
- `[project.optional-dependencies] test` in `pyproject.toml`: `pip install -e ".[test]"`

## [0.3.2] - 2025-11-13

### Added
- **Group policy inheritance**: hierarchical YAML policies with `inherits` field
  (company → team → project)
- `cloak policy validate` and `cloak policy show` commands
- Cycle detection in policy inheritance chains
- Deep merging of inherited rules, tilde expansion in paths
- Example inheritance policies: `company-baseline.yaml`, `team-backend.yaml`

## [0.3.1] - 2025-11-12

### Added
- HMAC-based tags (keyed with vault key) replace plain SHA-256 — brute-force resistant
- `SERVER.md` with threat model and security architecture
- Dry-run mode for pack/sanitize operations
- Automatic `.bak` backup before in-place file modifications

### Changed
- Binary renamed from `mcp` to `cloak` to avoid namespace conflicts

## [0.3.0] - 2025-11-11

### Security
- Critical security hardening: HMAC-SHA256 tagging, input validation, permission checks
- Vault file permissions tightened to `0600`

### Changed
- Vault tags now use HMAC-SHA256 with the vault key instead of plain SHA-256
- Comprehensive documentation rewrite

## [0.2.5] - 2025-11-11

### Added
- HMAC key caching (100-1000x performance improvement on large codebases)
- API rate limiting
- Vault export/import commands
- CLI policy validation

## [0.2.0] - 2025-11-11

### Added
- **Pack/unpack commands**: batch directory processing with deterministic tagging
- **Encrypted vaults**: Fernet AES-128 symmetric encryption in `~/.cloakmcp/`
- Deterministic tag generation (`PREFIX-<12 hex>`)
- `.mcpignore` support for file exclusion
- VS Code integration (keybindings, tasks)
- FastAPI REST server with Bearer token authentication
- Comprehensive test suite

## [0.1.0] - 2025-11-11

### Added
- Initial release: `cloak scan` and `cloak sanitize` commands
- YAML policy engine with detection rules (regex, entropy, IPv4/6, URL, JWT)
- Actions: allow, block, redact, pseudonymize, hash, replace_with_template
- Text normalizer (Unicode NFC, zero-width char removal)
- HMAC-based pseudonymization
- JSONL audit logging

[Unreleased]: https://github.com/ovitrac/CloakMCP/compare/v0.12.1...HEAD
[0.12.1]: https://github.com/ovitrac/CloakMCP/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/ovitrac/CloakMCP/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/ovitrac/CloakMCP/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/ovitrac/CloakMCP/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/ovitrac/CloakMCP/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/ovitrac/CloakMCP/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/ovitrac/CloakMCP/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/ovitrac/CloakMCP/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/ovitrac/CloakMCP/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/ovitrac/CloakMCP/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ovitrac/CloakMCP/compare/v0.6.3...v0.7.0
[0.6.3]: https://github.com/ovitrac/CloakMCP/compare/v0.6.0...v0.6.3
[0.6.0]: https://github.com/ovitrac/CloakMCP/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/ovitrac/CloakMCP/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ovitrac/CloakMCP/compare/v0.3.3...v0.5.0
[0.3.3]: https://github.com/ovitrac/CloakMCP/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/ovitrac/CloakMCP/compare/v0.3.1-alpha...v0.3.2
[0.3.1]: https://github.com/ovitrac/CloakMCP/compare/v0.3.0-alpha...v0.3.1-alpha
[0.3.0]: https://github.com/ovitrac/CloakMCP/compare/v0.2.5...v0.3.0-alpha
[0.2.5]: https://github.com/ovitrac/CloakMCP/compare/v0.2.0...v0.2.5
[0.2.0]: https://github.com/ovitrac/CloakMCP/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ovitrac/CloakMCP/releases/tag/v0.1.0
