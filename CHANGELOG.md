# Changelog

All notable changes to CloakMCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ovitrac/CloakMCP/compare/v0.6.0...HEAD
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
