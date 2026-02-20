# Changelog

All notable changes to CloakMCP are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0] - 2026-02-20

### Added
- **MCP tool server** (`cloak-mcp-server`): 6 tools exposed via JSON-RPC 2.0 over stdio for native Claude Code integration (`cloak_scan_text`, `cloak_pack_text`, `cloak_unpack_text`, `cloak_vault_stats`, `cloak_pack_dir`, `cloak_unpack_dir`).
- **Claude Code hooks** (`cloakmcp/hooks.py`): automatic session protection via `SessionStart` (pack), `SessionEnd` (unpack), and `PreToolUse` (guard-write) hooks with session state management and stale state recovery.
- **File-level pack/unpack** (`cloakmcp/filepack.py`): text-level operations with overlapping match deduplication algorithm (longest-span-wins).
- **Live demo suite** (`demo/`): 4 scripts — `llm_demo.sh` (Ollama/Claude), `mcp_demo.sh` (MCP protocol + hook lifecycle), `transcript.sh` (screenshot-friendly 6-phase), `run_demo.sh` (interactive 5-act).
- **Demo banking microservice**: Spring Boot `BankTransferService.java` with 10+ fake secrets across 3 config files (`application.properties`, `application.yml`), Maven scaffold, `.mcpignore`.
- **MCP server tests** (`tests/test_mcp_server.py`): 18 tests covering protocol compliance, tool dispatch, error handling.
- **Hook tests** (`tests/test_hooks.py`): 17 tests covering session lifecycle, guard-write scanning, state management.
- **Filepack tests** (`tests/test_filepack.py`): round-trip integrity tests with overlap deduplication.
- `.mcp.json` for Claude Code MCP server discovery.
- `.claude/hooks/` shell scripts for Claude Code hook integration.
- `.claude/settings.local.json` with hook and permission configuration.

### Changed
- **Package renamed**: `mcp/` → `cloakmcp/` to avoid conflict with Anthropic's `mcp` package.
- **Entry points**: `cloak = cloakmcp.cli:main`, `cloak-mcp-server = cloakmcp.mcp_server:main`.
- **README rewritten**: new teaser with LLM secret rehydration demo, Claude Code integration section, MCP/hooks documentation, updated project structure, streamlined from 1397 to 747 lines.
- Test suite expanded: 90+ → 115+ tests across 6 test files.

### Fixed
- **Overlapping match corruption**: added `_dedup_overlapping()` to prevent round-trip data loss when multiple scanner rules match overlapping text spans (e.g., JWT regex matching domain names inside URLs).
- **URL regex backtracking**: negative lookbehind `(?<![.,;:!?\-])` prevents trailing punctuation consumption.

---

## [0.3.3] - 2026-02-20

### Fixed
- **Critical performance regression**: email regex caused catastrophic backtracking on large inputs (10 MB string took ~38s, now <0.1s). Bounded quantifiers (`{1,64}`, `{1,63}`) replace unbounded `+` in all email patterns (scanner, policy, tests).
- **API error handling**: `/sanitize` and `/scan` endpoints now return proper HTTP 500 JSON responses instead of raising raw exceptions on invalid policy paths.
- **Test suite reliability**: fixed `test_action_pseudonymize` (HMAC key not found due to premature `os.chdir` restore in fixture) and `test_vault_create` (vault file is lazily created on first `tag_for`, not on init).

### Changed
- Performance tests (`test_scan_large_file`, `test_vault_many_secrets`) marked with `@pytest.mark.slow` and excluded from default runs via `pytest.ini` (`-m "not slow"`).
- Restored original large test sizes (10 MB, 10k emails, 1000 vault entries) now that the regex fix makes them fast.
- API test suite rewritten with unified `api_env` fixture using `importlib.reload(mcp.server)` to properly handle module-level token/policy initialization.

### Added
- `[project.optional-dependencies] test` in `pyproject.toml`: install test deps with `pip install -e ".[test]"` (pytest, httpx).

---

## [0.3.2-alpha] - 2025-11-12

### Added
- **Group policy inheritance**: hierarchical YAML policies with `inherits` field (company -> team -> project). Rules merged by ID (later overrides), lists concatenated, globals deep-merged.
- Cycle detection in policy inheritance chains.
- `cloak policy validate` command to check policy files including inheritance resolution.
- `cloak policy show` command to display merged policy after inheritance (YAML/JSON output).
- Example inheritance policies: `company-baseline.yaml`, `team-backend.yaml`, `project-with-inheritance.yaml`.

### Changed
- Documentation updated for v0.3.2 features.

---

## [0.3.1-alpha] - 2025-11-12

### Changed
- Binary renamed from `mcp` to `cloak` to avoid namespace conflicts.
- Safety features for file operations (atomic writes, backups before modification).

---

## [0.3.0-alpha] - 2025-11-11

### Fixed
- Critical security hardening across all modules.
- HMAC-SHA256 tagging in vault (prevents brute-force tag guessing without vault key).
- File permission enforcement (0600) for keys and vaults.

### Changed
- Vault tags now use HMAC-SHA256 with the vault key instead of plain SHA-256.
- Improved input validation and error handling.

---

## [0.2.5-alpha] - 2025-11-11

### Added
- Pre-production release with initial documentation.
- README and project structure.

---

## [0.2-alpha] - 2025-11-11

### Added
- Pack/unpack batch mode with encrypted vault (`~/.cloakmcp/`).
- Deterministic tag generation (`PREFIX-<12 hex>`).
- `.mcpignore` support for file exclusion.
- Vault export/import commands.
- Vault statistics command.
- FastAPI localhost server with Bearer token authentication.
- VS Code integration (tasks, keybindings).

---

## [0.1-alpha] - 2025-11-11

### Added
- Initial release.
- CLI with `scan` and `sanitize` commands.
- YAML policy engine with detection rules (regex, entropy, IPv4/6, URL, JWT).
- Actions: allow, block, redact, pseudonymize, hash, replace_with_template.
- Text normalizer (Unicode NFC, zero-width char removal).
- JSONL audit logging.
- HMAC-based pseudonymization.
