# CloakMCP v0.2.5 — Pre-Deployment Issues Report

**Date**: 2025-11-11
**Reviewer**: Claude (Sonnet 4.5)
**Project**: CloakMCP — Micro-Cleanse Preprocessor

---

## Executive Summary

CloakMCP is a well-architected security tool with solid foundations. The codebase demonstrates good practices: type hints, modular design, encryption, and deterministic behavior. However, several issues ranging from critical bugs to quality-of-life improvements were identified during this deep review.

**Status**: ✅ **Ready for deployment** with minor fixes recommended.

---

## 🔴 Critical Issues (Must Fix)

### C1. Leading Backslashes in Source Files
**Files**: `scanner.py`, `actions.py`, `utils.py`, `dirpack.py`, `mcp_policy.yaml`
**Severity**: LOW (does not cause runtime errors but unusual)
**Description**: Files begin with `\` followed by newline. While Python interprets this as a line continuation (harmless), it's non-standard and could confuse linters/IDEs.
**Fix**: Remove leading backslashes.

### C2. Version Mismatch
**Files**: `pyproject.toml` (0.2.0) vs `server.py:52` (0.1.0)
**Severity**: MEDIUM
**Description**: API reports incorrect version.
**Fix**: Update `server.py` version to "0.2.0".

### C3. Missing Input Validation in CLI
**File**: `cli.py`
**Severity**: MEDIUM
**Description**: `--input` and `--dir` arguments are not validated before use. Non-existent paths cause unclear errors.
**Fix**: Add `os.path.exists()` checks with clear error messages.

### C4. Uncaught Exceptions in File Operations
**Files**: `dirpack.py:44-48`, `dirpack.py:68-72`
**Severity**: MEDIUM
**Description**: Broad `except Exception` silently skips files, potentially hiding critical errors (permissions, corruption).
**Fix**: Log warnings when files are skipped. Use specific exception types.

---

## 🟠 Security / Logic Issues

### S1. Potential Tag Collision
**File**: `storage.py:72-78`
**Severity**: LOW
**Description**: No validation that a secret doesn't already look like a tag (e.g., "TAG-abc123def456"). Could cause unpack collisions.
**Recommendation**: Validate secrets against `TAG_RE` pattern; warn or reject if match.

### S2. No Entropy for Pseudonymization Key
**File**: `actions.py:19`
**Severity**: LOW
**Description**: Key file is read raw without validation. If file contains low-entropy data, HMAC security degrades.
**Recommendation**: Validate key length (≥32 bytes) and entropy on load.

### S3. CIDR Validation Missing
**File**: `policy.py:75-82`
**Severity**: LOW
**Description**: Malformed CIDR strings (e.g., "999.999.999.999/99") cause uncaught exceptions.
**Fix**: Wrap `ipaddress.ip_network()` in try-except; log and skip invalid CIDRs.

### S4. File Encoding Issues Silently Ignored
**File**: `dirpack.py:45`, `dirpack.py:69`
**Severity**: LOW
**Description**: `errors="ignore"` silently corrupts non-UTF-8 files.
**Recommendation**: Use `errors="replace"` or `errors="surrogateescape"` and log warnings.

### S5. No Rate Limiting on API
**File**: `server.py`
**Severity**: MEDIUM (if exposed)
**Description**: API has no rate limiting. If accidentally exposed to LAN, vulnerable to brute-force token attacks.
**Recommendation**: Add `slowapi` or similar rate limiting (10 req/min per IP).

---

## 🟡 Code Quality Issues

### Q1. Performance: Key File Read on Every Action
**File**: `actions.py:19`
**Severity**: LOW
**Description**: HMAC key file is read from disk for every pseudonymization operation.
**Fix**: Cache key in memory (store in `Policy.globals` or module-level).

### Q2. Overlapping Match Handling
**File**: `scanner.py:67`
**Severity**: LOW
**Description**: Matches are sorted by `(start, end)` but overlapping matches are not deduplicated. If two rules match the same substring, both replacements occur (first-wins due to `reversed()`).
**Behavior**: Current behavior is deterministic but may surprise users.
**Recommendation**: Document in `CLAUDE.md` or add `--strict` mode that errors on overlap.

### Q3. No Operational Logging
**Files**: All modules
**Severity**: LOW
**Description**: Only audit logs exist. No debug/info logging for operations (file counts, vault size, scan timing).
**Recommendation**: Add Python `logging` module with `--verbose` CLI flag.

### Q4. Type Hint Inconsistencies
**Files**: `actions.py:12` (union syntax `|` vs `Optional`)
**Severity**: LOW
**Description**: Mixed use of `str | None` (PEP 604) and `Optional[str]` (PEP 484).
**Fix**: Standardize to one style (prefer `Optional` for Python 3.10+ compatibility clarity).

### Q5. Missing Docstrings
**Files**: All public functions
**Severity**: LOW
**Description**: Many functions lack docstrings (e.g., `sanitize_text`, `pack_dir`).
**Recommendation**: Add docstrings following Google or NumPy style.

---

## 🔵 Missing Features / Enhancements

### F1. No Pack Dry-Run Mode
**File**: `cli.py:90-93`
**Severity**: LOW
**Description**: `mcp pack` has no `--dry-run` to preview changes before modifying files.
**Recommendation**: Add `--dry-run` flag that logs what would be replaced without writing.

### F2. Vault Export/Backup Missing
**File**: `storage.py`
**Severity**: MEDIUM
**Description**: No CLI command to export or backup vaults for disaster recovery.
**Recommendation**: Add `mcp vault export --dir DIR --output vault_backup.json`.

### F3. No Default `.mcpignore` Generation
**File**: `dirpack.py`
**Severity**: LOW
**Description**: Users must manually create `.mcpignore`. First-time users may accidentally scan binaries.
**Recommendation**: `mcp pack` auto-generates `.mcpignore` if missing (with user confirmation).

### F4. README Outdated
**File**: `README.md`
**Severity**: LOW
**Description**: Quickstart doesn't mention `pack`/`unpack` commands (only `scan`/`sanitize`).
**Fix**: Update README with full workflow example.

### F5. No Pre-Commit Hook Example
**Files**: `examples/`
**Severity**: LOW
**Description**: CLAUDE.md mentions pre-commit hooks but no example provided.
**Recommendation**: Add `.pre-commit-config.yaml` and `hooks/pre-commit.sh` examples.

---

## 🟢 Good Practices Observed

1. ✅ **Type hints throughout** (mypy strict mode)
2. ✅ **Deterministic tagging** (SHA-256 based)
3. ✅ **Encrypted vault** (Fernet/AES-128)
4. ✅ **Atomic file writes** (`os.replace()` for safety)
5. ✅ **Permissions hardening** (0600 for keys/vaults)
6. ✅ **Policy-driven design** (YAML configuration)
7. ✅ **Local-first** (no network calls in hot path)
8. ✅ **Audit trail** (JSONL logs)
9. ✅ **VS Code integration** (tasks + keybindings)
10. ✅ **Clear licensing** (MIT with authorship)

---

## Priority Fix Recommendations

### High Priority (Before v1.0)
1. Fix C2: Version mismatch
2. Fix C3: Add CLI input validation
3. Fix S5: Add API rate limiting (if server mode used)
4. Fix F2: Add vault export/backup
5. Fix F4: Update README

### Medium Priority (v1.1)
1. Fix C4: Improve error handling in dirpack
2. Fix Q1: Cache HMAC key
3. Fix F1: Add pack dry-run mode
4. Add comprehensive tests (see `tests/test_comprehensive.py`)

### Low Priority (v1.2+)
1. Add logging framework
2. Add docstrings
3. Standardize type hints
4. Add pre-commit hook examples

---

## Testing Gaps

Current test coverage: **~5%** (1 smoke test only)

**Missing tests**:
- ❌ Policy loading with invalid YAML
- ❌ Scanner edge cases (Unicode, zero-width chars, long strings)
- ❌ Action edge cases (empty secrets, special chars)
- ❌ Vault encryption/decryption roundtrip
- ❌ Pack/unpack with .mcpignore patterns
- ❌ API authentication failures
- ❌ Concurrent pack operations (race conditions)

**See**: `tests/test_comprehensive.py` (created separately)

---

## Deployment Checklist

- [ ] Fix C2: Update server version to 0.2.0
- [ ] Fix C3: Add CLI path validation
- [ ] Run full test suite: `pytest -v tests/`
- [ ] Run type checker: `mypy mcp/`
- [ ] Run security linter: `bandit -r mcp/`
- [ ] Update README with pack/unpack examples
- [ ] Generate default `.mcpignore` on first run
- [ ] Document vault backup procedure in SECURITY.md
- [ ] Test on fresh Python 3.10+ environment
- [ ] Verify all examples/ scripts work

---

## Conclusion

CloakMCP is **production-ready** for careful use with minor improvements. The architecture is sound, and the threat model is well-addressed. Primary concerns are operational robustness (error handling, logging) and completeness of documentation/tests.

**Recommendation**: Deploy as **beta (v0.2-beta)** while addressing high-priority fixes for v1.0 release.

---

*Report generated for Olivier Vitrac — Adservio Innovation Lab*
