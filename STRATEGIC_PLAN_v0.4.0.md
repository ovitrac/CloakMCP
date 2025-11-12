# Strategic Plan: CloakMCP v0.3.x → v0.4.0
**Based on**: External review (colleagues) + previous session priorities
**Date**: 2025-11-12
**Current Version**: v0.3.1-alpha (LIVE on GitHub)

---

## Executive Summary

**Current Status**: v0.3.1-alpha has critical HMAC security fix but suffers from:
1. **Binary name collision** with Anthropic's MCP
2. **Overclaimed security guarantees** (now mostly fixed in v0.3.1)
3. **Missing safety features** (no dry-run, no backup automation)
4. **Entry barrier too high** (README too long)
5. **Incomplete operational story** (key rotation, group policies)

**Recommendation**: Execute phased rollout to v0.4.0 (stable) over 2-3 weeks.

---

## Phase 1: Critical Fixes (v0.3.1) — 1 week

### Priority: CRITICAL (Do First)

#### 1.1 Binary Rename: `cloak` → `cloak` (HIGH PRIORITY)
**Time**: 6-8 hours
**Rationale**:
- Eliminates confusion with Anthropic's Model Context Protocol
- Improves discoverability and branding
- Colleagues + review both flagged as critical

**Tasks**:
- [ ] Choose final name: **`cloak`** (recommended) vs `cloakmcp` vs `cloak-llm`
- [ ] Update `pyproject.toml` entry point: `cloak = "cloak.cli:main"`
- [ ] Mass-rename in documentation (~15 files):
  - README.md, QUICKREF.md, SERVER.md, VSCODE_MANUAL.md
  - All examples, tests, .vscode/tasks.json
- [ ] Update GitHub repo description
- [ ] Add migration guide for v0.2.5/v0.3.1 users
- [ ] Test CLI: `cloak --help`, `cloak pack`, etc.
- [ ] Commit as v0.3.1-alpha

**Breaking Change**: YES (CLI command changes)
**Migration**: Simple search-replace in scripts: `cloak` → `cloak`

---

#### 1.2 Add `--dry-run` to Pack/Unpack (CRITICAL SAFETY)
**Time**: 4-6 hours
**Rationale**:
- Review flagged "no default dry-run, no safety check" as dangerous
- Prevents accidental mass-edits
- Mandatory for production use

**Implementation**:
```python
# mcp/cli.py - pack subcommand
parser_pack.add_argument(
    "--dry-run",
    action="store_true",
    help="Preview changes without modifying files"
)

# mcp/dirpack.py - pack_directory()
if dry_run:
    print(f"[DRY RUN] Would replace in {path}:")
    print(f"  {len(matches)} secrets → tags")
    return  # Don't write
```

**Tasks**:
- [ ] Add `--dry-run` flag to `pack` subcommand
- [ ] Add `--dry-run` flag to `unpack` subcommand
- [ ] Implement preview mode in `dirpack.py`:
  - Show files that would be modified
  - Show count of replacements per file
  - Colorize output (green = safe, yellow = many changes, red = blocked)
- [ ] Update all documentation examples
- [ ] Add tests for dry-run behavior
- [ ] Default behavior: prompt "Continue? [y/N]" for >10 file changes

**Breaking Change**: NO (additive)

---

#### 1.3 Add Auto-Backup to Pack/Unpack
**Time**: 3-4 hours
**Rationale**:
- Review: "no snapshot/backup mechanism" is risky
- Complements `--dry-run` for safety

**Implementation**:
```python
# mcp/dirpack.py
def _create_backup(directory: Path) -> Path:
    """Create timestamped backup of directory before pack/unpack."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = directory / ".cloak-backups" / timestamp
    backup_dir.mkdir(parents=True, exist_ok=True)
    # Copy only tracked files (respect .mcpignore)
    return backup_dir
```

**Tasks**:
- [ ] Add `--backup` flag (default: enabled)
- [ ] Add `--no-backup` to skip (for CI/automation)
- [ ] Store backups in `.cloak-backups/<timestamp>/`
- [ ] Add `.cloak-backups/` to default `.mcpignore`
- [ ] Show backup location after creation
- [ ] Add `cloak backup list` / `cloak backup restore` commands (future)

**Breaking Change**: NO (default enabled, opt-out available)

---

#### 1.4 Fix Documentation Overclaims
**Time**: 2 hours
**Rationale**: Review flagged "2^48 computationally infeasible" and "LLM cannot access secrets"

**Already Fixed in v0.3.1**:
- ✅ HMAC-based tags (no longer unkeyed SHA-256)
- ✅ Accurate security claims in README

**Remaining**:
- [ ] Add explicit THREAT_MODEL.md (from review Section 4)
- [ ] Clarify server `--host 0.0.0.0` warnings (already added, verify prominence)
- [ ] Remove "Production-Ready Beta" language (use "Alpha" or "Beta" only)
- [ ] Add "2-minute quick start" at top of README (already added, verify placement)

**Tasks**:
- [ ] Create THREAT_MODEL.md:
  - **In scope**: Accidental LLM sharing, honest-but-curious providers, repo leaks
  - **Out of scope**: Compromised dev machines, brute-force with vault access
  - **Assumptions**: Local machine trusted, `~/.cloakmcp/` secure
- [ ] Update README.md:
  - Move detailed architecture to `/docs`
  - Keep README <500 lines (currently ~800)
  - Emphasize "Alpha" status
- [ ] Add comparison table (already done, verify accuracy)

---

### Release: v0.3.1-alpha

**Changelog**:
```markdown
### v0.3.1-alpha (2025-11-1X)

**BREAKING CHANGES**:
- CLI binary renamed: `cloak` → `cloak` (fixes Anthropic MCP collision)

**Safety Features**:
- Added `--dry-run` flag to pack/unpack (preview changes)
- Added `--backup` flag (auto-backup before modifications, enabled by default)
- Added confirmation prompts for large operations (>10 files)

**Documentation**:
- Added THREAT_MODEL.md (explicit security assumptions)
- Improved README structure (2-min quick start at top)
- Removed overclaimed "production-ready" language

**Migration**:
- Update scripts: `cloak pack` → `cloak pack`
- No vault changes (v0.3.1 vaults compatible)
```

**Estimated Time**: 15-20 hours (1 full week)

---

## Phase 2: Feature Completion (v0.3.2) — 1 week

### Priority: HIGH (Polish for Stability)

#### 2.1 Key Rotation Command
**Time**: 4-6 hours
**Rationale**:
- Review: "Key management story is minimal"
- Essential operational capability for production use

**Implementation**:
```bash
cloak vault rekey --dir /path/to/project [--new-key /path/to/new.key]
```

**Tasks**:
- [ ] Add `cloak vault rekey` subcommand
- [ ] Generate new vault key (or accept provided key)
- [ ] Load existing vault with old key
- [ ] Re-encrypt all tag mappings with new key
- [ ] **Atomic operation**: rollback on failure
- [ ] Update vault metadata (creation date, key rotation count)
- [ ] Add `--dry-run` mode for rekey
- [ ] Documentation: key rotation best practices

**Algorithm**:
```python
def rekey_vault(old_key, new_key):
    # 1. Backup old vault
    # 2. Decrypt with old key
    # 3. Re-encrypt with new key
    # 4. Atomic swap (rename old → .bak, new → active)
    # 5. Verify (decrypt sample tags)
    # 6. Delete backup after confirmation
```

**Breaking Change**: NO (vault format unchanged)

---

#### 2.2 Group Policy Support
**Time**: 6-8 hours
**Rationale**:
- User (Olivier) explicitly requested
- Enables organization-wide standards

**Implementation**:
```yaml
# examples/mcp_policy.yaml
version: 1
inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml  # Global defaults
  - ./team-overrides.yaml                       # Team-specific

globals:
  # ... (local overrides)
```

**Tasks**:
- [ ] Add `inherits` field to policy schema
- [ ] Implement policy merging (later rules override earlier)
- [ ] Support multiple inheritance (array of paths)
- [ ] Resolve relative paths (`.`, `~`, absolute)
- [ ] Add `cloak policy validate` command (check syntax + inheritance)
- [ ] Add `cloak policy show` (display merged policy)
- [ ] Documentation: policy hierarchy best practices
- [ ] Example: company baseline policy

**Breaking Change**: NO (additive, backward compatible)

---

#### 2.3 Detection Scope Documentation
**Time**: 2-3 hours
**Rationale**:
- Review: "Does not state how many detectors it ships"
- Improves trust and sets expectations

**Tasks**:
- [ ] Create `/docs/DETECTORS.md`:
  - List all built-in detectors (~15-20)
  - For each: pattern, action, false positive rate estimate
  - Benchmark results (small/medium/large repos)
- [ ] Add `cloak detectors list` command (CLI introspection)
- [ ] Compare to competitors (ggshield, gitleaks) in table
- [ ] Document custom detector authoring

**Content**:
```markdown
## Built-in Detectors (v0.3.2)

| ID | Pattern | Default Action | FP Rate |
|----|---------|----------------|---------|
| aws_access_key | AKIA[A-Z0-9]{16} | block | <0.1% |
| gcp_api_key | AIza[0-9A-Za-z_-]{35} | block | <0.1% |
| jwt_token | [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+ | pseudonymize | ~2% |
| email | [a-z0-9.+-]+@[a-z0-9-]+\.[a-z0-9.-]+ | template | ~1% |
| ... | ... | ... | ... |

**Total**: 18 detectors (as of v0.3.2)
```

---

#### 2.4 Automated HMAC Tests
**Time**: 2-3 hours
**Rationale**:
- Previous session: only manual testing done
- Critical for CI/CD confidence

**Tasks**:
- [ ] Add `tests/test_hmac_determinism.py`:
  - Test same secret → same tag (100 iterations)
  - Test different secrets → different tags
  - Test vault roundtrip (pack + unpack)
  - Test tag format (PREFIX-[0-9a-f]{12})
- [ ] Add `tests/test_vault_encryption.py`:
  - Test vault creation
  - Test key loading/generation
  - Test Fernet encryption/decryption
- [ ] Add to CI (GitHub Actions or local pre-commit)

---

### Release: v0.3.2-alpha

**Changelog**:
```markdown
### v0.3.2-alpha (2025-11-1X)

**Features**:
- Added `cloak vault rekey` (key rotation with atomic rollback)
- Added group policy support (inherit from organization baselines)
- Added `cloak policy validate|show` commands
- Added `cloak detectors list` (introspection)

**Documentation**:
- Added `/docs/DETECTORS.md` (complete detector catalog)
- Added `/docs/POLICIES.md` (policy hierarchy guide)
- Added key rotation best practices

**Testing**:
- Added automated HMAC determinism tests
- Added vault encryption tests
- CI integration (pre-commit hooks)

**Migration**:
- No breaking changes (fully backward compatible with v0.3.1)
```

**Estimated Time**: 14-20 hours (1 week)

---

## Phase 3: Stabilization (v0.4.0 Stable) — 1 week

### Priority: MEDIUM (Production Readiness)

#### 3.1 AES-256 Option (or Justification)
**Time**: 4-6 hours
**Rationale**:
- Review: "AES-128 vs expectations — security people will ask"

**Option A**: Add AES-256 support
```yaml
# mcp_policy.yaml
globals:
  vault:
    encryption: aes-256-gcm  # or 'aes-128-gcm' (default)
```

**Option B**: Justify AES-128 in docs
```markdown
## Why AES-128?

CloakMCP uses Fernet (AES-128-CBC + HMAC) because:
1. **Authenticated encryption** (AEAD) prevents tampering
2. **128-bit is sufficient** for all practical attacks (NIST approved through 2030+)
3. **Battle-tested** (cryptography.io, used by millions)
4. **Future-proof**: Migrating to AES-256 is trivial if quantum computing advances

**If you require AES-256**: See docs/CUSTOM_CRYPTO.md for pluggable backend.
```

**Decision**: Start with Option B (documentation), add Option A in v0.5.0 if requested.

---

#### 3.2 Hierarchical CLI Commands
**Time**: 3-4 hours
**Rationale**:
- Review: "Mixing `cloak scan/sanitize/pack/unpack` and `vault-export/import/stats` is crowded"

**Refactor**:
```bash
# Before (v0.3.x)
cloak vault-export
cloak vault-import
cloak vault-stats

# After (v0.4.0)
cloak vault export
cloak vault import
cloak vault stats
cloak vault rekey
cloak vault list
```

**Tasks**:
- [ ] Refactor CLI to use subparsers (2 levels)
- [ ] Maintain backward compatibility (aliases for old commands)
- [ ] Update all documentation
- [ ] Add `cloak help vault` (context-sensitive help)

**Breaking Change**: NO (old commands still work, deprecated with warning)

---

#### 3.3 Performance Benchmarks
**Time**: 4-6 hours
**Rationale**:
- Review: "Does not state performance characteristics at scale"

**Tasks**:
- [ ] Create `benchmarks/` directory:
  - Small repo (<100 files, <1MB)
  - Medium repo (1K files, ~50MB)
  - Large repo (10K files, ~500MB, vendor dirs)
- [ ] Benchmark metrics:
  - Pack time (first run)
  - Pack time (no changes)
  - Unpack time
  - Memory usage
  - Vault size
- [ ] Add results to `/docs/PERFORMANCE.md`
- [ ] Compare to ggshield/gitleaks (if fair)

**Expected Results** (target):
- Small: <1s pack, <0.5s unpack
- Medium: <10s pack, <3s unpack
- Large: <60s pack, <20s unpack (with proper .mcpignore)

---

#### 3.4 Final Documentation Polish
**Time**: 4-6 hours

**Tasks**:
- [ ] Move README heavy content to `/docs`:
  - `/docs/ARCHITECTURE.md` (Mermaid diagrams)
  - `/docs/SERVER.md` (already exists, verify)
  - `/docs/VSCODE.md` (IDE integration)
- [ ] README.md → <500 lines:
  - 2-min quick start (already added)
  - Comparison table (already added)
  - Link to docs for deep dives
- [ ] Add `/docs/MIGRATION.md`:
  - v0.2.5 → v0.3.1 (HMAC breaking change)
  - v0.3.1 → v0.3.1 (binary rename)
  - v0.3.1 → v0.4.0 (no breaking changes)
- [ ] Add `/docs/FAQ.md` (frequently asked questions)
- [ ] Review all docs for consistency (version numbers, commands, etc.)

---

### Release: v0.4.0 (Stable)

**Changelog**:
```markdown
### v0.4.0 (2025-11-2X) — Stable Release

**Stabilization**:
- Promoted from alpha to stable (production-ready)
- Comprehensive test coverage (unit + integration + benchmarks)
- Performance benchmarks published (see docs/PERFORMANCE.md)
- Complete documentation overhaul

**Features**:
- Hierarchical CLI commands (`cloak vault export`)
- AES-128 justification (or AES-256 option)
- Complete detector catalog (18 built-in detectors)
- Group policy inheritance
- Key rotation with atomic rollback
- Auto-backup (enabled by default)
- Dry-run mode for all destructive operations

**Security**:
- HMAC-based tags (v0.3.1)
- Fernet AES-128-CBC + HMAC vault encryption
- Explicit threat model (docs/THREAT_MODEL.md)
- Accurate security claims (no overclaiming)

**Documentation**:
- Complete `/docs` directory (10+ guides)
- Migration guides for all versions
- FAQ, troubleshooting, best practices
- Performance benchmarks

**Breaking Changes** (since v0.2.5):
- v0.3.1: HMAC tags (old vaults incompatible)
- v0.3.1: Binary rename (`cloak` → `cloak`)

**Migration**:
- From v0.3.2: No changes required (drop-in replacement)
- From v0.3.1/v0.3.1: Update scripts to use `cloak` binary
- From v0.2.5: Re-pack repositories (vault format changed)
```

**Estimated Time**: 15-20 hours (1 week)

---

## Summary Timeline

| Phase | Version | Duration | Key Deliverables |
|-------|---------|----------|------------------|
| **Phase 1** | v0.3.1 | 1 week | Binary rename, dry-run, auto-backup, threat model |
| **Phase 2** | v0.3.2 | 1 week | Key rotation, group policies, detector docs, tests |
| **Phase 3** | v0.4.0 | 1 week | Stabilization, benchmarks, docs polish, stable release |
| **Total** | | **3 weeks** | Production-ready v0.4.0 |

---

## Prioritized Task List (Next Session)

### Immediate (Today/Tomorrow)
1. ✅ Read this plan
2. ✅ Decide on binary name: **`cloak`** (recommended)
3. 🔴 Execute Phase 1.1: Binary rename (6-8 hours)
4. 🔴 Execute Phase 1.2: Add `--dry-run` (4-6 hours)

### This Week (Phase 1)
5. 🟠 Execute Phase 1.3: Auto-backup (3-4 hours)
6. 🟠 Execute Phase 1.4: THREAT_MODEL.md (2 hours)
7. 🟠 Release v0.3.1-alpha

### Next Week (Phase 2)
8. 🟡 Execute Phase 2.1: Key rotation (4-6 hours)
9. 🟡 Execute Phase 2.2: Group policies (6-8 hours)
10. 🟡 Execute Phase 2.3: Detector docs (2-3 hours)
11. 🟡 Execute Phase 2.4: Automated tests (2-3 hours)
12. 🟡 Release v0.3.2-alpha

### Following Week (Phase 3)
13. 🟢 Execute Phase 3.1: AES justification (4-6 hours)
14. 🟢 Execute Phase 3.2: Hierarchical CLI (3-4 hours)
15. 🟢 Execute Phase 3.3: Benchmarks (4-6 hours)
16. 🟢 Execute Phase 3.4: Docs polish (4-6 hours)
17. 🟢 Release v0.4.0 (Stable)

---

## Critical Decisions Needed

### 1. Binary Name (HIGH PRIORITY)
**Options**:
- ✅ **`cloak`** (recommended: short, memorable, thematic)
- ❌ `cloakmcp` (too long)
- ❌ `cloak-llm` (hyphen awkward in CLI)

**Decision**: Please confirm **`cloak`** or suggest alternative.

### 2. v0.3.1 Scope
**Should we bundle**:
- Binary rename (mandatory)
- Dry-run (mandatory)
- Auto-backup (recommended)
- Threat model (recommended)

**OR split into**:
- v0.3.1: Binary rename + dry-run (minimal breaking change)
- v0.3.2: Auto-backup + threat model (additive)

**Recommendation**: Bundle all in v0.3.1 (users upgrade once, not twice).

### 3. AES-256 Priority
**Options**:
- Option A: Document AES-128 justification (2 hours) — recommended for v0.4.0
- Option B: Add AES-256 support (4-6 hours) — defer to v0.5.0
- Option C: Make AES-256 default (8-10 hours + vault migration) — defer to v1.0.0

**Recommendation**: Start with Option A, gauge user feedback.

### 4. Release Cadence
**Options**:
- Fast track: 1 release per week (aggressive, risky)
- Steady: 1 release per 2 weeks (recommended)
- Conservative: 1 release per month (too slow)

**Recommendation**: 1 release per week for v0.3.1-alpha and v0.3.2-alpha, then 2-week soak for v0.4.0 stable.

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Binary rename breaks user scripts | HIGH | MEDIUM | Provide migration guide, keep old binary as symlink for 1 release |
| Group policy inheritance bugs | MEDIUM | MEDIUM | Extensive testing, dry-run mode, clear error messages |
| Performance degrades on large repos | MEDIUM | HIGH | Benchmark early, optimize .mcpignore, add progress indicators |
| Key rotation corrupts vault | LOW | CRITICAL | Atomic operations, mandatory backups, extensive testing |
| AES-128 controversy | MEDIUM | LOW | Document justification clearly, offer future upgrade path |

---

## Success Metrics

### v0.3.1-alpha
- ✅ Binary renamed without major breakage
- ✅ Dry-run prevents at least 1 user mistake (self-test)
- ✅ Auto-backup recovers from accidental pack (test case)
- ✅ THREAT_MODEL.md clarifies scope (qualitative)

### v0.3.2-alpha
- ✅ Key rotation tested on 10+ projects
- ✅ Group policy used by ≥2 teams (internal dogfooding)
- ✅ All tests pass (100% coverage on critical paths)
- ✅ Detector catalog complete (18+ detectors)

### v0.4.0 (Stable)
- ✅ Benchmarks published (performance acceptable)
- ✅ Documentation <500 lines in README, rest in /docs
- ✅ No critical bugs in 2-week soak period
- ✅ PyPI package published (optional, if ready)

---

## Next Steps

1. **Read and approve this plan** (or suggest changes)
2. **Confirm binary name**: `cloak` (or alternative)
3. **Execute Phase 1.1**: Binary rename (tomorrow, 6-8 hours)
4. **Update NEXT_SESSION_QUICK_START.md** with Phase 1 tasks

**Ready to proceed?** 🚀

---

**Author**: Claude (Sonnet 4.5) for Olivier Vitrac
**Date**: 2025-11-12
**Version**: Strategic Plan v1.0
**Status**: DRAFT — Awaiting approval
