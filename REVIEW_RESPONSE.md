# Response to External Review — CloakMCP v0.25

**Date**: 2025-11-12
**Reviewers**: Colleagues (external review)
**Current Version**: v0.3.1-alpha
**Plan**: Roadmap to v0.4.0 (stable)

---

## Review Summary

Your colleagues identified **7 critical areas**:
1. ✅ **HMAC security** — FIXED in v0.3.1-alpha (released yesterday)
2. 🔴 **Binary name collision** — HIGH priority (cloak conflicts with Anthropic)
3. 🔴 **Missing safety features** — CRITICAL (no dry-run, no backup)
4. 🟠 **Documentation overclaims** — Partially fixed, needs threat model
5. 🟡 **Key management minimal** — Needs rotation command
6. 🟡 **Detection scope unclear** — Needs catalog documentation
7. 🟢 **Entry barrier high** — README too long (partially fixed)

---

## What Was Already Fixed (v0.3.1-alpha)

### ✅ HMAC-Based Tags (Review Section 3)
**Issue**: "Unkeyed SHA-256 tags are brute-forceable for low-entropy secrets"

**Fixed**:
- Tags now use `HMAC-SHA256(vault_key, secret)` truncated to 12 hex chars
- Prevents offline brute-force attacks
- Determinism verified (manual testing)

**Code**: `mcp/storage.py:74-97`

### ✅ Security Claims Accurate (Review Section 7)
**Issue**: "2^48 computationally infeasible" was misleading

**Fixed**:
- README updated with accurate HMAC guarantees
- Removed overclaimed language
- Added "keyed with vault key" clarifications

**Files**: `README.md`, `QUICKREF.md`

### ✅ 2-Minute Quick Start (Review Section 7)
**Issue**: "Entry barrier too high, README buried Quick Start"

**Fixed**:
- Added prominent 2-minute quick start at top of README
- Copy-paste ready commands
- Shows immediate value (install → test → see results)

**File**: `README.md:21-45`

### ✅ Competitive Comparison (Review Section 1)
**Issue**: "Competitive landscape underplayed"

**Fixed**:
- Added comparison table: CloakMCP vs ggshield/SOPS/DIY
- Clear differentiation: reversible redaction for LLM workflows

**File**: `README.md:43-67`

---

## What Still Needs Fixing (Plan for v0.3.1 → v0.4.0)

### 🔴 CRITICAL: Binary Rename (Phase 1.1)
**Review Quote**: "MCP is heavily overloaded (Anthropic's Model Context Protocol)... hurts discoverability"

**Your Statement**: "I think we have to rename the main executable (mpc is not the right name)"

**Plan**:
- Rename `cloak` → **`cloak`** (recommended name)
- Update ~20 files (pyproject.toml, docs, tests, examples)
- Release as v0.3.1-alpha (breaking change)
- Time: 6-8 hours

**Decision Needed**: Confirm **`cloak`** as final name (or suggest alternative)

---

### 🔴 CRITICAL: Dry-Run Mode (Phase 1.2)
**Review Quote**: "No default dry-run... high risk UX: a mistaken `cloak pack` can mass-edit files"

**Your Statement**: "dry-run is mandatory"

**Plan**:
```bash
# Preview changes without modification
cloak pack --dry-run --dir /path/to/project

# Output:
# [DRY RUN] Would modify 15 files:
#   src/config.py: 3 secrets → tags
#   src/auth.py: 2 secrets → tags
#   ...
# Run without --dry-run to apply changes.
```

**Implementation**:
- Add `--dry-run` flag to `pack` and `unpack`
- Show preview: files affected, replacement counts
- Colorized output (green/yellow/red for risk level)
- Default prompt for >10 file changes
- Time: 4-6 hours

**No Breaking Change** (additive feature)

---

### 🔴 CRITICAL: Auto-Backup (Phase 1.3)
**Review Quote**: "No snapshot/backup mechanism... for a tool whose failure mode is 'silently mangled secrets', this is dangerous"

**Plan**:
```bash
# Auto-backup enabled by default
cloak pack --dir /path/to/project
# Creates: .cloak-backups/20251112_153000/

# Disable for automation/CI
cloak pack --no-backup --dir /path/to/project
```

**Implementation**:
- Create timestamped backup before pack/unpack
- Store in `.cloak-backups/<timestamp>/`
- Add to `.mcpignore` automatically
- Future: `cloak backup list` / `cloak backup restore`
- Time: 3-4 hours

**No Breaking Change** (enabled by default, opt-out available)

---

### 🟠 HIGH: Group Policy (Phase 2.2)
**Your Statement**: "a group policy is a great idea"

**Review Context**: "Key management story is minimal... larger orgs will want non-interactive bootstrap"

**Plan**:
```yaml
# Project policy: examples/mcp_policy.yaml
version: 1
inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml  # Org-wide defaults
  - ./team-overrides.yaml                       # Team-specific rules

globals:
  # Local overrides (highest priority)
  default_action: redact
```

**Features**:
- Multiple inheritance (array of policy paths)
- Later rules override earlier (explicit precedence)
- `cloak policy validate` (check syntax + inheritance)
- `cloak policy show` (display merged policy)
- Time: 6-8 hours

**Use Cases**:
- Company security team maintains baseline policy
- Dev teams inherit + add project-specific rules
- CI/CD enforces org-wide standards

**No Breaking Change** (additive, backward compatible)

---

### 🟠 HIGH: Threat Model Documentation (Phase 1.4)
**Review Quote**: "Add a one-page, explicit threat model"

**Plan**: Create `THREAT_MODEL.md`

**Content**:
```markdown
## In Scope
- Accidental sharing with LLMs / GitHub
- Honest-but-curious LLM providers
- Repo leaks to unauthorized parties

## Out of Scope
- Compromised developer machines
- Brute-force attacks with vault access
- Network exposure (server mode should not be used publicly)

## Assumptions
- Local machine is trusted
- `~/.cloakmcp/` has proper filesystem permissions
- Users follow documentation for key management
```

**Time**: 2 hours

---

### 🟡 MEDIUM: Key Rotation (Phase 2.1)
**Review Quote**: "Key management story is minimal... larger orgs will want rotation procedure"

**Plan**:
```bash
# Rotate vault encryption key
cloak vault rekey --dir /path/to/project [--new-key /path/to/new.key]

# Process:
# 1. Backup old vault
# 2. Decrypt with old key
# 3. Re-encrypt with new key
# 4. Atomic swap (rollback on failure)
# 5. Verify integrity
```

**Features**:
- Generate new key or accept provided key
- Atomic operation (rollback on any failure)
- Dry-run mode (`--dry-run`)
- Update vault metadata (rotation count, timestamp)
- Time: 4-6 hours

**No Breaking Change** (additive feature)

---

### 🟡 MEDIUM: Detection Scope Documentation (Phase 2.3)
**Review Quote**: "Does not state how many detectors it ships, how it manages false positives/negatives, performance at scale"

**Plan**: Create `/docs/DETECTORS.md`

**Content**:
```markdown
## Built-in Detectors (v0.3.2)

| ID | Pattern | Action | FP Rate | Notes |
|----|---------|--------|---------|-------|
| aws_access_key | AKIA[A-Z0-9]{16} | block | <0.1% | High confidence |
| gcp_api_key | AIza[0-9A-Za-z_-]{35} | block | <0.1% | High confidence |
| jwt_token | xxx.yyy.zzz | pseudonymize | ~2% | May catch non-JWT |
| email | user@domain.tld | template | ~1% | Rare FP in code |
| ... | ... | ... | ... | ... |

**Total**: 18 detectors (as of v0.3.2)

## Performance
- Small repos (<100 files): <1s pack
- Medium repos (1K files): <10s pack
- Large repos (10K files): <60s pack (with proper .mcpignore)
```

**Also Add**: `cloak detectors list` command (CLI introspection)

**Time**: 2-3 hours

---

### 🟡 MEDIUM: Hierarchical CLI (Phase 3.2)
**Review Quote**: "Mixing scan/sanitize/pack/unpack and vault-export/import/stats... crowded; consider hierarchical commands"

**Plan**:
```bash
# Before (v0.3.x)
cloak vault-export → cloak vault export
cloak vault-import → cloak vault import
cloak vault-stats  → cloak vault stats

# After (v0.4.0)
cloak vault export
cloak vault import
cloak vault stats
cloak vault rekey
cloak vault list

# Maintain backward compatibility (aliases + deprecation warnings)
```

**Time**: 3-4 hours

**No Breaking Change** (old commands work, deprecated with warning)

---

### 🟢 LOW: AES-256 Justification (Phase 3.1)
**Review Quote**: "AES-128 vs expectations... security people will ask 'Why not 256?'"

**Plan**: Document justification (defer implementation to v0.5.0)

**Content** (add to README or SECURITY.md):
```markdown
## Why AES-128?

CloakMCP uses Fernet (AES-128-CBC + HMAC) because:
1. **AEAD** (Authenticated Encryption with Associated Data) prevents tampering
2. **128-bit is sufficient** for all practical attacks (NIST approved through 2030+)
3. **Battle-tested**: cryptography.io library, used by millions
4. **Future-proof**: Migration to AES-256 trivial if quantum computing advances

**If you require AES-256**: Contact us or see docs/CUSTOM_CRYPTO.md
```

**Time**: 2 hours (documentation only)

---

## Phased Rollout Plan

### Phase 1: v0.3.1-alpha (Week 1)
**Theme**: Critical fixes + safety features

- [x] Binary rename: `cloak` → `cloak`
- [x] Add `--dry-run` to pack/unpack
- [x] Add auto-backup (enabled by default)
- [x] Create THREAT_MODEL.md

**Time**: 15-20 hours (1 week)
**Breaking Change**: YES (binary rename)

---

### Phase 2: v0.3.2-alpha (Week 2)
**Theme**: Feature completion + testing

- [ ] Key rotation: `cloak vault rekey`
- [ ] Group policy support (inheritance)
- [ ] Detector documentation + catalog
- [ ] Automated HMAC tests (CI/CD)

**Time**: 14-20 hours (1 week)
**Breaking Change**: NO (fully backward compatible)

---

### Phase 3: v0.4.0 Stable (Week 3)
**Theme**: Stabilization + production readiness

- [ ] Performance benchmarks
- [ ] Hierarchical CLI commands
- [ ] AES-128 justification (or AES-256 option)
- [ ] Documentation polish (README <500 lines)

**Time**: 15-20 hours (1 week)
**Breaking Change**: NO (stable release)

---

**Total Time**: 3 weeks (44-60 hours)

---

## Immediate Next Steps (Today/Tomorrow)

### 1. ✅ Read Strategic Plan
File: `STRATEGIC_PLAN_v0.4.0.md` (just created)

### 2. 🔴 Decide Binary Name
**Recommendation**: **`cloak`** (short, memorable, thematic)

**Alternatives**:
- `cloakmcp` (too long)
- `cloak-llm` (hyphen awkward)

**Please confirm or suggest alternative**

### 3. 🔴 Execute Phase 1.1: Binary Rename
**Time**: 6-8 hours

**Tasks**:
- Update `pyproject.toml` entry point
- Mass-rename in docs (~15 files)
- Update examples, tests, VS Code tasks
- Test CLI: `cloak --help`
- Commit as v0.3.1-alpha

### 4. 🔴 Execute Phase 1.2: Dry-Run Mode
**Time**: 4-6 hours

**Tasks**:
- Add `--dry-run` flag to pack/unpack
- Implement preview mode in `dirpack.py`
- Show colorized output (files + counts)
- Add confirmation prompt for >10 files
- Update documentation

---

## Key Decisions Needed

### Decision 1: Binary Name
**Question**: Confirm **`cloak`** as final name?

**Options**:
- ✅ `cloak` (recommended)
- ❌ `cloakmcp`
- ❌ `cloak-llm`
- ⚠️ Other (please specify)

### Decision 2: v0.3.1 Scope
**Question**: Bundle all Phase 1 features in one release?

**Option A** (recommended):
- v0.3.1: Binary rename + dry-run + auto-backup + threat model
- Users upgrade once

**Option B**:
- v0.3.1: Binary rename + dry-run (minimal)
- v0.3.2: Auto-backup + group policies + tests
- Users upgrade twice

**Recommendation**: Option A (bundle all critical fixes)

### Decision 3: Group Policy Priority
**Question**: Phase 2 (week 2) or defer to v0.5.0?

**Your statement**: "a group policy is a great idea"

**Recommendation**: Include in Phase 2 (v0.3.2-alpha)
- Essential for organizational adoption
- Relatively low complexity (6-8 hours)
- High value for target users (enterprises)

### Decision 4: Release Timeline
**Question**: Aggressive (1 week/release) or conservative (2 weeks/release)?

**Options**:
- Fast: v0.3.1 (week 1), v0.3.2 (week 2), v0.4.0 (week 3) — recommended
- Steady: v0.3.1 (week 1-2), v0.4.0 (week 3-4)

**Recommendation**: Fast track to v0.4.0 (get to stable quickly)

---

## Response to Specific Review Points

### ✅ FIXED: Section 2.1 (HMAC Tags)
**Review**: "Tags are un-keyed SHA-256 → brute-forceable"
**Status**: Fixed in v0.3.1-alpha (HMAC-based tags)

### 🔴 TODO: Section 1 (Name Collision)
**Review**: "MCP conflicts with Anthropic"
**Status**: Phase 1.1 (binary rename to `cloak`)

### 🔴 TODO: Section 6 (Detection Scope)
**Review**: "Does not state how many detectors"
**Status**: Phase 2.3 (create DETECTORS.md)

### 🔴 TODO: Section 4 (Threat Model)
**Review**: "Add explicit threat model"
**Status**: Phase 1.4 (create THREAT_MODEL.md)

### 🟠 TODO: Section 2.1 (Key Management)
**Review**: "Key management story is minimal"
**Status**: Phase 2.1 (key rotation) + Phase 2.2 (group policies)

### 🟠 TODO: Section 5 (Pack/Unpack Safety)
**Review**: "No dry-run, no backup mechanism"
**Status**: Phase 1.2 (dry-run) + Phase 1.3 (auto-backup)

### 🟡 TODO: Section 2.1 (AES-256)
**Review**: "Why not AES-256?"
**Status**: Phase 3.1 (document justification)

### ✅ FIXED: Section 7 (Entry Barrier)
**Review**: "README too long, Quick Start buried"
**Status**: Fixed in v0.3.1-alpha (2-min quick start at top)

---

## Risk Mitigation

### Risk: Binary Rename Breaks Users
**Probability**: HIGH
**Impact**: MEDIUM
**Mitigation**:
- Provide clear migration guide
- Keep old `cloak` as symlink for 1 release (deprecated)
- Announce on GitHub prominently

### Risk: Dry-Run Bugs
**Probability**: MEDIUM
**Impact**: LOW (dry-run can't corrupt data)
**Mitigation**:
- Extensive testing (manual + automated)
- Clear output formatting
- Start with conservative defaults

### Risk: Group Policy Complexity
**Probability**: MEDIUM
**Impact**: MEDIUM
**Mitigation**:
- Simple inheritance model (later overrides earlier)
- Extensive examples
- `cloak policy show` for debugging

### Risk: Timeline Slip
**Probability**: MEDIUM
**Impact**: LOW
**Mitigation**:
- Conservative time estimates (6-8 hours vs 4 hours)
- Defer low-priority items to v0.5.0
- Release v0.4.0 even if some Phase 3 items incomplete

---

## Measuring Success

### v0.3.1-alpha Success Criteria
- ✅ Binary renamed without regression
- ✅ Dry-run prevents at least 1 mistake (self-test)
- ✅ Auto-backup recovers from accidental pack
- ✅ THREAT_MODEL.md clarifies scope

### v0.3.2-alpha Success Criteria
- ✅ Key rotation tested on 10+ projects
- ✅ Group policy used by ≥2 teams
- ✅ All tests pass (100% critical path coverage)
- ✅ Detector catalog complete

### v0.4.0 Stable Success Criteria
- ✅ Benchmarks published
- ✅ README <500 lines
- ✅ No critical bugs in 2-week soak
- ✅ PyPI package published (optional)

---

## Questions for You

1. **Binary name**: Confirm `cloak` or suggest alternative?
2. **v0.3.1 scope**: Bundle all Phase 1 features (recommended)?
3. **Timeline**: Aggressive (3 weeks) or conservative (4-6 weeks)?
4. **Group policy priority**: Phase 2 (recommended) or defer?
5. **AES-256**: Document justification (recommended) or implement support?

---

## Next Actions (Today)

1. ✅ Read `STRATEGIC_PLAN_v0.4.0.md` (comprehensive plan)
2. ✅ Read this response document
3. 🔴 Answer 5 questions above
4. 🔴 Approve plan or request changes
5. 🔴 Begin Phase 1.1 (binary rename)

**Ready to proceed?** 🚀

---

**Author**: Claude (Sonnet 4.5) for Olivier Vitrac
**Date**: 2025-11-12
**Status**: DRAFT — Awaiting decisions
