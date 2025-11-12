# NEXT SESSION — QUICK START

**Resume From**: 2025-11-11 23:00 UTC
**Version**: 0.3.1-alpha
**Status**: ✅ Released to GitHub, ready for next phase

---

## ⚡ QUICK SUMMARY

### ✅ What Was Completed This Session
1. **HMAC testing**: ✅ PASSED - Deterministic tags verified
2. **pyproject.toml fix**: ✅ Package discovery issue resolved
3. **Git commit**: ✅ `a72b08e` created with full changelog
4. **Git tag**: ✅ `v0.3.1-alpha` created
5. **GitHub push**: ✅ Deployed to origin/main with tags
6. **Testing verified**:
   - Tags are deterministic: `TAG-67869511f279`, `TAG-ab859d12656e`, `TAG-0855cded1681`
   - Unpack restores original secrets correctly
   - Pack/unpack roundtrip works perfectly

### 🎉 v0.3.1-alpha is LIVE
- **GitHub**: https://github.com/ovitrac/CloakMCP
- **Commit**: `a72b08e` - "v0.3.1-alpha: Critical security hardening"
- **Tag**: `v0.3.1-alpha`

---

## 🎯 FIRST 3 THINGS TO DO NEXT SESSION

### 1. **Verify GitHub Release** (5 minutes)
```bash
# Check the release is visible
open https://github.com/ovitrac/CloakMCP/releases

# Verify tag
git ls-remote --tags origin
```

### 2. **Binary Rename Decision** (HIGH PRIORITY)
**Issue**: `cloak` conflicts with Anthropic's Model Context Protocol

**Option A**: Rename now (2-3 hours)
- Rename to `cloak` (recommended name)
- Update ~20 files (code, docs, tests, examples)
- Create v0.3.1 or v0.4.0

**Option B**: Defer to v0.4.0
- Let v0.3.1-alpha get user feedback first
- Plan comprehensive rename with user migration guide

**Decision needed**: Choose A or B

### 3. **Plan Next Feature Phase** (Choose one)
**Option 1**: Pack/Unpack Safety (HIGH - 4-6 hours)
- Add `--dry-run` flag (preview changes)
- Add `--backup` flag (auto-backup before modification)
- Add confirmation prompts for destructive operations

**Option 2**: Key Rotation (MEDIUM - 3-4 hours)
- Implement `cloak vault rekey` command
- Re-encrypt vault with new key
- Update documentation

**Option 3**: Testing & Stabilization (MEDIUM - 2-3 hours)
- Add automated HMAC tests
- Improve error messages
- Add vault compatibility detection

---

## 📊 CURRENT PROJECT STATUS

### Version Info
- **Version**: 0.3.1-alpha
- **Last Commit**: `a72b08e` (2025-11-11)
- **GitHub**: https://github.com/ovitrac/CloakMCP
- **Python**: Requires Python >=3.10

### Installation Status
- ✅ Virtual environment: `.venv/` exists
- ✅ Package installed: `pip install -e .` completed
- ✅ CLI working: `cloak --help` verified
- ✅ Dependencies: All installed (pyyaml, fastapi, uvicorn, pydantic, cryptography)

### Security Fixes Deployed
- ✅ HMAC-SHA256 tags (keyed with vault key)
- ✅ 3 critical server warnings added
- ✅ All security claims accurate
- ✅ Breaking change documented

### Known Issues
1. **Binary name collision**: `cloak` vs Anthropic MCP (high priority to fix)
2. **No --dry-run mode**: Pack/unpack are destructive (medium priority)
3. **No automated HMAC tests**: Only manual testing done (low priority)

---

## 🧪 VERIFICATION COMMANDS

```bash
# Activate environment
cd ~/Documents/Adservio/Projects/CloakMCP
source .venv/bin/activate

# Verify version
python3 -c "import cloak; print(f'Version: {cloak.__version__}')"
# Should output: Version: 0.3.1

# Test CLI
cloak --help

# Quick test pack/unpack
cd /tmp && mkdir -p test-verify && cd test-verify
echo "SECRET=test123" > test.py
cloak pack --policy ~/Documents/Adservio/Projects/CloakMCP/examples/mcp_policy.yaml --dir .
cat test.py  # Should show TAG-xxxxx
cloak unpack --dir .
cat test.py  # Should show SECRET=test123
cd ~ && rm -rf /tmp/test-verify

# Check git status
cd ~/Documents/Adservio/Projects/CloakMCP
git status  # Should be clean
git log --oneline -3
git tag -l
```

---

## 📁 KEY FILES TO READ

1. **V0.3.1_SECURITY_RELEASE_SUMMARY.md** — Complete release notes
2. **PROJECT_STATE_v0.3.1.md** — Full project state (pre-release)
3. **README.md** — Updated with quick start & comparison table
4. **SERVER.md** — Security warnings for network exposure
5. **TODO – REVIEW of v. 0.25.md** — Original external review

---

## 🔴 HIGH PRIORITY NEXT STEPS (From Review)

### 1. **Binary Rename** (HIGH)
`cloak` conflicts with Anthropic's Model Context Protocol

**Recommendation**: `cloak` (short, memorable, thematic)

**Files to update** (~20 files):
- `pyproject.toml` (entry point: `cloak = "cloak.cli:main"`)
- All `*.md` files (README, SERVER, QUICKREF, etc.)
- `.vscode/tasks.json` & `keybindings.json`
- Test files
- Example code

**Commands**:
```bash
# Find all references
cd ~/Documents/Adservio/Projects/CloakMCP
grep -r "cloak " --include="*.md" --include="*.py" | wc -l

# After renaming
git commit -m "Rename binary: cloak → cloak (fix Anthropic MCP collision)"
```

**Estimated**: 2-3 hours

### 2. **Pack/Unpack Safety** (HIGH)
Add safety features to prevent accidental data loss

**Features**:
- `--dry-run`: Preview changes without modifying files
- `--backup`: Auto-create backup before pack/unpack
- Confirmation prompts for destructive operations
- Better error messages for vault issues

**Estimated**: 4-6 hours

### 3. **Key Rotation Command** (MEDIUM)
`cloak vault rekey` for vault re-encryption

**Features**:
- Generate new vault key
- Re-encrypt all tags with new key
- Preserve tag-to-secret mappings
- Atomic operation (rollback on failure)

**Estimated**: 3-4 hours

---

## 🟡 MEDIUM PRIORITY

### 1. **Automated Testing** (2-3 hours)
- Add pytest tests for HMAC determinism
- Test vault creation/loading
- Test pack/unpack roundtrip
- Add CI/CD integration

### 2. **Documentation Polish** (1-2 hours)
- Add THREAT_MODEL.md
- Clarify detection scope
- Add troubleshooting guide
- Improve examples

### 3. **CLI Improvements** (2 hours)
- Hierarchical commands (`cloak vault stats`, `cloak vault export`)
- Better progress indicators
- Colored output for warnings
- Verbose mode

---

## 🟢 LOW PRIORITY (Future)

1. **AES-256 Upgrade** (consider vs AES-128)
2. **VS Code Extension** (dedicated extension vs tasks)
3. **Performance Optimization** (large repos)
4. **Multi-vault Support** (different projects, different keys)
5. **Cloud KMS Integration** (optional, local-first priority)

---

## 💾 BACKUP INFO

**Last Backup**: `.backups/20251111_202023_pre_v0.3.1/`

**Create New Backup**:
```bash
cd ~/Documents/Adservio/Projects/CloakMCP
BACKUP_DIR=".backups/$(date +%Y%m%d_%H%M%S)_pre_next_phase"
mkdir -p "$BACKUP_DIR"
cp -r cloak tests examples *.md pyproject.toml "$BACKUP_DIR/"
echo "Backup created: $BACKUP_DIR"
```

---

## 🎯 DECISION TREE FOR NEXT SESSION

**START HERE**:

1. **Do you want to release v0.3.1-alpha "as is" for user feedback?**
   - YES → Skip binary rename, monitor GitHub issues
   - NO → Proceed to step 2

2. **Is the binary name collision a blocker?**
   - YES → Rename now (`cloak` → `cloak`), bump to v0.3.1
   - NO → Defer to v0.4.0, proceed to step 3

3. **What's the most valuable next feature?**
   - Safety features → Implement `--dry-run` & `--backup`
   - Key management → Implement `cloak vault rekey`
   - Stability → Add automated tests & improve docs

---

## 📝 NOTES FROM THIS SESSION

### Fixed Issues
1. **pyproject.toml**: Added `[build-system]` and `[tool.setuptools.packages.find]` to fix package discovery error
2. **HMAC Testing**: Verified deterministic tag generation works correctly
3. **Git Workflow**: Successfully committed and tagged v0.3.1-alpha

### Test Results
```
Test File: /tmp/test-hmac/config.py
Original:
  EMAIL = "alice@example.com"
  AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
  JWT = "eyJhbGci..."

After Pack (1st):
  EMAIL = "TAG-67869511f279"
  AWS_KEY = "TAG-ab859d12656e"
  JWT = "TAG-0855cded1681"

After Unpack:
  (Restored to original)

After Pack (2nd):
  EMAIL = "TAG-67869511f279"  ← SAME TAG ✓
  AWS_KEY = "TAG-ab859d12656e" ← SAME TAG ✓
  JWT = "TAG-0855cded1681"    ← SAME TAG ✓
```

**RESULT**: ✅ HMAC determinism confirmed

### Vault Location
```
~/.cloakmcp/
├── keys/
│   └── <project-slug>.key
└── vaults/
    └── <project-slug>.vault
```

---

## ⚠️ IMPORTANT REMINDERS

1. **Breaking Change**: v0.3.1 vaults incompatible with v0.2.5
2. **GitHub Release**: Create a GitHub Release with notes from `V0.3.1_SECURITY_RELEASE_SUMMARY.md`
3. **User Communication**: If you have users on v0.2.5, warn them about vault incompatibility
4. **Binary Rename**: High priority due to Anthropic MCP collision

---

## 🚀 RECOMMENDED NEXT SESSION PLAN

**Total Time**: ~3-4 hours

1. **Verify Release** (5 min)
   - Check GitHub
   - Verify tag is visible

2. **Binary Rename** (2-3 hours) - HIGH PRIORITY
   - Rename `cloak` → `cloak`
   - Update all documentation
   - Test CLI works
   - Commit as v0.3.1

3. **Create GitHub Release** (30 min)
   - Use `V0.3.1_SECURITY_RELEASE_SUMMARY.md` as release notes
   - Mark as pre-release (alpha)
   - Add breaking change warnings

4. **Plan v0.4.0 Features** (30 min)
   - Review user feedback (if any)
   - Prioritize safety features or key rotation
   - Create detailed implementation plan

---

**Status**: ✅ v0.3.1-alpha released and ready
**Next Step**: Binary rename or user feedback cycle
**Time to Next Release**: 2-4 hours (if renaming) or 1 week (if waiting for feedback)

---

**Full Details**: See `PROJECT_STATE_v0.3.1.md` and `V0.3.1_SECURITY_RELEASE_SUMMARY.md`

**GitHub**: https://github.com/ovitrac/CloakMCP
