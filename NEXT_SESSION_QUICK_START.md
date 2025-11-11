# NEXT SESSION — QUICK START

**Resume From**: 2025-11-11 20:30 UTC
**Version**: 0.3.0-alpha
**Status**: ✅ Security fixes complete, ready for testing

---

## ⚡ QUICK SUMMARY

### ✅ What Was Done Today
1. **CRITICAL FIX**: HMAC-based tags (prevents brute-force attacks)
2. **Server warnings**: 3 prominent security warnings added
3. **Version bump**: 0.2.5 → 0.3.0-alpha
4. **README enhanced**: 2-min quickstart + comparison table
5. **Full backup**: `.backups/20251111_202023_pre_v0.3.0/`

### ⚠️ BREAKING CHANGE
v0.3.0 vaults incompatible with v0.2.5 (HMAC vs plain SHA-256)

---

## 🎯 FIRST 3 THINGS TO DO

### 1. **Test HMAC Implementation** (30 minutes)
```bash
cd /tmp && mkdir test-hmac && cd test-hmac
echo "SECRET=sk_test_abc123" > config.py

# First pack
~/Documents/Adservio/Projects/CloakMCP/.venv/bin/mcp pack \
  --policy ~/Documents/Adservio/Projects/CloakMCP/examples/mcp_policy.yaml \
  --dir .
cat config.py  # Note the TAG-xxxxx

# Unpack
~/Documents/Adservio/Projects/CloakMCP/.venv/bin/mcp unpack --dir .
cat config.py  # Should show original secret

# Second pack (verify determinism)
~/Documents/Adservio/Projects/CloakMCP/.venv/bin/mcp pack \
  --policy ~/Documents/Adservio/Projects/CloakMCP/examples/mcp_policy.yaml \
  --dir .
cat config.py  # Should show SAME TAG-xxxxx (deterministic)

# ✅ SUCCESS: Tags are identical
# ❌ FAILURE: Tags differ (HMAC not deterministic)
```

### 2. **Git Commit & Tag** (10 minutes)
```bash
cd ~/Documents/Adservio/Projects/CloakMCP

git status
git add -A
git commit -m "v0.3.0-alpha: Critical security hardening

BREAKING CHANGES:
- HMAC-SHA256 tags (keyed) instead of plain SHA-256
- Existing vaults incompatible with v0.3.0

Security Fixes:
- HMAC tags prevent brute-force attacks
- Added 3 critical warnings for server network exposure
- Updated all security claims (accurate)

Documentation:
- Added 2-minute quick start to README
- Added competitive comparison table
- Created SERVER.md (20 KB)
- Added 5 Mermaid diagrams

Version: 0.2.5-beta → 0.3.0-alpha"

git tag -a v0.3.0-alpha -m "Security hardening release"
```

### 3. **Push to GitHub** (5 minutes)
```bash
git push origin main --tags
```

---

## 🔴 HIGH PRIORITY NEXT STEPS

### 1. **Binary Rename** (HIGH - Review Feedback)
`mcp` conflicts with Anthropic's Model Context Protocol

**Recommendation**: Rename to `cloak`

**Files to update** (~20 files):
- `pyproject.toml` (entry point)
- All `*.md` files with commands
- `.vscode/tasks.json`
- Test files

**Estimated**: 2-3 hours

### 2. **Pack/Unpack Safety** (HIGH - Review Feedback)
Add `--dry-run` and `--backup` flags

**Estimated**: 4-6 hours

### 3. **Key Rotation Command** (MEDIUM)
`mcp vault rekey` for vault re-encryption

**Estimated**: 3-4 hours

---

## 📁 KEY FILES TO READ

1. **PROJECT_STATE_v0.3.0.md** — Full state snapshot (this session)
2. **V0.3.0_SECURITY_RELEASE_SUMMARY.md** — Complete release notes
3. **IMMEDIATE_ACTION_COMPLETE.md** — Today's accomplishments
4. **README_v0.3.0_UPDATES.md** — README changes

---

## 🧪 TESTING COMMANDS

```bash
# Activate venv
cd ~/Documents/Adservio/Projects/CloakMCP
source .venv/bin/activate

# Run smoke test
python3 -m pytest tests/test_smoke.py -v

# Check version
python3 -c "import mcp; print(mcp.__version__)"
# Should output: 0.3.0

# Test CLI
mcp --help
```

---

## 💾 BACKUP INFO

**Location**: `.backups/20251111_202023_pre_v0.3.0/`

**Restore everything**:
```bash
cp -r .backups/20251111_202023_pre_v0.3.0/* .
```

---

## 🎯 DECISION NEEDED

**Choose release path**:

### Option 1: Quick Release (30 min)
- Test HMAC → Commit → Push
- Get security fixes deployed ASAP

### Option 2: Polish First (2-3 hours)
- Test HMAC → Binary rename → Commit → Push
- Better UX, no name collision

### Option 3: Full Enhancement (1 week)
- All above + safety features + key rotation
- Production-ready quality

**Recommendation**: **Option 1** or **Option 2**

---

## ⚠️ REMEMBER

1. **Tests passing**: ✅ Smoke test verified
2. **HMAC implemented**: ✅ Code complete
3. **Backup exists**: ✅ Can revert if needed
4. **Breaking change**: ⚠️ Warn users about vault incompatibility

---

**Status**: Ready for manual testing → commit → release
**Next Step**: Run HMAC test above
**Time to Release**: 30-45 minutes

---

**Full Details**: See `PROJECT_STATE_v0.3.0.md`
