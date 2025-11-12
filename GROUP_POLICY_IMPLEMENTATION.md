# Group Policy Implementation — IN PROGRESS

**Date**: 2025-11-12
**Version**: 0.3.2-alpha (in progress)
**Status**: Core logic complete, CLI commands pending

---

## ✅ Completed

### 1. Enhanced policy.py (DONE)
**File**: `mcp/policy.py`

**Features Implemented**:
- ✅ `inherits` field support in YAML
- ✅ Recursive policy loading with cycle detection
- ✅ Policy merging (later overrides earlier)
- ✅ Relative path resolution (relative to policy file)
- ✅ `~` expansion for home directory
- ✅ Inheritance chain tracking (`_inherits_from`)
- ✅ `validate_policy()` function (checks rules, actions, fields)
- ✅ `policy_to_yaml()` function (converts Policy → YAML with comments)
- ✅ `_merge_policy_dicts()` (deep merge of globals, rules, whitelist/blacklist)

**Merging Rules**:
1. **Globals**: Override values replace base values
2. **Detection rules**: Rules with same `id` are replaced, others appended
3. **Whitelist/blacklist**: Lists concatenated (no deduplication)

**Example Usage**:
```python
from mcp.policy import Policy

# Load policy with inheritance
policy = Policy.load("examples/project-policy.yaml")

# Validate policy
is_valid, errors = validate_policy("examples/project-policy.yaml")

# Convert to YAML
yaml_str = policy_to_yaml(policy, include_inheritance=True)
```

---

## 🔴 TODO: CLI Commands

### 2. Add `cloak policy` subcommand

**File to modify**: `mcp/cli.py`

**Add to main()** (after line 115):
```python
# Policy management commands
s_policy = sub.add_parser("policy", help="Policy management")
policy_sub = s_policy.add_subparsers(dest="policy_cmd", required=True)

s_policy_validate = policy_sub.add_parser("validate", help="Validate policy file (including inheritance)")
s_policy_validate.add_argument("--policy", required=True, help="Policy file to validate")

s_policy_show = policy_sub.add_parser("show", help="Show merged policy (after inheritance)")
s_policy_show.add_argument("--policy", required=True, help="Policy file to show")
s_policy_show.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output format")
```

**Add handler** (after line 175):
```python
if args.cmd == "policy":
    if args.policy_cmd == "validate":
        from .policy import validate_policy
        _validate_policy_path(args.policy)
        is_valid, errors = validate_policy(args.policy)
        if is_valid:
            print(f"✓ Policy is valid: {args.policy}", file=sys.stderr)
            print(f"  Inheritance chain:", file=sys.stderr)
            policy = Policy.load(args.policy)
            for i, path in enumerate(policy._inherits_from, 1):
                print(f"    {i}. {path}", file=sys.stderr)
            sys.exit(0)
        else:
            print(f"✗ Policy validation failed: {args.policy}", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            sys.exit(1)

    elif args.policy_cmd == "show":
        from .policy import Policy, policy_to_yaml
        _validate_policy_path(args.policy)
        policy = Policy.load(args.policy)
        if args.format == "yaml":
            print(policy_to_yaml(policy, include_inheritance=True))
        elif args.format == "json":
            import json
            from .policy import _policy_to_dict
            data = _policy_to_dict(policy)
            print(json.dumps(data, indent=2))
        return
```

---

## 🔴 TODO: Example Policies

### 3. Create Company Baseline Policy

**File**: `examples/policies/company-baseline.yaml`

```yaml
# Company-Wide Baseline Policy
# This policy defines mandatory detection rules for all projects.
# Store in ~/.cloakmcp/policies/company-baseline.yaml

version: 1

globals:
  default_action: block  # Company standard: block by default
  audit:
    enabled: true
    include_value_hash: true

detection:
  # Company API keys (mandatory detection)
  - id: company_api_key
    type: regex
    pattern: '\bCOMP-[A-Z0-9]{32}\b'
    action: block
    note: "Company API keys must never be committed"

  # AWS keys (critical)
  - id: aws_access_key
    type: regex
    pattern: '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    action: block

  # Internal emails (pseudonymize for privacy)
  - id: internal_email
    type: regex
    pattern: '[a-z0-9.+-]+@(company\.com|internal\.company)'
    action: pseudonymize

  # High entropy tokens (stricter than default)
  - id: high_entropy_token
    type: entropy
    min_entropy: 4.8  # Company standard
    min_length: 20
    action: redact

blacklist:
  urls:
    - internal-api.company.com
    - staging.company.local
```

### 4. Create Team Policy

**File**: `examples/policies/team-backend.yaml`

```yaml
# Backend Team Policy
# Inherits from company baseline + adds team-specific rules

version: 1

inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml  # Company rules

detection:
  # Backend-specific secrets
  - id: database_connection_string
    type: regex
    pattern: '(postgresql|mysql|mongodb)://[^\s]+'
    action: block

  # Redis passwords
  - id: redis_password
    type: regex
    pattern: 'redis://:[^@]+@'
    action: block
```

### 5. Create Project Policy

**File**: `examples/project-with-inheritance.yaml`

```yaml
# Project-Specific Policy
# Inherits from company + team policies

version: 1

inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml
  - ~/.cloakmcp/policies/team-backend.yaml

globals:
  # Project-specific overrides
  default_action: redact  # Less strict than company default

  # Project-specific key (NOT shared)
  pseudonymization:
    method: hmac-sha256
    secret_key_file: ./keys/mcp_hmac_key  # PROJECT key
    salt: session

detection:
  # Project-specific secrets
  - id: project_api_token
    type: regex
    pattern: '\bPROJ-[A-Z0-9]{24}\b'
    action: block

  # Override company rule for this project
  - id: internal_email
    type: regex
    pattern: '[a-z0-9.+-]+@company\.com'
    action: redact  # Override: redact instead of pseudonymize
```

---

## 🔴 TODO: Directory Structure

### 6. Create ~/.cloakmcp/policies/

**Commands**:
```bash
mkdir -p ~/.cloakmcp/policies
cp examples/policies/company-baseline.yaml ~/.cloakmcp/policies/
chmod 644 ~/.cloakmcp/policies/*
```

**Add to README.md**:
```markdown
## Group Policies

CloakMCP supports policy inheritance for organization-wide standards:

```yaml
# Project policy
inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml  # Company rules
  - ./team-policy.yaml                         # Team rules

globals:
  default_action: redact  # Override company default

detection:
  - id: project_secret
    pattern: ...
```

**Distribution Methods**:
1. **Git** (recommended): `git clone company/cloak-policies ~/.cloakmcp/policies`
2. **Package**: `pip install company-cloak-policies`
3. **Manual**: Copy YAML files to `~/.cloakmcp/policies/`

**Security**: Policies contain RULES, not KEYS. Each project has its own vault.
```

---

## 🔴 TODO: Testing

### 7. Test Policy Inheritance

**File**: `tests/test_policy_inheritance.py`

```python
import pytest
from pathlib import Path
from mcp.policy import Policy, validate_policy
import tempfile
import os

def test_simple_inheritance(tmp_path):
    """Test basic policy inheritance."""
    # Create parent policy
    parent = tmp_path / "parent.yaml"
    parent.write_text("""
version: 1
globals:
  default_action: block
detection:
  - id: test_rule
    type: regex
    pattern: 'TEST'
    action: redact
""")

    # Create child policy
    child = tmp_path / "child.yaml"
    child.write_text(f"""
version: 1
inherits:
  - {parent}
detection:
  - id: child_rule
    type: regex
    pattern: 'CHILD'
    action: block
""")

    # Load child (should have both rules)
    policy = Policy.load(str(child))
    assert len(policy.rules) == 2
    assert {r.id for r in policy.rules} == {"test_rule", "child_rule"}

def test_rule_override(tmp_path):
    """Test that child can override parent rules."""
    parent = tmp_path / "parent.yaml"
    parent.write_text("""
version: 1
detection:
  - id: test_rule
    type: regex
    pattern: 'TEST'
    action: redact
""")

    child = tmp_path / "child.yaml"
    child.write_text(f"""
version: 1
inherits:
  - {parent}
detection:
  - id: test_rule
    type: regex
    pattern: 'TEST'
    action: block  # Override action
""")

    policy = Policy.load(str(child))
    assert len(policy.rules) == 1
    assert policy.rules[0].action == "block"  # Child overrides

def test_circular_inheritance(tmp_path):
    """Test that circular inheritance is detected."""
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"

    a.write_text(f"""
version: 1
inherits:
  - {b}
""")

    b.write_text(f"""
version: 1
inherits:
  - {a}
""")

    with pytest.raises(ValueError, match="Circular inheritance"):
        Policy.load(str(a))

def test_three_level_inheritance(tmp_path):
    """Test 3-level inheritance: company → team → project."""
    company = tmp_path / "company.yaml"
    company.write_text("""
version: 1
globals:
  default_action: block
detection:
  - id: company_rule
    type: regex
    pattern: 'COMPANY'
    action: block
""")

    team = tmp_path / "team.yaml"
    team.write_text(f"""
version: 1
inherits:
  - {company}
detection:
  - id: team_rule
    type: regex
    pattern: 'TEAM'
    action: redact
""")

    project = tmp_path / "project.yaml"
    project.write_text(f"""
version: 1
inherits:
  - {team}
globals:
  default_action: redact  # Override
detection:
  - id: project_rule
    type: regex
    pattern: 'PROJECT'
    action: pseudonymize
""")

    policy = Policy.load(str(project))
    assert len(policy.rules) == 3
    assert policy.globals.default_action == "redact"  # Project override
    assert {r.id for r in policy.rules} == {"company_rule", "team_rule", "project_rule"}
```

**Run tests**:
```bash
pytest tests/test_policy_inheritance.py -v
```

---

## 🔴 TODO: Documentation Updates

### 8. Update QUICKREF.md

Add section:
```markdown
## Policy Inheritance

### Create organization baseline
```bash
# Save to ~/.cloakmcp/policies/company-baseline.yaml
version: 1
globals:
  default_action: block
detection:
  - id: company_api_key
    pattern: '\bCOMP-[A-Z0-9]{32}\b'
    action: block
```

### Use in project
```bash
# Project policy inherits from company
inherits:
  - ~/.cloakmcp/policies/company-baseline.yaml

globals:
  default_action: redact  # Override for this project

detection:
  - id: project_secret
    pattern: ...
```

### Validate & show merged policy
```bash
cloak policy validate --policy examples/mcp_policy.yaml
cloak policy show --policy examples/mcp_policy.yaml
```

### Merging rules
- Later policies override earlier ones
- Rules with same ID are replaced
- Whitelist/blacklist lists are concatenated
```

---

## 📋 Implementation Checklist

- [x] Enhanced `mcp/policy.py` with inheritance
- [x] Cycle detection
- [x] Policy merging logic
- [x] Validation function
- [x] YAML export function
- [ ] Add `cloak policy validate` command to CLI
- [ ] Add `cloak policy show` command to CLI
- [ ] Create example policies (company, team, project)
- [ ] Create `~/.cloakmcp/policies/` directory
- [ ] Write policy inheritance tests
- [ ] Update documentation (README, QUICKREF)
- [ ] Test end-to-end inheritance
- [ ] Update version to 0.3.2
- [ ] Git commit

---

## 🚀 Next Steps (When Resuming)

1. **Add CLI commands** (30 min):
   - `cloak policy validate`
   - `cloak policy show`

2. **Create example policies** (20 min):
   - `examples/policies/company-baseline.yaml`
   - `examples/policies/team-backend.yaml`
   - `examples/project-with-inheritance.yaml`

3. **Write tests** (30 min):
   - `tests/test_policy_inheritance.py`

4. **Update docs** (20 min):
   - README.md (add Group Policy section)
   - QUICKREF.md (add commands)

5. **Test & commit** (20 min):
   - Test inheritance manually
   - Run pytest
   - Git commit as v0.3.2-alpha

**Total remaining**: ~2 hours

---

## 🎯 Testing Commands (Manual)

```bash
# 1. Create test policies
mkdir -p ~/.cloakmcp/policies
cat > ~/.cloakmcp/policies/test-base.yaml << 'EOF'
version: 1
globals:
  default_action: block
detection:
  - id: test_secret
    type: regex
    pattern: 'SECRET-[A-Z0-9]+'
    action: redact
EOF

# 2. Create child policy
cat > /tmp/test-child.yaml << 'EOF'
version: 1
inherits:
  - ~/.cloakmcp/policies/test-base.yaml
detection:
  - id: child_secret
    type: regex
    pattern: 'CHILD-[A-Z0-9]+'
    action: block
EOF

# 3. Test loading
python3 << 'PYTHON'
from mcp.policy import Policy
p = Policy.load("/tmp/test-child.yaml")
print(f"Rules: {len(p.rules)}")
for r in p.rules:
    print(f"  - {r.id}: {r.action}")
print(f"Inheritance chain:")
for path in p._inherits_from:
    print(f"  {path}")
PYTHON

# 4. Test validation
# (after CLI commands added)
cloak policy validate --policy /tmp/test-child.yaml
cloak policy show --policy /tmp/test-child.yaml
```

---

**Status**: Core logic complete, CLI/docs/tests pending (~2 hours remaining)
**Ready for**: CLI command implementation
