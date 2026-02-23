from __future__ import annotations
import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

@dataclass
class PseudonymizationCfg:
    method: str
    secret_key_file: str
    salt: str

@dataclass
class GlobalsCfg:
    default_action: str
    audit_enabled: bool
    audit_path: str
    include_value_hash: bool
    pz: PseudonymizationCfg

@dataclass
class Rule:
    id: str
    type: str
    action: str
    pattern: Optional[str] = None
    template: Optional[str] = None
    whitelist: Optional[List[str]] = None
    whitelist_cidrs: Optional[List[str]] = None
    min_entropy: Optional[float] = None
    min_length: Optional[int] = None
    severity: Optional[str] = None
    whitelist_patterns: Optional[List[str]] = None

class Policy:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.version = raw.get("version", 1)
        g = raw.get("globals", {})
        audit = g.get("audit", {})
        pz = g.get("pseudonymization", {})
        self.globals = GlobalsCfg(
            default_action=g.get("default_action", "redact"),
            audit_enabled=bool(audit.get("enabled", True)),
            audit_path=audit.get("path", "./audit/audit.jsonl"),
            include_value_hash=bool(audit.get("include_value_hash", True)),
            pz=PseudonymizationCfg(
                method=pz.get("method", "hmac-sha256"),
                secret_key_file=pz.get("secret_key_file", "./keys/mcp_hmac_key"),
                salt=pz.get("salt", "session"),
            ),
        )
        self.whitelist = raw.get("whitelist", {})
        self.blacklist = raw.get("blacklist", {})
        self.rules: List[Rule] = []
        for r in raw.get("detection", []):
            self.rules.append(
                Rule(
                    id=r["id"],
                    type=r["type"],
                    action=r["action"],
                    pattern=r.get("pattern"),
                    template=r.get("template"),
                    whitelist=r.get("whitelist"),
                    whitelist_cidrs=r.get("whitelist_cidrs"),
                    min_entropy=r.get("min_entropy"),
                    min_length=r.get("min_length"),
                    severity=r.get("severity"),
                    whitelist_patterns=r.get("whitelist_patterns"),
                )
            )

        # Store inheritance chain for debugging
        self._inherits_from: List[str] = raw.get("_inherits_from", [])

    @staticmethod
    def load(path: str, _visited: Optional[Set[str]] = None) -> "Policy":
        """Load policy with inheritance support.

        Args:
            path: Path to policy file
            _visited: Internal parameter for cycle detection

        Returns:
            Policy object with all inherited rules merged

        Raises:
            ValueError: If circular inheritance detected
            FileNotFoundError: If policy file not found
        """
        if _visited is None:
            _visited = set()

        # Resolve path and detect cycles
        abs_path = os.path.abspath(os.path.expanduser(path))
        if abs_path in _visited:
            raise ValueError(f"Circular inheritance detected: {path}")
        _visited.add(abs_path)

        # Load current policy file
        with open(abs_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Check for inheritance
        inherits = data.get("inherits", [])
        if not inherits:
            # No inheritance, return policy as-is
            policy = Policy(data)
            policy._inherits_from = [abs_path]
            return policy

        # Normalize inherits to list
        if isinstance(inherits, str):
            inherits = [inherits]

        # Load and merge parent policies (in order)
        merged_data = {
            "version": 1,
            "globals": {},
            "detection": [],
            "whitelist": {},
            "blacklist": {},
            "_inherits_from": []
        }

        for parent_path in inherits:
            # Expand ~ first (before checking if absolute)
            parent_path = os.path.expanduser(parent_path)

            # Resolve relative paths relative to current policy's directory
            if not os.path.isabs(parent_path):
                parent_path = os.path.join(os.path.dirname(abs_path), parent_path)

            # Load parent recursively
            parent_policy = Policy.load(parent_path, _visited.copy())

            # Convert parent policy back to dict for merging
            parent_data = _policy_to_dict(parent_policy)

            # Merge parent into accumulated data
            merged_data = _merge_policy_dicts(merged_data, parent_data)
            merged_data["_inherits_from"].extend(parent_policy._inherits_from)

        # Merge current policy (overrides all parents)
        merged_data = _merge_policy_dicts(merged_data, data)
        merged_data["_inherits_from"].append(abs_path)

        return Policy(merged_data)

    def cidr_allowed(self, ip: str, cidrs: Optional[List[str]]) -> bool:
        if not cidrs:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            # Invalid IP address
            return False

        for c in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                # Invalid CIDR notation, skip this entry
                import sys
                print(f"Warning: Invalid CIDR notation in policy: {c}", file=sys.stderr)
                continue
        return False

    def email_whitelisted(self, email: str) -> bool:
        wl = self.whitelist.get("emails", [])
        for pat in wl:
            if pat.startswith("re:"):
                if re.match(pat[3:], email, flags=re.IGNORECASE):
                    return True
            elif pat.startswith("*@"):
                domain = pat[2:].lower()
                if email.lower().endswith("@" + domain):
                    return True
            elif email.lower() == pat.lower():
                return True
        return False


# ── Shared policy resolution ─────────────────────────────────────


def resolve_policy(explicit: Optional[str] = None, project_dir: str = ".") -> str:
    """Resolve policy path with standard priority chain.

    Resolution order:
        1. Explicit path (if provided and exists)
        2. CLOAK_POLICY environment variable
        3. <project_dir>/.cloak/policy.yaml
        4. examples/mcp_policy.yaml (development fallback)

    Args:
        explicit: Explicit policy path (operator-supplied, highest priority)
        project_dir: Project root directory for .cloak/ lookup

    Returns:
        Absolute path to policy file.

    Raises:
        FileNotFoundError: If no policy found at any level.
    """
    # 1. Explicit path
    if explicit:
        abs_explicit = os.path.abspath(os.path.expanduser(explicit))
        if os.path.isfile(abs_explicit):
            return abs_explicit
        raise FileNotFoundError(f"Policy not found: {explicit}")

    # 2. CLOAK_POLICY env var
    env = os.environ.get("CLOAK_POLICY")
    if env:
        abs_env = os.path.abspath(os.path.expanduser(env))
        if os.path.isfile(abs_env):
            return abs_env

    # 3. Per-project .cloak/policy.yaml
    project_policy = os.path.join(os.path.abspath(project_dir), ".cloak", "policy.yaml")
    if os.path.isfile(project_policy):
        return project_policy

    # 4. Development fallback
    default = os.path.join(os.path.abspath(project_dir), "examples", "mcp_policy.yaml")
    if os.path.isfile(default):
        return default

    raise FileNotFoundError(
        "No policy found. Use 'cloak policy use <path>' to set one, "
        "or set CLOAK_POLICY env, or place .cloak/policy.yaml in the project."
    )


def find_policy(project_dir: str = ".") -> str:
    """Find policy (non-raising). Returns "" if not found.

    With CLOAK_FAIL_CLOSED=1: raises FileNotFoundError instead of returning "".

    Args:
        project_dir: Project root directory

    Returns:
        Absolute path to policy file, or "" if not found (fail-open mode).

    Raises:
        FileNotFoundError: Only when CLOAK_FAIL_CLOSED=1 and no policy found.
    """
    try:
        return resolve_policy(project_dir=project_dir)
    except FileNotFoundError:
        if os.environ.get("CLOAK_FAIL_CLOSED") == "1":
            raise
        return ""


def policy_sha256(path: str) -> str:
    """Compute SHA-256 hash of a policy file.

    Args:
        path: Path to policy file

    Returns:
        Hex-encoded SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compare_policies(old_path: str, new_path: str) -> Dict[str, Any]:
    """Compare two policies and detect downgrades.

    A downgrade is defined as:
    - Fewer detection rules, OR
    - Any rule's severity lowered (critical > high > medium > low)

    Args:
        old_path: Path to the currently active policy
        new_path: Path to the proposed new policy

    Returns:
        Dict with:
        - is_downgrade: bool
        - old_rules: int (rule count)
        - new_rules: int (rule count)
        - removed_rules: list of rule IDs present in old but not in new
        - severity_changes: list of {rule_id, old_severity, new_severity}
    """
    _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 2}

    old_policy = Policy.load(old_path)
    new_policy = Policy.load(new_path)

    old_ids = {r.id: r for r in old_policy.rules}
    new_ids = {r.id: r for r in new_policy.rules}

    removed_rules = sorted(set(old_ids.keys()) - set(new_ids.keys()))

    severity_changes = []
    for rid in sorted(set(old_ids.keys()) & set(new_ids.keys())):
        old_sev = old_ids[rid].severity
        new_sev = new_ids[rid].severity
        if _SEVERITY_ORDER.get(new_sev, 2) < _SEVERITY_ORDER.get(old_sev, 2):
            severity_changes.append({
                "rule_id": rid,
                "old_severity": old_sev or "medium",
                "new_severity": new_sev or "medium",
            })

    is_downgrade = bool(removed_rules) or bool(severity_changes)

    return {
        "is_downgrade": is_downgrade,
        "old_rules": len(old_policy.rules),
        "new_rules": len(new_policy.rules),
        "removed_rules": removed_rules,
        "severity_changes": severity_changes,
    }


def _policy_to_dict(policy: Policy) -> Dict[str, Any]:
    """Convert Policy object back to dict representation."""
    return {
        "version": policy.version,
        "globals": {
            "default_action": policy.globals.default_action,
            "audit": {
                "enabled": policy.globals.audit_enabled,
                "path": policy.globals.audit_path,
                "include_value_hash": policy.globals.include_value_hash,
            },
            "pseudonymization": {
                "method": policy.globals.pz.method,
                "secret_key_file": policy.globals.pz.secret_key_file,
                "salt": policy.globals.pz.salt,
            },
        },
        "whitelist": policy.whitelist,
        "blacklist": policy.blacklist,
        "detection": [
            {
                "id": rule.id,
                "type": rule.type,
                "action": rule.action,
                "pattern": rule.pattern,
                "template": rule.template,
                "whitelist": rule.whitelist,
                "whitelist_cidrs": rule.whitelist_cidrs,
                "min_entropy": rule.min_entropy,
                "min_length": rule.min_length,
                "severity": rule.severity,
                "whitelist_patterns": rule.whitelist_patterns,
            }
            for rule in policy.rules
        ],
        "_inherits_from": policy._inherits_from,
    }


def _merge_policy_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two policy dictionaries (override wins on conflicts).

    Merging rules:
    1. Globals: override values replace base values
    2. Detection rules: rules with same ID are replaced, others appended
    3. Whitelist/blacklist: lists are concatenated (no deduplication)

    Args:
        base: Base policy dict
        override: Override policy dict

    Returns:
        Merged policy dict
    """
    merged = {
        "version": override.get("version", base.get("version", 1)),
        "globals": {},
        "detection": [],
        "whitelist": {},
        "blacklist": {},
        "_inherits_from": base.get("_inherits_from", []),
    }

    # Merge globals (deep merge)
    base_globals = base.get("globals", {})
    override_globals = override.get("globals", {})

    # Merge top-level global settings
    merged["globals"]["default_action"] = override_globals.get(
        "default_action", base_globals.get("default_action", "redact")
    )

    # Merge audit settings
    base_audit = base_globals.get("audit", {})
    override_audit = override_globals.get("audit", {})
    merged["globals"]["audit"] = {
        "enabled": override_audit.get("enabled", base_audit.get("enabled", True)),
        "path": override_audit.get("path", base_audit.get("path", "./audit/audit.jsonl")),
        "include_value_hash": override_audit.get(
            "include_value_hash", base_audit.get("include_value_hash", True)
        ),
    }

    # Merge pseudonymization settings
    base_pz = base_globals.get("pseudonymization", {})
    override_pz = override_globals.get("pseudonymization", {})
    merged["globals"]["pseudonymization"] = {
        "method": override_pz.get("method", base_pz.get("method", "hmac-sha256")),
        "secret_key_file": override_pz.get(
            "secret_key_file", base_pz.get("secret_key_file", "./keys/mcp_hmac_key")
        ),
        "salt": override_pz.get("salt", base_pz.get("salt", "session")),
    }

    # Merge detection rules (override rules with same ID)
    base_rules = base.get("detection", [])
    override_rules = override.get("detection", [])

    # Build map of override rule IDs
    override_ids = {rule["id"] for rule in override_rules}

    # Keep base rules that are not overridden
    merged["detection"] = [rule for rule in base_rules if rule["id"] not in override_ids]

    # Add all override rules
    merged["detection"].extend(override_rules)

    # Merge whitelist (concatenate lists)
    base_whitelist = base.get("whitelist", {})
    override_whitelist = override.get("whitelist", {})
    merged["whitelist"] = {}
    for key in set(base_whitelist.keys()) | set(override_whitelist.keys()):
        merged["whitelist"][key] = (
            base_whitelist.get(key, []) + override_whitelist.get(key, [])
        )

    # Merge blacklist (concatenate lists)
    base_blacklist = base.get("blacklist", {})
    override_blacklist = override.get("blacklist", {})
    merged["blacklist"] = {}
    for key in set(base_blacklist.keys()) | set(override_blacklist.keys()):
        merged["blacklist"][key] = (
            base_blacklist.get(key, []) + override_blacklist.get(key, [])
        )

    return merged


def validate_policy(path: str) -> tuple[bool, List[str]]:
    """Validate a policy file (including inheritance).

    Args:
        path: Path to policy file

    Returns:
        (is_valid, errors) tuple
    """
    errors = []

    try:
        policy = Policy.load(path)
    except FileNotFoundError as e:
        errors.append(f"Policy file not found: {e}")
        return False, errors
    except ValueError as e:
        errors.append(f"Invalid policy: {e}")
        return False, errors
    except yaml.YAMLError as e:
        errors.append(f"YAML syntax error: {e}")
        return False, errors
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
        return False, errors

    # Validate detection rules
    for rule in policy.rules:
        if rule.type == "regex" and not rule.pattern:
            errors.append(f"Rule '{rule.id}': regex type requires 'pattern' field")
        elif rule.type == "entropy" and (rule.min_entropy is None or rule.min_length is None):
            errors.append(f"Rule '{rule.id}': entropy type requires 'min_entropy' and 'min_length' fields")

        if rule.action not in ["allow", "redact", "block", "pseudonymize", "replace_with_template"]:
            errors.append(f"Rule '{rule.id}': invalid action '{rule.action}'")

        if rule.action == "replace_with_template" and not rule.template:
            errors.append(f"Rule '{rule.id}': replace_with_template requires 'template' field")

        if rule.severity is not None and rule.severity not in ("critical", "high", "medium", "low"):
            errors.append(f"Rule '{rule.id}': invalid severity '{rule.severity}' (must be critical/high/medium/low)")

    # Validate pseudonymization config
    if policy.globals.pz.method not in ["hmac-sha256"]:
        errors.append(f"Invalid pseudonymization method: {policy.globals.pz.method}")

    return len(errors) == 0, errors


def policy_to_yaml(policy: Policy, include_inheritance: bool = True) -> str:
    """Convert Policy object to YAML string.

    Args:
        policy: Policy object
        include_inheritance: Include inheritance chain as comment

    Returns:
        YAML string
    """
    data = _policy_to_dict(policy)

    # Remove internal fields
    data.pop("_inherits_from", None)

    # Convert to YAML
    output = yaml.dump(data, default_flow_style=False, sort_keys=False)

    # Add inheritance chain comment
    if include_inheritance and policy._inherits_from:
        header = "# Merged policy from inheritance chain:\n"
        for i, path in enumerate(policy._inherits_from, 1):
            header += f"#   {i}. {path}\n"
        header += "\n"
        output = header + output

    return output
