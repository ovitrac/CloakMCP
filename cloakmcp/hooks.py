"""Hook handlers for Claude Code integration.

All JSON parsing and logic lives here. Shell scripts are thin wrappers:
    stdin (Claude JSON) -> cloak hook <event> -> stdout (hook response JSON)

Safety invariants:
- Strict JSON parsing (Python json module, never regex scraping)
- Hard failure = safe: if parsing fails, emit warning additionalContext
- No shell interpolation of extracted content
- Single testable Python path for all hook logic
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .dirpack import (
    pack_dir, unpack_dir, verify_unpack, build_manifest, compute_delta,
    load_ignores, create_backup, cleanup_backup, warn_legacy_backups,
    restore_from_backup,
)
from .filepack import pack_text, TAG_RE
from .policy import Policy, find_policy, policy_sha256
from .scanner import scan
from .normalizer import normalize
from .storage import Vault, BACKUPS_DIR, _project_slug

SESSION_STATE_FILE = ".cloak-session-state"
SESSION_MANIFEST_FILE = ".cloak-session-manifest.json"
AUDIT_FILE = ".cloak-session-audit.jsonl"
DEFAULT_POLICY = "examples/mcp_policy.yaml"
DEFAULT_PREFIX = "TAG"

# Conservative set of obviously dangerous command patterns
DANGEROUS_PATTERNS: List[Tuple[str, str]] = [
    (r"\brm\s+-rf\s+/(?:\s|$)", "rm -rf / (recursive delete root)"),
    (r"\bsudo\s+rm\b", "sudo rm (privileged delete)"),
    (r"\bcurl\b.*\|\s*sh\b", "curl | sh (remote code execution)"),
    (r"\bcurl\b.*\|\s*bash\b", "curl | bash (remote code execution)"),
    (r"\bwget\b.*\|\s*sh\b", "wget | sh (remote code execution)"),
    (r"\bwget\b.*\|\s*bash\b", "wget | bash (remote code execution)"),
    (r"\bgit\s+push\s+--force\b", "git push --force (force push)"),
    (r"\bgit\s+push\s+-f\b", "git push -f (force push)"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard (discard changes)"),
    (r"\bgit\s+clean\s+-f\b", "git clean -f (remove untracked files)"),
    (r"\bchmod\s+-R\s+777\b", "chmod -R 777 (world-writable permissions)"),
    (r"\bdd\s+.*of=/dev/", "dd to device (raw disk write)"),
    (r"\bmkfs\b", "mkfs (format filesystem)"),
]


def _pinned_policy(project_dir: str) -> str:
    """Get pinned policy from session state, falling back to find_policy().

    G1: During an active session, always use the pinned policy path from
    session state. This prevents policy drift from caller input.

    Args:
        project_dir: Project root directory (absolute)

    Returns:
        Policy path (absolute) or "" if no policy available.
    """
    state = _read_state(project_dir)
    if state and state.get("policy_path"):
        pinned = state["policy_path"]
        if os.path.isfile(pinned):
            return pinned
    return find_policy(project_dir)


def _read_stdin_json() -> Optional[Dict[str, Any]]:
    """Read and parse JSON from stdin. Returns None on failure."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _emit_json(data: Dict[str, Any]) -> None:
    """Write JSON response to stdout."""
    json.dump(data, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _write_state(project_dir: str, policy_path: str, prefix: str,
                 backup_path: str = "", policy_hash: str = "",
                 policy_rule_count: int = 0) -> None:
    """Write session state marker with pinned policy (G1)."""
    state = {
        "policy": policy_path,
        "policy_path": policy_path,
        "policy_sha256": policy_hash,
        "policy_rule_count": policy_rule_count,
        "prefix": prefix,
        "project_dir": os.path.abspath(project_dir),
        "backup_path": backup_path,
    }
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)


def _read_state(project_dir: str) -> Optional[Dict[str, Any]]:
    """Read session state marker. Returns None if absent."""
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    if not os.path.isfile(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _remove_state(project_dir: str) -> None:
    """Remove session state marker."""
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    if os.path.isfile(state_path):
        os.remove(state_path)


def _write_manifest(project_dir: str, manifest: Dict[str, Any]) -> None:
    """Write session manifest JSON."""
    path = os.path.join(project_dir, SESSION_MANIFEST_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False)


def _read_manifest(project_dir: str) -> Optional[Dict[str, Any]]:
    """Read session manifest. Returns None if absent."""
    path = os.path.join(project_dir, SESSION_MANIFEST_FILE)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _remove_manifest(project_dir: str) -> None:
    """Remove session manifest file."""
    path = os.path.join(project_dir, SESSION_MANIFEST_FILE)
    if os.path.isfile(path):
        os.remove(path)


def _now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _append_audit(project_dir: str, event: Dict[str, Any]) -> None:
    """Append an audit event to the session audit log (JSONL).

    Args:
        project_dir: Project root directory
        event: Dict with event data (ts is added automatically if missing)
    """
    if "ts" not in event:
        event["ts"] = _now_iso()
    audit_path = os.path.join(project_dir, AUDIT_FILE)
    try:
        with open(audit_path, "a", encoding="utf-8") as f:
            json.dump(event, f, ensure_ascii=False)
            f.write("\n")
    except OSError:
        pass  # Best-effort: never fail on audit write


def _read_audit_tail(project_dir: str, n: int = 10) -> List[Dict[str, Any]]:
    """Read last N events from the audit JSONL file (most-recent-first).

    Args:
        project_dir: Project root directory
        n: Number of events to return

    Returns:
        List of audit event dicts, most recent first. Empty if no file.
    """
    audit_path = os.path.join(project_dir, AUDIT_FILE)
    if not os.path.isfile(audit_path):
        return []
    try:
        with open(audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []

    events: List[Dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(events) >= n:
            break
    return events


def list_backups(project_dir: str) -> List[Dict[str, Any]]:
    """Enumerate available backups for a project.

    Args:
        project_dir: Project root directory

    Returns:
        List of {timestamp, path, file_count} sorted descending (most recent first).
    """
    slug = _project_slug(project_dir)
    slug_dir = os.path.join(BACKUPS_DIR, slug)
    if not os.path.isdir(slug_dir):
        return []

    backups: List[Dict[str, Any]] = []
    try:
        entries = sorted(os.listdir(slug_dir), reverse=True)
    except OSError:
        return []

    for entry in entries:
        entry_path = os.path.join(slug_dir, entry)
        if not os.path.isdir(entry_path):
            continue
        file_count = 0
        for _dp, _dns, fns in os.walk(entry_path):
            file_count += len(fns)
        backups.append({
            "timestamp": entry,
            "path": entry_path,
            "file_count": file_count,
        })

    return backups


# ── Hook handlers ───────────────────────────────────────────────


def handle_session_start(project_dir: str = ".") -> Dict[str, Any]:
    """Handle SessionStart hook: pack directory and write state marker.

    Returns:
        Hook response JSON with additionalContext or error info
    """
    project_dir = os.path.abspath(project_dir)

    # Check for stale session state (abnormal previous exit)
    existing_state = _read_state(project_dir)
    if existing_state is not None:
        # Already packed — skip re-packing, warn user
        return {
            "additionalContext": (
                "[CloakMCP] WARNING: Stale session state detected. "
                "Files may already be packed from a previous session. "
                "Run `cloak recover --dir .` if secrets need restoring."
            )
        }

    # Find policy (G1: resolve once, pin for session)
    try:
        policy_path = find_policy(project_dir)
    except FileNotFoundError:
        # CLOAK_FAIL_CLOSED=1: refuse to run unprotected
        return {
            "additionalContext": (
                "[CloakMCP] FAIL-CLOSED: No policy found and CLOAK_FAIL_CLOSED=1. "
                "Session cannot start without a policy. "
                "Run 'cloak policy use <path>' to set one."
            )
        }

    if not policy_path:
        # G3: Banner — INACTIVE
        return {
            "additionalContext": (
                "[CloakMCP] Guard INACTIVE: no policy found (writes not protected). "
                "Set CLOAK_POLICY env, run 'cloak policy use <path>', "
                "or place .cloak/policy.yaml in the project."
            )
        }

    prefix = os.environ.get("CLOAK_PREFIX", DEFAULT_PREFIX)

    # G1: Compute policy hash for pinning
    p_hash = policy_sha256(policy_path)

    # Check for legacy in-tree backups (security warning)
    legacy_warn = warn_legacy_backups(project_dir)

    try:
        policy = Policy.load(policy_path)
        rule_count = len(policy.rules)
        # Create external backup (outside project tree)
        backup_path = create_backup(project_dir, external=True)
        # Pack without internal backup (already created externally)
        pack_dir(project_dir, policy, prefix=prefix, backup=False)
        # G1: Write state with pinned policy path + hash
        _write_state(project_dir, policy_path, prefix,
                     backup_path=backup_path, policy_hash=p_hash,
                     policy_rule_count=rule_count)
        # R5: write session manifest (file hashes at pack time)
        ignores = load_ignores(project_dir)
        manifest = build_manifest(project_dir, ignores)
        manifest["policy"] = policy_path
        manifest["prefix"] = prefix
        _write_manifest(project_dir, manifest)
    except Exception as e:
        return {
            "additionalContext": (
                f"[CloakMCP] Pack failed: {e}. "
                "Secrets are NOT protected this session."
            )
        }

    _append_audit(project_dir, {
        "event": "session_pack",
        "policy": policy_path,
        "policy_sha256": p_hash,
        "prefix": prefix,
        "manifest_files": manifest.get("total_files", 0),
    })

    # G3: Banner — ACTIVE
    context = (
        f"[CloakMCP] Guard ACTIVE: policy={policy_path} "
        f"({rule_count} rules, sha256={p_hash[:16]}…). "
        "All files have been packed — "
        "secrets replaced by deterministic tags (TAG-xxxxxxxxxxxx). "
        "Do NOT manually alter tag syntax. "
        "Secrets will be restored automatically when the session ends. "
        "IMPORTANT: Hooks protect files on disk and user prompts. "
        "Do not embed secrets in tool arguments or filenames. "
        "CloakMCP prevents exfiltration, not inference from context."
    )
    if legacy_warn:
        context = legacy_warn + "\n" + context

    return {"additionalContext": context}


def handle_session_end(project_dir: str = ".") -> Dict[str, Any]:
    """Handle SessionEnd hook: unpack directory and remove state marker.

    After unpack, runs R4 verification (tag residue scan) and R5 delta
    computation (new/deleted/changed files). Results are written to audit.

    Returns:
        Hook response JSON (empty on success)
    """
    project_dir = os.path.abspath(project_dir)

    state = _read_state(project_dir)
    if state is None:
        # Not packed — nothing to do
        return {}

    # Read manifest before unpack (R5)
    manifest = _read_manifest(project_dir)

    try:
        unpack_dir(project_dir, backup=False)
        _remove_state(project_dir)
        # Clean up external backup after successful unpack
        if state.get("backup_path"):
            cleanup_backup(state["backup_path"])
    except Exception as e:
        print(
            f"[CloakMCP] Unpack failed: {e}. "
            "Run `cloak recover --dir .` manually.",
            file=sys.stderr,
        )
        return {}

    # R4: post-unpack verification
    verification = verify_unpack(project_dir)

    # R5: compute delta against pack-time manifest
    delta: Dict[str, Any] = {}
    if manifest is not None:
        ignores = load_ignores(project_dir)
        delta = compute_delta(manifest, project_dir, ignores)

    # Audit: combined session_unpack event
    audit_event: Dict[str, Any] = {"event": "session_unpack"}
    audit_event["verification"] = {
        "tags_found": verification["tags_found"],
        "tags_resolved": verification["tags_resolved"],
        "tags_unresolvable": verification["tags_unresolvable"],
    }
    if delta:
        audit_event["delta"] = {
            "new_files": len(delta.get("new_files", [])),
            "deleted_files": len(delta.get("deleted_files", [])),
            "changed_files": len(delta.get("changed_files", [])),
            "unchanged_count": delta.get("unchanged_count", 0),
        }

    _append_audit(project_dir, audit_event)

    # Clean up manifest
    _remove_manifest(project_dir)

    # Warn on residual tags
    if verification["tags_unresolvable"] > 0:
        files_list = ", ".join(
            f[0] for f in verification["unresolvable_files"][:5]
        )
        print(
            f"[CloakMCP] WARNING: {verification['tags_unresolvable']} "
            f"unresolvable tag(s) remain in: {files_list}",
            file=sys.stderr,
        )

    return {}


def handle_status(
    project_dir: str = ".", json_output: bool = False, audit_lines: int = 10
) -> Dict[str, Any]:
    """Collect session diagnostics (read-only).

    Gathers session state, manifest summary, file delta, vault stats,
    tag residue, available backups, legacy backup warnings, and recent
    audit events.

    Args:
        project_dir: Project root directory
        json_output: If True, caller will format as JSON (no effect on collection)
        audit_lines: Number of recent audit events to include

    Returns:
        Structured dict with all diagnostic sections. Sections that fail
        are set to None.
    """
    project_dir = os.path.abspath(project_dir)
    status: Dict[str, Any] = {}

    # 1. Session state
    try:
        state = _read_state(project_dir)
        status["session_active"] = state is not None
        status["session"] = state
    except Exception:
        status["session_active"] = False
        status["session"] = None

    # 2. Manifest
    try:
        manifest = _read_manifest(project_dir)
        if manifest is not None:
            status["manifest"] = {
                "timestamp": manifest.get("ts"),
                "total_files": manifest.get("total_files", 0),
            }
        else:
            status["manifest"] = None
    except Exception:
        status["manifest"] = None

    # 3. File delta (only when manifest exists)
    try:
        if manifest is not None:
            ignores = load_ignores(project_dir)
            delta = compute_delta(manifest, project_dir, ignores)
            status["delta"] = delta
        else:
            status["delta"] = None
    except Exception:
        status["delta"] = None

    # 4. Vault stats
    try:
        vault = Vault(project_dir)
        stats = vault.get_stats()
        stats["vault_path"] = vault.vault_path
        status["vault"] = stats
    except Exception:
        status["vault"] = None

    # 5. Legacy warning
    try:
        legacy = warn_legacy_backups(project_dir)
        status["legacy_warning"] = legacy
    except Exception:
        status["legacy_warning"] = None

    # 6. Available backups
    try:
        status["backups"] = list_backups(project_dir)
    except Exception:
        status["backups"] = None

    # 7. Recent audit
    try:
        status["recent_audit"] = _read_audit_tail(project_dir, n=audit_lines)
    except Exception:
        status["recent_audit"] = None

    # 8. Tag residue
    try:
        residue = verify_unpack(project_dir)
        status["tag_residue"] = residue
    except Exception:
        status["tag_residue"] = None

    return status


# ── Severity helpers ─────────────────────────────────────────────


def _effective_severity(rule: Any) -> str:
    """Return the effective severity of a rule (default: medium)."""
    return rule.severity if rule.severity else "medium"


def handle_guard_write(project_dir: str = ".") -> Dict[str, Any]:
    """Handle PreToolUse guard for Write/Edit: scan content for raw secrets.

    Reads Claude hook JSON from stdin, extracts file content,
    scans for secrets, and enforces deny on critical/high severity matches.
    Medium/low severity matches produce advisory warnings only.

    With CLOAK_STRICT=1, medium severity also triggers deny.

    Returns:
        Hook response JSON:
        - hookSpecificOutput with deny if critical/high secrets found
        - additionalContext warning if only medium/low secrets found
        - empty dict if clean
    """
    project_dir = os.path.abspath(project_dir)

    # Parse hook input JSON
    hook_input = _read_stdin_json()
    if hook_input is None:
        return {}

    # Extract content to scan from the tool input
    tool_input = hook_input.get("tool_input", {})
    content = tool_input.get("content", "")
    new_string = tool_input.get("new_string", "")
    text_to_scan = content or new_string

    if not text_to_scan:
        return {}

    # G1: Use pinned policy from session state, never from caller input
    policy_path = _pinned_policy(project_dir)
    if not policy_path:
        # G3: fail-closed check
        if os.environ.get("CLOAK_FAIL_CLOSED") == "1":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "[CloakMCP Guard] FAIL-CLOSED: No policy found. "
                        "Cannot verify content safety without a policy."
                    ),
                }
            }
        return {}

    try:
        policy = Policy.load(policy_path)
        norm = normalize(text_to_scan)
        matches = scan(norm, policy)
    except Exception:
        return {}

    if not matches:
        return {}

    # Partition matches by severity
    deny_severities = {"critical", "high"}
    if os.environ.get("CLOAK_STRICT") == "1":
        deny_severities = {"critical", "high", "medium"}

    high = [m for m in matches if _effective_severity(m.rule) in deny_severities]
    low = [m for m in matches if _effective_severity(m.rule) not in deny_severities]

    if high:
        # Deny: block the write operation
        rule_ids = sorted({m.rule.id for m in high})
        severities = sorted({_effective_severity(m.rule) for m in high})

        _append_audit(project_dir, {
            "event": "guard_deny",
            "match_count": len(high),
            "rule_ids": rule_ids,
            "severities": severities,
            "decision": "deny",
        })

        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"[CloakMCP Guard] Blocked: {len(high)} high-severity secret(s) "
                    f"detected (rules: {', '.join(rule_ids)}). "
                    "Use vault tags instead of raw values."
                ),
            }
        }

    # Warn only (medium/low severity)
    rule_ids = sorted({m.rule.id for m in low})

    _append_audit(project_dir, {
        "event": "guard_trigger",
        "match_count": len(low),
        "rule_ids": rule_ids,
        "decision": "warn",
    })

    return {
        "additionalContext": (
            f"[CloakMCP] WARNING: {len(low)} potential secret(s) detected "
            f"in content being written (rules: {', '.join(rule_ids)}). "
            "Consider using vault tags instead of raw values."
        )
    }


def handle_prompt_guard(project_dir: str = ".") -> Dict[str, Any]:
    """Handle UserPromptSubmit hook: scan user prompts for secrets.

    Reads Claude hook JSON from stdin, extracts the prompt text,
    scans for secrets, and blocks (critical/high) or warns (medium/low).

    Block response uses ``decision: "block"`` + ``reason`` (prompt is erased).
    Warn response uses ``additionalContext`` (advisory only).

    Env vars:
        CLOAK_PROMPT_GUARD=off  — disable entirely (return {})
        CLOAK_STRICT=1          — medium also triggers block

    Returns:
        Hook response JSON:
        - decision: block + reason if critical/high secrets
        - additionalContext warning if only medium/low secrets
        - empty dict if clean or disabled
    """
    # Check kill-switch
    if os.environ.get("CLOAK_PROMPT_GUARD", "").lower() == "off":
        return {}

    project_dir = os.path.abspath(project_dir)

    # Parse hook input JSON
    hook_input = _read_stdin_json()
    if hook_input is None:
        return {}

    # Extract prompt text
    prompt = hook_input.get("prompt", "")
    if not prompt:
        return {}

    # G1: Use pinned policy from session state
    policy_path = _pinned_policy(project_dir)
    if not policy_path:
        return {}

    try:
        policy = Policy.load(policy_path)
        norm = normalize(prompt)
        matches = scan(norm, policy)
    except Exception:
        return {}

    if not matches:
        return {}

    # Partition matches by severity
    deny_severities = {"critical", "high"}
    if os.environ.get("CLOAK_STRICT") == "1":
        deny_severities = {"critical", "high", "medium"}

    high = [m for m in matches if _effective_severity(m.rule) in deny_severities]
    low = [m for m in matches if _effective_severity(m.rule) not in deny_severities]

    if high:
        rule_ids = sorted({m.rule.id for m in high})
        severities = sorted({_effective_severity(m.rule) for m in high})

        _append_audit(project_dir, {
            "event": "prompt_deny",
            "match_count": len(high),
            "rule_ids": rule_ids,
            "severities": severities,
            "decision": "block",
        })

        return {
            "decision": "block",
            "reason": (
                f"[CloakMCP] Prompt blocked: {len(high)} high-severity secret(s) "
                f"detected (rules: {', '.join(rule_ids)}). "
                "Remove secrets and use vault tags (TAG-xxxx) instead."
            ),
        }

    # Warn only (medium/low severity)
    rule_ids = sorted({m.rule.id for m in low})

    _append_audit(project_dir, {
        "event": "prompt_warn",
        "match_count": len(low),
        "rule_ids": rule_ids,
        "decision": "warn",
    })

    return {
        "additionalContext": (
            f"[CloakMCP] WARNING: {len(low)} potential secret(s) detected "
            f"in prompt (rules: {', '.join(rule_ids)}). "
            "Consider using vault tags instead of raw values."
        )
    }


def handle_safety_guard(project_dir: str = ".") -> Dict[str, Any]:
    """Handle PreToolUse guard for Bash: block obviously dangerous commands.

    Reads Claude hook JSON from stdin, checks tool_input.command against
    DANGEROUS_PATTERNS, and emits a deny response if matched.

    Returns:
        Hook response JSON (deny if dangerous, empty if safe)
    """
    project_dir = os.path.abspath(project_dir)

    hook_input = _read_stdin_json()
    if hook_input is None:
        return {}

    tool_input = hook_input.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        return {}

    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            _append_audit(project_dir, {
                "event": "safety_block",
                "pattern_desc": description,
            })
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"[CloakMCP Safety Guard] Blocked: {description}"
                    ),
                }
            }

    return {}


SENSITIVE_PATH_PATTERNS = [
    ".cloak-backups",
    ".cloak-session-state",
    ".cloak-session-manifest.json",
    ".cloak-session-audit.jsonl",
    ".cloakmcp/",
]


def handle_guard_read(project_dir: str = ".") -> Dict[str, Any]:
    """PreToolUse guard: deny Read/Grep/Glob access to sensitive paths.

    Checks file_path, path, and pattern fields in tool_input for any
    reference to backup directories or session state files.

    Returns:
        Hook response JSON (deny if sensitive path detected, empty if safe)
    """
    project_dir = os.path.abspath(project_dir)
    hook_input = _read_stdin_json()
    if hook_input is None:
        return {}

    tool_input = hook_input.get("tool_input", {})
    paths_to_check: List[str] = []
    for key in ("file_path", "path"):
        val = tool_input.get(key, "")
        if val:
            paths_to_check.append(val)
    pattern = tool_input.get("pattern", "")
    if pattern:
        paths_to_check.append(pattern)

    for path_val in paths_to_check:
        for sensitive in SENSITIVE_PATH_PATTERNS:
            if sensitive in path_val:
                _append_audit(project_dir, {
                    "event": "guard_read_deny",
                    "sensitive_pattern": sensitive,
                    "tool_name": hook_input.get("tool_name", ""),
                })
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"[CloakMCP Guard] Blocked: access to sensitive path "
                            f"containing '{sensitive}'."
                        ),
                    }
                }
    return {}


def handle_audit_log(project_dir: str = ".") -> Dict[str, Any]:
    """Handle PostToolUse audit logging.

    Tier 1 (always-on): Classify CloakMCP-related events from tool calls.
    Tier 2 (opt-in via CLOAK_AUDIT_TOOLS=1): Log tool metadata with hashed paths.

    Returns:
        Empty dict (audit logging is silent, never affects tool execution)
    """
    project_dir = os.path.abspath(project_dir)

    hook_input = _read_stdin_json()
    if hook_input is None:
        return {}

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Tier 1: classify CloakMCP-related events
    event_type = _classify_secret_event(tool_name, tool_input)
    if event_type:
        _append_audit(project_dir, {"event": event_type, "tool": tool_name})

    # Tier 2: opt-in tool metadata logging
    if os.environ.get("CLOAK_AUDIT_TOOLS") == "1":
        file_path = tool_input.get("file_path", "") or tool_input.get("file", "")
        hashed_path = ""
        if file_path:
            hashed_path = hashlib.sha256(file_path.encode()).hexdigest()[:16]
        _append_audit(project_dir, {
            "event": "tool_use",
            "tool": tool_name,
            "file_hash": hashed_path,
        })

    # Opt-in repack-on-write: re-pack the written file after Write/Edit
    if os.environ.get("CLOAK_REPACK_ON_WRITE") == "1" and tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        if file_path and os.path.isfile(file_path):
            _repack_single_file(project_dir, file_path)

    return {}


def _repack_single_file(project_dir: str, file_path: str) -> None:
    """Re-pack a single file after a Write/Edit tool call (hook-driven).

    Standalone: does not depend on session manifest. Validates path is inside
    project, loads policy, packs in-place, appends audit event.
    """
    from .dirpack import repack_file

    policy_path = _pinned_policy(project_dir)
    if not policy_path:
        return

    state = _read_state(project_dir)
    if state is None:
        return  # No active session — skip repack

    prefix = state.get("prefix", DEFAULT_PREFIX)

    try:
        policy = Policy.load(policy_path)
        vault = Vault(project_dir)
        count = repack_file(file_path, project_dir, policy, vault, prefix=prefix)
        if count > 0:
            _append_audit(project_dir, {
                "event": "repack_file",
                "secrets_packed": count,
            })
    except Exception:
        pass  # Best-effort: never fail on repack


def _classify_secret_event(tool_name: str, tool_input: Dict[str, Any]) -> str:
    """Classify a tool call as a CloakMCP-related event.

    Returns:
        Event type string, or empty string if not CloakMCP-related
    """
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if "cloak pack" in command or "cloak hook session-start" in command:
            return "cloak_pack"
        if "cloak unpack" in command or "cloak hook session-end" in command:
            return "cloak_unpack"
    elif tool_name in ("Write", "Edit"):
        return "file_write"
    return ""


def handle_recover(project_dir: str = ".") -> None:
    """Detect stale session state and run unpack.

    Used for manual recovery after abnormal session exit.
    """
    project_dir = os.path.abspath(project_dir)

    # Warn about legacy in-tree backups
    legacy_warn = warn_legacy_backups(project_dir)
    if legacy_warn:
        print(legacy_warn, file=sys.stderr)

    state = _read_state(project_dir)
    if state is None:
        print("No stale session state found. Nothing to recover.", file=sys.stderr)
        return

    print(f"Found stale session state: {json.dumps(state, indent=2)}", file=sys.stderr)
    print("Unpacking...", file=sys.stderr)

    try:
        unpack_dir(project_dir, backup=False)
        _remove_state(project_dir)
        print("Recovery complete. Secrets restored.", file=sys.stderr)
    except Exception as e:
        print(f"Recovery failed: {e}", file=sys.stderr)
        sys.exit(1)


def handle_restore(
    project_dir: str = ".",
    from_backup: bool = False,
    force: bool = False,
    backup_id: Optional[str] = None,
) -> None:
    """Restore secrets — vault-based (default) or from backup.

    Vault-based (default):
        Replaces tags with secrets from vault, verifies, computes delta,
        and cleans session state.

    Backup-based (--from-backup):
        Copies pre-redaction files from external backup. Requires --force
        for execution; without it, shows dry-run preview.

    Args:
        project_dir: Project root directory
        from_backup: If True, restore from external backup instead of vault
        force: Execute destructive backup restore (required with --from-backup)
        backup_id: Timestamp of specific backup to restore from
    """
    project_dir = os.path.abspath(project_dir)

    if from_backup:
        _restore_from_backup(project_dir, force, backup_id)
    else:
        _restore_from_vault(project_dir)


def _restore_from_vault(project_dir: str) -> None:
    """Vault-based restore: replace tags with secrets from vault."""
    # Warn about legacy backups
    legacy_warn = warn_legacy_backups(project_dir)
    if legacy_warn:
        print(legacy_warn, file=sys.stderr)

    # Read state and check vault
    state = _read_state(project_dir)
    vault = Vault(project_dir)
    vault_stats = vault.get_stats()

    if state is None and vault_stats["total_secrets"] == 0:
        print("Nothing to restore. No session state and vault is empty.", file=sys.stderr)
        return

    if state is None:
        print(
            "[CloakMCP] No session state found, but vault has data. "
            "Proceeding with tag replacement...",
            file=sys.stderr,
        )

    # Read manifest before unpack
    manifest = _read_manifest(project_dir)

    # Unpack
    try:
        unpack_dir(project_dir, backup=False)
    except Exception as e:
        print(f"[CloakMCP] Restore failed during unpack: {e}", file=sys.stderr)
        sys.exit(1)

    # R4: verification
    verification = verify_unpack(project_dir)
    print(f"Verification: {verification['tags_found']} tags found, "
          f"{verification['tags_resolved']} resolved, "
          f"{verification['tags_unresolvable']} unresolvable", file=sys.stderr)

    if verification["unresolvable_files"]:
        for rel_path, count in verification["unresolvable_files"][:5]:
            print(f"  {rel_path}: {count} unresolvable tag(s)", file=sys.stderr)

    # R5: delta (if manifest exists)
    if manifest is not None:
        ignores = load_ignores(project_dir)
        delta = compute_delta(manifest, project_dir, ignores)
        new_count = len(delta.get("new_files", []))
        del_count = len(delta.get("deleted_files", []))
        chg_count = len(delta.get("changed_files", []))
        unch_count = delta.get("unchanged_count", 0)
        print(f"Delta: {new_count} new, {del_count} deleted, "
              f"{chg_count} changed, {unch_count} unchanged", file=sys.stderr)

    # Clean up
    _remove_state(project_dir)
    if state and state.get("backup_path"):
        cleanup_backup(state["backup_path"])
    _remove_manifest(project_dir)

    # Audit
    _append_audit(project_dir, {
        "event": "restore_vault",
        "tags_found": verification["tags_found"],
        "tags_unresolvable": verification["tags_unresolvable"],
    })

    print("Restore complete.", file=sys.stderr)

    if verification["tags_unresolvable"] > 0:
        sys.exit(1)


def _restore_from_backup(
    project_dir: str, force: bool, backup_id: Optional[str]
) -> None:
    """Backup-based restore: copy pre-redaction files from external backup."""
    backups = list_backups(project_dir)

    if not backups:
        print("[CloakMCP] No backups available for this project.", file=sys.stderr)
        sys.exit(1)

    # No backup_id: list available backups
    if backup_id is None:
        print("Available backups:", file=sys.stderr)
        for b in backups:
            print(f"  {b['timestamp']}  ({b['file_count']} files)  {b['path']}",
                  file=sys.stderr)
        print(
            "\nUsage: cloak restore --from-backup --backup-id <timestamp>",
            file=sys.stderr,
        )
        return

    # Find matching backup
    matching = [b for b in backups if b["timestamp"] == backup_id]
    if not matching:
        print(f"[CloakMCP] No backup with timestamp '{backup_id}'.", file=sys.stderr)
        print("Available timestamps:", file=sys.stderr)
        for b in backups:
            print(f"  {b['timestamp']}", file=sys.stderr)
        sys.exit(1)

    backup = matching[0]

    if not force:
        # Dry-run preview
        restored, skipped = restore_from_backup(
            backup["path"], project_dir, dry_run=True
        )
        print(f"[DRY RUN] Would restore {restored} files from backup "
              f"{backup['timestamp']}.", file=sys.stderr)
        print(
            "WARNING: This is DESTRUCTIVE — current files will be overwritten "
            "with backup copies.", file=sys.stderr,
        )
        print(
            "Add --force to execute: "
            f"cloak restore --from-backup --backup-id {backup_id} --force",
            file=sys.stderr,
        )
        return

    # Execute restore
    restored, skipped = restore_from_backup(
        backup["path"], project_dir, dry_run=False
    )
    print(f"Restored {restored} files from backup {backup['timestamp']} "
          f"({skipped} skipped).", file=sys.stderr)

    # Clean state
    _remove_state(project_dir)
    _remove_manifest(project_dir)

    # Audit
    _append_audit(project_dir, {
        "event": "restore_backup",
        "backup_timestamp": backup["timestamp"],
        "restored_files": restored,
        "skipped_files": skipped,
    })


def handle_policy_reload(project_dir: str = ".") -> None:
    """Reload policy mid-session (G2).

    Re-resolves policy, updates session state with new path + hash,
    prints old → new diff, logs policy_reload audit event.
    """
    project_dir = os.path.abspath(project_dir)

    state = _read_state(project_dir)
    if state is None:
        print("[CloakMCP] No active session. Nothing to reload.", file=sys.stderr)
        return

    old_path = state.get("policy_path", state.get("policy", ""))
    old_hash = state.get("policy_sha256", "")

    try:
        new_path = find_policy(project_dir)
    except FileNotFoundError as e:
        print(f"[CloakMCP] Policy reload failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not new_path:
        print("[CloakMCP] No policy found. Session policy unchanged.", file=sys.stderr)
        return

    new_hash = policy_sha256(new_path)
    new_policy = Policy.load(new_path)
    new_rule_count = len(new_policy.rules)

    if new_hash == old_hash:
        print(f"[CloakMCP] Policy unchanged (sha256={new_hash[:16]}…).",
              file=sys.stderr)
        return

    # Update session state
    state["policy"] = new_path
    state["policy_path"] = new_path
    state["policy_sha256"] = new_hash
    state["policy_rule_count"] = new_rule_count
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)

    # Print diff
    print(f"[CloakMCP] Policy reloaded:", file=sys.stderr)
    print(f"  Old: {old_path} (sha256={old_hash[:16]}…)", file=sys.stderr)
    print(f"  New: {new_path} ({new_rule_count} rules, sha256={new_hash[:16]}…)",
          file=sys.stderr)
    print("  Hint: Run 'cloak repack --dir .' to realign content.",
          file=sys.stderr)

    _append_audit(project_dir, {
        "event": "policy_reload",
        "old_policy": old_path,
        "old_sha256": old_hash,
        "new_policy": new_path,
        "new_sha256": new_hash,
        "new_rule_count": new_rule_count,
    })


# ── Main dispatcher (called by `cloak hook <event>`) ────────────


def dispatch_hook(event: str, project_dir: str = ".") -> None:
    """Dispatch hook event to appropriate handler.

    Args:
        event: One of 'session-start', 'session-end', 'guard-write',
               'prompt-guard', 'safety-guard', 'audit-log'
        project_dir: Project root directory
    """
    handlers = {
        "session-start": handle_session_start,
        "session-end": handle_session_end,
        "guard-write": handle_guard_write,
        "guard-read": handle_guard_read,
        "prompt-guard": handle_prompt_guard,
        "safety-guard": handle_safety_guard,
        "audit-log": handle_audit_log,
    }

    handler = handlers.get(event)
    if handler is None:
        print(f"Unknown hook event: {event}", file=sys.stderr)
        sys.exit(1)

    result = handler(project_dir)
    if result:
        _emit_json(result)
