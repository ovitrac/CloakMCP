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

from .dirpack import pack_dir, unpack_dir, verify_unpack, build_manifest, compute_delta, load_ignores
from .filepack import pack_text, TAG_RE
from .policy import Policy
from .scanner import scan
from .normalizer import normalize
from .storage import Vault

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


def _find_policy() -> str:
    """Find the policy file — check env, then default location."""
    env = os.environ.get("CLOAK_POLICY")
    if env and os.path.isfile(env):
        return env
    if os.path.isfile(DEFAULT_POLICY):
        return DEFAULT_POLICY
    return ""


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


def _write_state(project_dir: str, policy_path: str, prefix: str) -> None:
    """Write session state marker."""
    state = {
        "policy": policy_path,
        "prefix": prefix,
        "project_dir": os.path.abspath(project_dir),
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

    # Find policy
    policy_path = _find_policy()
    if not policy_path:
        return {
            "additionalContext": (
                "[CloakMCP] No policy file found. "
                "Set CLOAK_POLICY env or place examples/mcp_policy.yaml. "
                "Secrets are NOT protected this session."
            )
        }

    prefix = os.environ.get("CLOAK_PREFIX", DEFAULT_PREFIX)

    try:
        policy = Policy.load(policy_path)
        pack_dir(project_dir, policy, prefix=prefix, backup=True)
        _write_state(project_dir, policy_path, prefix)
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
        "prefix": prefix,
        "manifest_files": manifest.get("total_files", 0),
    })

    return {
        "additionalContext": (
            "[CloakMCP] Session started. All files have been packed — "
            "secrets replaced by deterministic tags (TAG-xxxxxxxxxxxx). "
            "Do NOT manually alter tag syntax. "
            "Secrets will be restored automatically when the session ends. "
            "IMPORTANT: Hooks protect files on disk and user prompts. "
            "Do not embed secrets in tool arguments or filenames."
        )
    }


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

    # Find policy
    policy_path = _find_policy()
    if not policy_path:
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

    # Find policy
    policy_path = _find_policy()
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

    return {}


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
