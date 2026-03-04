from __future__ import annotations
import argparse
import os
import sys
from typing import Any, Dict, List, Tuple

from .normalizer import normalize
from .policy import Policy
from .scanner import scan
from .actions import apply_action
from .audit import write_event, now_iso
from .dirpack import pack_dir, unpack_dir
from .storage import Vault

def _validate_input_path(path: str, arg_name: str = "input") -> None:
    """Validate that an input path exists (or is stdin)."""
    if path == "-":
        return  # stdin is always valid
    if not os.path.exists(path):
        print(f"Error: {arg_name} path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"Error: {arg_name} path is not a file: {path}", file=sys.stderr)
        sys.exit(1)

def _validate_dir_path(path: str, arg_name: str = "directory") -> None:
    """Validate that a directory path exists."""
    if not os.path.exists(path):
        print(f"Error: {arg_name} path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(path):
        print(f"Error: {arg_name} path is not a directory: {path}", file=sys.stderr)
        sys.exit(1)

def _validate_policy_path(path: str) -> None:
    """Validate that a policy file exists."""
    if not os.path.exists(path):
        print(f"Error: policy file does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"Error: policy path is not a file: {path}", file=sys.stderr)
        sys.exit(1)

def _load_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _write_text(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def sanitize_text(text: str, policy: Policy, dry_run: bool = False) -> Tuple[str, bool]:
    text = normalize(text)
    matches = scan(text, policy)
    blocked = False
    out = list(text)
    for m in reversed(matches):
        res = apply_action(m.rule, m.value, policy)
        if res.blocked:
            blocked = True
        if not dry_run:
            out[m.start:m.end] = list(res.replacement)
        if policy.globals.audit_enabled:
            write_event(
                policy.globals.audit_path,
                {
                    "ts": now_iso(),
                    "rule_id": m.rule.id,
                    "action": m.rule.action,
                    "blocked": res.blocked,
                    "start": m.start,
                    "end": m.end,
                    "value_hash": res.value_hash,
                },
            )
    return ("".join(out) if not dry_run else text, blocked)

def _print_status(status: Dict[str, Any]) -> None:
    """Print human-readable status report to stderr."""
    print("=" * 50, file=sys.stderr)
    print("CloakMCP Status", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    # Session
    active = status.get("session_active", False)
    print(f"\nSession: {'ACTIVE' if active else 'INACTIVE'}", file=sys.stderr)
    if active and status.get("session"):
        session = status["session"]
        print(f"  Policy: {session.get('policy', 'N/A')}", file=sys.stderr)
        print(f"  Prefix: {session.get('prefix', 'N/A')}", file=sys.stderr)
        if session.get("backup_path"):
            print(f"  Backup: {session['backup_path']}", file=sys.stderr)

    # Manifest
    manifest = status.get("manifest")
    if manifest:
        print(f"\nManifest: {manifest.get('total_files', 0)} files "
              f"(ts: {manifest.get('timestamp', 'N/A')})", file=sys.stderr)
    else:
        print("\nManifest: none", file=sys.stderr)

    # Delta
    delta = status.get("delta")
    if delta:
        new_files = delta.get("new_files", [])
        deleted_files = delta.get("deleted_files", [])
        changed_files = delta.get("changed_files", [])
        unchanged = delta.get("unchanged_count", 0)
        print(f"\nDelta: {len(new_files)} new, {len(deleted_files)} deleted, "
              f"{len(changed_files)} changed, {unchanged} unchanged", file=sys.stderr)
        for label, files in [("New", new_files), ("Deleted", deleted_files),
                             ("Changed", changed_files)]:
            for f in files[:10]:
                print(f"  [{label}] {f}", file=sys.stderr)
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more", file=sys.stderr)

    # Vault
    vault = status.get("vault")
    if vault:
        print(f"\nVault: {vault.get('total_secrets', 0)} secrets, "
              f"{vault.get('unique_tags', 0)} unique tags", file=sys.stderr)
        print(f"  Path: {vault.get('vault_path', 'N/A')}", file=sys.stderr)
    else:
        print("\nVault: unavailable", file=sys.stderr)

    # Tag residue
    residue = status.get("tag_residue")
    if residue:
        print(f"\nTag residue: {residue.get('tags_found', 0)} found, "
              f"{residue.get('tags_resolved', 0)} resolved, "
              f"{residue.get('tags_unresolvable', 0)} unresolvable", file=sys.stderr)
        unresolvable_files = residue.get("unresolvable_files", [])
        for rel_path, count in unresolvable_files[:5]:
            print(f"  {rel_path}: {count} tag(s)", file=sys.stderr)
        if len(unresolvable_files) > 5:
            print(f"  ... and {len(unresolvable_files) - 5} more files",
                  file=sys.stderr)

    # Backups
    backups = status.get("backups")
    if backups:
        print(f"\nBackups: {len(backups)} available", file=sys.stderr)
        for b in backups[:5]:
            fmt = b.get("format", "unknown")
            size_kb = b.get("size", 0) // 1024
            print(f"  {b['timestamp']}  [{fmt}]  {size_kb} KB", file=sys.stderr)
        if len(backups) > 5:
            print(f"  ... and {len(backups) - 5} more", file=sys.stderr)
    else:
        print("\nBackups: none", file=sys.stderr)

    # Legacy warning
    legacy = status.get("legacy_warning")
    if legacy:
        print(f"\n{legacy}", file=sys.stderr)

    # Recent audit
    audit = status.get("recent_audit")
    if audit:
        print(f"\nRecent audit ({len(audit)} events):", file=sys.stderr)
        for evt in audit:
            ts = evt.get("ts", "?")
            event_type = evt.get("event", "?")
            print(f"  [{ts}] {event_type}", file=sys.stderr)
    else:
        print("\nAudit: no events", file=sys.stderr)

    print("", file=sys.stderr)


def main() -> None:
    import cloakmcp
    p = argparse.ArgumentParser(prog="cloak", description="Micro-Cleanse Preprocessor (local secret-removal)")
    p.add_argument("--version", action="version", version=f"%(prog)s {cloakmcp.__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── Existing commands ───────────────────────────────────────

    s_scan = sub.add_parser("scan", help="Scan input and log detections (no modifications)")
    s_scan.add_argument("--policy", required=True)
    s_scan.add_argument("--input", required=True, help="File path or '-' for stdin")

    s_san = sub.add_parser("sanitize", help="Sanitize input and write output")
    s_san.add_argument("--policy", required=True)
    s_san.add_argument("--input", required=True, help="File path or '-' for stdin")
    s_san.add_argument("--output", required=True, help="File path or '-' for stdout")

    s_pack = sub.add_parser("pack", help="Pack a directory: replace secrets by tags (vaulted)")
    s_pack.add_argument("--policy", required=True)
    s_pack.add_argument("--dir", required=True, help="Directory to process")
    s_pack.add_argument("--prefix", default="TAG", help="Tag prefix (e.g., TAG, SEC, KEY)")
    s_pack.add_argument("--dry-run", action="store_true", help="Preview changes without modifying files")
    s_pack.add_argument("--no-backup", action="store_true", help="Disable automatic backup (not recommended)")

    s_unpack = sub.add_parser("unpack", help="Unpack a directory: restore tags from vault")
    s_unpack.add_argument("--dir", required=True, help="Directory to process")
    s_unpack.add_argument("--dry-run", action="store_true", help="Preview changes without modifying files")
    s_unpack.add_argument("--no-backup", action="store_true", help="Disable automatic backup (not recommended)")

    s_vault_export = sub.add_parser("vault-export", help="Export vault to encrypted backup file")
    s_vault_export.add_argument("--dir", required=True, help="Project directory")
    s_vault_export.add_argument("--output", required=True, help="Output file path")

    s_vault_import = sub.add_parser("vault-import", help="Import vault from encrypted backup file")
    s_vault_import.add_argument("--dir", required=True, help="Project directory")
    s_vault_import.add_argument("--input", required=True, help="Input file path")

    s_vault_stats = sub.add_parser("vault-stats", help="Display vault statistics")
    s_vault_stats.add_argument("--dir", required=True, help="Project directory")

    # Policy management commands
    s_policy = sub.add_parser("policy", help="Policy management (validate, show merged policy)")
    policy_sub = s_policy.add_subparsers(dest="policy_cmd", required=True)

    s_policy_validate = policy_sub.add_parser("validate", help="Validate policy file (including inheritance)")
    s_policy_validate.add_argument("--policy", required=True, help="Policy file to validate")

    s_policy_show = policy_sub.add_parser("show", help="Show merged policy (after inheritance)")
    s_policy_show.add_argument("--policy", required=True, help="Policy file to show")
    s_policy_show.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output format")

    # ── v0.9.0: policy use / policy reload ──────────────────
    s_policy_use = policy_sub.add_parser("use", help="Set per-project policy (.cloak/policy.yaml)")
    s_policy_use.add_argument("path", nargs="?", default=None,
                              help="Path to policy file to use")
    s_policy_use.add_argument("--show", action="store_true", dest="show_active",
                              help="Show active policy path, sha256, and rule count")
    s_policy_use.add_argument("--clear", action="store_true",
                              help="Remove per-project policy (.cloak/policy.yaml)")
    s_policy_use.add_argument("--link", action="store_true",
                              help="Symlink instead of copy")
    s_policy_use.add_argument("--force", action="store_true",
                              help="Allow policy downgrade (fewer rules / lower severity)")
    s_policy_use.add_argument("--dir", default=".", help="Project root directory")

    s_policy_reload = policy_sub.add_parser("reload", help="Reload policy mid-session (G2)")
    s_policy_reload.add_argument("--dir", default=".", help="Project root directory")

    # ── v0.4.0: File-level pack/unpack ──────────────────────────

    s_pack_file = sub.add_parser("pack-file", help="Pack a single file: replace secrets by tags")
    s_pack_file.add_argument("--policy", required=True)
    s_pack_file.add_argument("--file", required=True, help="File to process")
    s_pack_file.add_argument("--prefix", default="TAG", help="Tag prefix")
    s_pack_file.add_argument("--project-root", default=".", help="Project root for vault lookup")
    s_pack_file.add_argument("--dry-run", action="store_true", help="Preview only")

    s_unpack_file = sub.add_parser("unpack-file", help="Unpack a single file: restore tags from vault")
    s_unpack_file.add_argument("--file", required=True, help="File to process")
    s_unpack_file.add_argument("--project-root", default=".", help="Project root for vault lookup")
    s_unpack_file.add_argument("--dry-run", action="store_true", help="Preview only")

    # ── v0.4.0: Guard (stdin secret scanner) ────────────────────

    s_guard = sub.add_parser("guard", help="Read stdin, exit 1 if secrets detected")
    s_guard.add_argument("--policy", required=True)

    # ── v0.4.0: Hook dispatcher ─────────────────────────────────

    s_hook = sub.add_parser("hook", help="Handle Claude Code hook events")
    s_hook.add_argument("event", choices=["session-start", "session-end", "guard-write",
                                          "guard-read", "prompt-guard", "safety-guard",
                                          "audit-log"],
                        help="Hook event type")
    s_hook.add_argument("--dir", default=".", help="Project root directory")

    # ── v0.4.0: Recovery ────────────────────────────────────────

    s_recover = sub.add_parser("recover", help="Detect stale session state and run unpack")
    s_recover.add_argument("--dir", default=".", help="Project root directory")

    # ── v0.5.1: stdin sanitization helper ──────────────────────

    s_stdin = sub.add_parser("sanitize-stdin", help="Sanitize text from stdin → stdout")
    s_stdin.add_argument("--policy", required=True, help="Path to YAML policy file")

    # ── v0.6.0: incremental re-pack ─────────────────────────

    s_repack = sub.add_parser("repack", help="Incremental re-pack: scan new/changed files only")
    s_repack.add_argument("--dir", required=True, help="Directory to process")
    s_repack.add_argument("--policy", required=True, help="Path to YAML policy file")
    s_repack.add_argument("--prefix", default="TAG", help="Tag prefix (e.g., TAG, SEC, KEY)")
    s_repack.add_argument("--dry-run", action="store_true", help="Preview changes without modifying files")

    # ── v0.5.1: post-unpack verification ─────────────────────

    s_verify = sub.add_parser("verify", help="Scan for residual tags after unpack")
    s_verify.add_argument("--dir", required=True, help="Directory to verify")

    # ── scripts-path ─────────────────────────────────────────────
    sub.add_parser("scripts-path", help="Print path to bundled installer scripts")

    # ── hooks-path (toolbox discovery contract) ────────────────
    s_hpath = sub.add_parser("hooks-path",
                             help="Print path to bundled hook scripts (toolbox contract)")
    s_hpath.add_argument("--format", choices=["sh", "py", "cli"], default="sh",
                         dest="hook_format",
                         help="Hook format: sh (POSIX), py (Python), cli (command prefix)")

    # ── install (cross-platform hook installer) ────────────────
    s_install = sub.add_parser("install", help="Install Claude Code hooks (cross-platform)")
    s_install.add_argument("--profile", choices=["secrets-only", "hardened"],
                           default="secrets-only", help="Hook profile (default: secrets-only)")
    s_install.add_argument("--method", choices=["cli", "copy", "symlink"],
                           default="cli", help="Install method (default: cli)")
    s_install.add_argument("--policy", default="", help="Set per-project policy file")
    s_install.add_argument("--dry-run", action="store_true", help="Preview without changes")
    s_install.add_argument("--uninstall", action="store_true", help="Remove hooks")
    s_install.add_argument("--dir", default=".", help="Project root directory")

    # ── doctor (cross-platform diagnostics) ────────────────────
    s_doctor = sub.add_parser("doctor", help="Check CloakMCP installation health")
    s_doctor.add_argument("--dir", default=".", help="Project root directory")

    # ── v0.8.0: session status ─────────────────────────────────────
    s_status = sub.add_parser("status", help="Show session status and diagnostics")
    s_status.add_argument("--dir", default=".", help="Project root directory")
    s_status.add_argument("--json", action="store_true", dest="json_output",
                           help="Output as JSON (machine-readable)")
    s_status.add_argument("--audit-lines", type=int, default=10,
                           help="Number of recent audit events to show (default: 10)")

    # ── v0.8.0: restore ───────────────────────────────────────────
    s_restore = sub.add_parser("restore", help="Restore secrets (vault-based or from backup)")
    s_restore.add_argument("--dir", default=".", help="Project root directory")
    s_restore.add_argument("--from-backup", action="store_true",
                            help="Restore from external backup instead of vault")
    s_restore.add_argument("--force", action="store_true",
                            help="Execute destructive backup restore (required with --from-backup)")
    s_restore.add_argument("--backup-id", default=None,
                            help="Timestamp of specific backup to restore from")

    # ── v0.11.0: key management ────────────────────────────────
    s_key = sub.add_parser("key", help="Key management (wrap/unwrap)")
    key_sub = s_key.add_subparsers(dest="key_cmd", required=True)

    s_key_wrap = key_sub.add_parser("wrap", help="Wrap key with passphrase (Tier 0 -> Tier 1)")
    s_key_wrap.add_argument("--dir", default=".", help="Project root directory")

    s_key_unwrap = key_sub.add_parser("unwrap", help="Unwrap key back to raw (Tier 1 -> Tier 0)")
    s_key_unwrap.add_argument("--dir", default=".", help="Project root directory")

    # ── v0.11.0: backup management ──────────────────────────────
    s_backup = sub.add_parser("backup", help="Backup management (migrate, prune)")
    backup_sub = s_backup.add_subparsers(dest="backup_cmd", required=True)

    s_backup_migrate = backup_sub.add_parser("migrate", help="Encrypt legacy plaintext backups")
    s_backup_migrate.add_argument("--dir", default=".", help="Project root directory")
    s_backup_migrate.add_argument("--dry-run", action="store_true",
                                   help="Preview only (default behavior)")
    s_backup_migrate.add_argument("--quarantine", action="store_true",
                                   help="Move legacy dirs to quarantine instead of deleting")

    s_backup_prune = backup_sub.add_parser("prune", help="Remove old backups")
    s_backup_prune.add_argument("--dir", default=".", help="Project root directory")
    s_backup_prune.add_argument("--ttl", default="30d",
                                 help="TTL threshold (e.g. 30d, 24h, 90m) — default: 30d")
    s_backup_prune.add_argument("--keep-last", type=int, default=10,
                                 help="Always keep N newest backups (default: 10)")
    s_backup_prune.add_argument("--apply", action="store_true",
                                 help="Actually delete (dry-run without this flag)")
    s_backup_prune.add_argument("--include-legacy", action="store_true",
                                 help="Also prune legacy plaintext directories")

    # ── serve (FastMCP) ────────────────────────────────────────
    s_serve = sub.add_parser("serve", help="Start the MCP server (FastMCP)")
    s_serve.add_argument("--policy", default=None, help="Path to YAML policy file")
    s_serve.add_argument("--prefix", default="TAG", help="Tag prefix (default: TAG)")
    s_serve.add_argument("--transport", default="stdio",
                          choices=["stdio", "streamable-http", "sse"],
                          help="MCP transport (default: stdio)")
    s_serve.add_argument("--host", default="localhost",
                          help="Bind address for network transport (default: localhost)")
    s_serve.add_argument("--port", type=int, default=8766,
                          help="Port for network transport (default: 8766)")
    s_serve.add_argument("--check", action="store_true",
                          help="Validate server config and exit")

    # ── Dispatch ────────────────────────────────────────────────

    args = p.parse_args()
    if args.cmd == "scan":
        _validate_policy_path(args.policy)
        _validate_input_path(args.input, "input")
        policy = Policy.load(args.policy)
        text = _load_text(args.input)
        _ = sanitize_text(text, policy, dry_run=True)
        return

    if args.cmd == "sanitize":
        _validate_policy_path(args.policy)
        _validate_input_path(args.input, "input")
        policy = Policy.load(args.policy)
        text = _load_text(args.input)
        out, blocked = sanitize_text(text, policy, dry_run=False)
        if blocked:
            print("ERROR: one or more blocked secrets detected; refusing to output.", file=sys.stderr)
            sys.exit(2)
        _write_text(args.output, out)
        return

    if args.cmd == "pack":
        _validate_policy_path(args.policy)
        _validate_dir_path(args.dir, "directory")
        policy = Policy.load(args.policy)
        dry_run = getattr(args, 'dry_run', False)
        no_backup = getattr(args, 'no_backup', False)
        pack_dir(args.dir, policy, prefix=args.prefix, in_place=True, dry_run=dry_run, backup=not no_backup)
        return

    if args.cmd == "unpack":
        _validate_dir_path(args.dir, "directory")
        dry_run = getattr(args, 'dry_run', False)
        no_backup = getattr(args, 'no_backup', False)
        unpack_dir(args.dir, dry_run=dry_run, backup=not no_backup)
        return

    if args.cmd == "vault-export":
        _validate_dir_path(args.dir, "directory")
        vault = Vault(args.dir)
        vault.export_to_json(args.output)
        stats = vault.get_stats()
        print(f"Vault exported to {args.output}", file=sys.stderr)
        print(f"  Total secrets: {stats['total_secrets']}", file=sys.stderr)
        print(f"  Vault location: {vault.vault_path}", file=sys.stderr)
        print(f"  Key location: {vault.key_path}", file=sys.stderr)
        return

    if args.cmd == "vault-import":
        _validate_dir_path(args.dir, "directory")
        _validate_input_path(args.input, "input")
        vault = Vault(args.dir)
        vault.import_from_json(args.input)
        stats = vault.get_stats()
        print(f"Vault imported from {args.input}", file=sys.stderr)
        print(f"  Total secrets: {stats['total_secrets']}", file=sys.stderr)
        print(f"  Vault location: {vault.vault_path}", file=sys.stderr)
        return

    if args.cmd == "vault-stats":
        _validate_dir_path(args.dir, "directory")
        vault = Vault(args.dir)
        stats = vault.get_stats()
        print(f"Vault statistics for: {args.dir}", file=sys.stderr)
        print(f"  Project slug: {vault.slug}", file=sys.stderr)
        print(f"  Total secrets: {stats['total_secrets']}", file=sys.stderr)
        print(f"  Unique tags: {stats['unique_tags']}", file=sys.stderr)
        print(f"  Vault location: {vault.vault_path}", file=sys.stderr)
        print(f"  Key location: {vault.key_path}", file=sys.stderr)
        return

    if args.cmd == "policy":
        from .policy import (validate_policy, policy_to_yaml, resolve_policy,
                             find_policy, policy_sha256, compare_policies)
        import json
        import shutil

        if args.policy_cmd == "validate":
            _validate_policy_path(args.policy)
            is_valid, errors = validate_policy(args.policy)
            if is_valid:
                print(f"Policy is valid: {args.policy}", file=sys.stderr)
                policy = Policy.load(args.policy)
                if len(policy._inherits_from) > 1:
                    print(f"  Inheritance chain:", file=sys.stderr)
                    for i, path in enumerate(policy._inherits_from, 1):
                        print(f"    {i}. {path}", file=sys.stderr)
                print(f"  Total detection rules: {len(policy.rules)}", file=sys.stderr)
                sys.exit(0)
            else:
                print(f"Policy validation failed: {args.policy}", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                sys.exit(1)

        elif args.policy_cmd == "show":
            _validate_policy_path(args.policy)
            policy = Policy.load(args.policy)
            if args.format == "yaml":
                print(policy_to_yaml(policy, include_inheritance=True))
            elif args.format == "json":
                from .policy import _policy_to_dict
                data = _policy_to_dict(policy)
                data.pop("_inherits_from", None)  # Remove internal field
                print(json.dumps(data, indent=2))
            return

        elif args.policy_cmd == "use":
            project_dir = os.path.abspath(args.dir)
            cloak_dir = os.path.join(project_dir, ".cloak")
            target = os.path.join(cloak_dir, "policy.yaml")

            # --show: display active policy info
            if getattr(args, "show_active", False):
                try:
                    path = resolve_policy(project_dir=project_dir)
                    h = policy_sha256(path)
                    pol = Policy.load(path)
                    print(f"Active policy: {path}", file=sys.stderr)
                    print(f"  Rules: {len(pol.rules)}", file=sys.stderr)
                    print(f"  SHA-256: {h}", file=sys.stderr)
                    if len(pol._inherits_from) > 1:
                        print(f"  Inheritance chain:", file=sys.stderr)
                        for i, p in enumerate(pol._inherits_from, 1):
                            print(f"    {i}. {p}", file=sys.stderr)
                except FileNotFoundError:
                    print("No active policy found.", file=sys.stderr)
                    sys.exit(1)
                return

            # --clear: remove per-project policy
            if getattr(args, "clear", False):
                if os.path.exists(target):
                    os.remove(target)
                    print(f"Removed: {target}", file=sys.stderr)
                else:
                    print("No per-project policy to remove.", file=sys.stderr)
                return

            # policy use <path>: set per-project policy
            if args.path is None:
                print("Error: provide a policy path, --show, or --clear.",
                      file=sys.stderr)
                sys.exit(1)

            source = os.path.abspath(args.path)
            if not os.path.isfile(source):
                print(f"Error: policy file not found: {args.path}",
                      file=sys.stderr)
                sys.exit(1)

            # Validate source loads correctly
            try:
                new_policy = Policy.load(source)
            except Exception as e:
                print(f"Error: invalid policy file: {e}", file=sys.stderr)
                sys.exit(1)

            # G4: Downgrade detection
            if os.path.isfile(target):
                try:
                    diff = compare_policies(target, source)
                    if diff["is_downgrade"]:
                        print("[CloakMCP] WARNING: Policy downgrade detected!",
                              file=sys.stderr)
                        print(f"  Old: {diff['old_rules']} rules, "
                              f"New: {diff['new_rules']} rules",
                              file=sys.stderr)
                        if diff["removed_rules"]:
                            print(f"  Removed rules: {', '.join(diff['removed_rules'])}",
                                  file=sys.stderr)
                        if diff["severity_changes"]:
                            for sc in diff["severity_changes"]:
                                print(f"  Severity lowered: {sc['rule_id']} "
                                      f"({sc['old_severity']} -> {sc['new_severity']})",
                                      file=sys.stderr)
                        if not getattr(args, "force", False):
                            print("  Use --force to proceed with downgrade.",
                                  file=sys.stderr)
                            sys.exit(1)
                        print("  --force: proceeding with downgrade.",
                              file=sys.stderr)
                except Exception:
                    pass  # Skip downgrade check on comparison error

            # Create .cloak/ directory
            os.makedirs(cloak_dir, exist_ok=True)

            # Copy or symlink
            if getattr(args, "link", False):
                if sys.platform == "win32":
                    print("Error: Symlinks require Developer Mode or admin on Windows. "
                          "Use 'cloak policy use' without --link instead.",
                          file=sys.stderr)
                    sys.exit(1)
                if os.path.exists(target):
                    os.remove(target)
                os.symlink(source, target)
                print(f"Linked: {source} -> {target}", file=sys.stderr)
            else:
                shutil.copy2(source, target)
                print(f"Copied: {source} -> {target}", file=sys.stderr)

            h = policy_sha256(target)
            print(f"  Rules: {len(new_policy.rules)}", file=sys.stderr)
            print(f"  SHA-256: {h}", file=sys.stderr)
            return

        elif args.policy_cmd == "reload":
            from .hooks import handle_policy_reload
            _validate_dir_path(args.dir, "directory")
            handle_policy_reload(project_dir=args.dir)
            return

    # ── v0.4.0 commands ─────────────────────────────────────────

    if args.cmd == "pack-file":
        from .filepack import pack_file
        _validate_policy_path(args.policy)
        _validate_input_path(args.file, "file")
        _validate_dir_path(args.project_root, "project-root")
        policy = Policy.load(args.policy)
        vault = Vault(args.project_root)
        dry_run = getattr(args, 'dry_run', False)
        count = pack_file(args.file, policy, vault, prefix=args.prefix, dry_run=dry_run)
        print(f"{count} secret(s) {'found' if dry_run else 'replaced'} in {args.file}", file=sys.stderr)
        return

    if args.cmd == "unpack-file":
        from .filepack import unpack_file
        _validate_input_path(args.file, "file")
        _validate_dir_path(args.project_root, "project-root")
        vault = Vault(args.project_root)
        dry_run = getattr(args, 'dry_run', False)
        count = unpack_file(args.file, vault, dry_run=dry_run)
        print(f"{count} tag(s) {'found' if dry_run else 'restored'} in {args.file}", file=sys.stderr)
        return

    if args.cmd == "guard":
        _validate_policy_path(args.policy)
        policy = Policy.load(args.policy)
        text = sys.stdin.read()
        norm = normalize(text)
        matches = scan(norm, policy)
        if matches:
            rule_ids = sorted({m.rule.id for m in matches})
            print(
                f"GUARD: {len(matches)} secret(s) detected (rules: {', '.join(rule_ids)})",
                file=sys.stderr,
            )
            sys.exit(1)
        sys.exit(0)

    if args.cmd == "sanitize-stdin":
        _validate_policy_path(args.policy)
        policy = Policy.load(args.policy)
        text = sys.stdin.read()
        out, blocked = sanitize_text(text, policy, dry_run=False)
        if blocked:
            print("ERROR: one or more blocked secrets detected; refusing to output.", file=sys.stderr)
            sys.exit(2)
        sys.stdout.write(out)
        return

    if args.cmd == "repack":
        from .dirpack import repack_dir
        import json as _json
        _validate_policy_path(args.policy)
        _validate_dir_path(args.dir, "directory")
        policy = Policy.load(args.policy)
        # Load session manifest if available (fast path)
        manifest = None
        manifest_path = os.path.join(args.dir, ".cloak-session-manifest.json")
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = _json.load(f)
            except (ValueError, OSError):
                manifest = None
        dry_run = getattr(args, 'dry_run', False)
        result = repack_dir(args.dir, policy, prefix=args.prefix, manifest=manifest, dry_run=dry_run)
        if not dry_run and manifest_path and os.path.isdir(args.dir):
            # Update manifest after repack
            from .dirpack import build_manifest, load_ignores
            ignores = load_ignores(args.dir)
            new_manifest = build_manifest(args.dir, ignores)
            with open(manifest_path, "w", encoding="utf-8") as f:
                _json.dump(new_manifest, f, ensure_ascii=False)
        return

    if args.cmd == "hook":
        from .hooks import dispatch_hook
        dispatch_hook(args.event, project_dir=args.dir)
        return

    if args.cmd == "recover":
        from .hooks import handle_recover
        _validate_dir_path(args.dir, "directory")
        handle_recover(project_dir=args.dir)
        return

    if args.cmd == "status":
        from .hooks import handle_status
        _validate_dir_path(args.dir, "directory")
        result = handle_status(project_dir=args.dir, json_output=args.json_output,
                               audit_lines=args.audit_lines)
        if args.json_output:
            import json as _json
            print(_json.dumps(result, indent=2, default=str))
        else:
            _print_status(result)
        return

    if args.cmd == "restore":
        from .hooks import handle_restore
        _validate_dir_path(args.dir, "directory")
        handle_restore(project_dir=args.dir, from_backup=args.from_backup,
                       force=args.force, backup_id=args.backup_id)
        return

    if args.cmd == "key":
        from .storage import wrap_keyfile, unwrap_keyfile, _project_slug, _key_path, _detect_key_format

        if args.key_cmd == "wrap":
            _validate_dir_path(args.dir, "directory")
            try:
                path = wrap_keyfile(args.dir)
                print(f"Key wrapped: {path}", file=sys.stderr)
                print("  Format: CLOAKKEY1 (passphrase-wrapped via scrypt)", file=sys.stderr)
            except (RuntimeError, FileNotFoundError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            return

        elif args.key_cmd == "unwrap":
            _validate_dir_path(args.dir, "directory")
            try:
                path = unwrap_keyfile(args.dir)
                print(f"Key unwrapped: {path}", file=sys.stderr)
                print("  Format: raw Fernet key (Tier 0)", file=sys.stderr)
            except (RuntimeError, FileNotFoundError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error: wrong passphrase or corrupt key file: {e}", file=sys.stderr)
                sys.exit(1)
            return

    if args.cmd == "backup":
        from .dirpack import migrate_all_legacy_backups, prune_backups

        if args.backup_cmd == "migrate":
            _validate_dir_path(args.dir, "directory")
            dry_run = getattr(args, 'dry_run', True)
            quarantine = getattr(args, 'quarantine', False)
            results = migrate_all_legacy_backups(
                args.dir, dry_run=dry_run, quarantine=quarantine
            )
            if not results:
                print("No legacy plaintext backups found.", file=sys.stderr)
                return
            for r in results:
                status = r["status"]
                size_kb = r.get("size", 0) // 1024
                print(f"  {r['timestamp']}  [{status}]  {size_kb} KB", file=sys.stderr)
            migrated = sum(1 for r in results if r["status"] == "migrated")
            failed = sum(1 for r in results if r["status"] == "failed")
            would = sum(1 for r in results if r["status"] == "would_migrate")
            if dry_run:
                print(f"\n[DRY RUN] Would migrate {would} backup(s).", file=sys.stderr)
                print("Run without --dry-run to execute.", file=sys.stderr)
            else:
                print(f"\nMigrated: {migrated}, Failed: {failed}", file=sys.stderr)
            return

        elif args.backup_cmd == "prune":
            _validate_dir_path(args.dir, "directory")
            try:
                result = prune_backups(
                    args.dir,
                    ttl=args.ttl,
                    keep_last=args.keep_last,
                    apply=args.apply,
                    include_legacy=args.include_legacy,
                )
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            for d in result["details"]:
                size_kb = d.get("size", 0) // 1024
                print(f"  {d['timestamp']}  [{d['format']}]  {size_kb} KB  -> {d['action']}",
                      file=sys.stderr)
            freed_kb = result["freed_bytes"] // 1024
            if args.apply:
                print(f"\nPruned: {result['pruned']}, Kept: {result['kept']}, "
                      f"Freed: {freed_kb} KB", file=sys.stderr)
            else:
                print(f"\n[DRY RUN] Would prune: {result['pruned']}, Keep: {result['kept']}",
                      file=sys.stderr)
                print("Add --apply to execute.", file=sys.stderr)
            return

    if args.cmd == "serve":
        try:
            from .fastmcp_server import create_server, build_parser as mcp_parser
        except ImportError:
            from .installer import _install_hint
            print(f"MCP dependencies not installed. Run: {_install_hint('mcp')}",
                  file=sys.stderr)
            sys.exit(1)
        server_argv = []
        if args.policy:
            server_argv.extend(["--policy", args.policy])
        if args.prefix and args.prefix != "TAG":
            server_argv.extend(["--prefix", args.prefix])
        server_args = mcp_parser().parse_args(server_argv)
        if getattr(args, "check", False):
            import cloakmcp
            print(f"CloakMCP server OK (v{cloakmcp.__version__})")
            return
        mcp, _ = create_server(server_args)
        transport = getattr(args, "transport", "stdio")
        host = getattr(args, "host", "localhost")
        port = getattr(args, "port", 8766)
        if transport == "stdio":
            print("CloakMCP MCP server (stdio). Ctrl+C to stop.",
                  file=sys.stderr)
            mcp.run()
        else:
            if host not in ("localhost",) and not host.startswith("127."):
                print(f"WARNING: binding to {host} exposes the server "
                      "beyond localhost.", file=sys.stderr)
            print(f"CloakMCP MCP server ({transport} on {host}:{port})",
                  file=sys.stderr)
            mcp.settings.host = host
            mcp.settings.port = port
            mcp.run(transport=transport)
        return

    if args.cmd == "verify":
        from .dirpack import verify_unpack
        _validate_dir_path(args.dir, "directory")
        result = verify_unpack(args.dir)
        print(f"Verification for: {args.dir}", file=sys.stderr)
        print(f"  Tags found:        {result['tags_found']}", file=sys.stderr)
        print(f"  Tags resolved:     {result['tags_resolved']}", file=sys.stderr)
        print(f"  Tags unresolvable: {result['tags_unresolvable']}", file=sys.stderr)
        if result["unresolvable_files"]:
            print("  Files with unresolvable tags:", file=sys.stderr)
            for rel_path, count in result["unresolvable_files"]:
                print(f"    {rel_path}: {count} tag(s)", file=sys.stderr)
        if result["tags_unresolvable"] > 0:
            sys.exit(1)
        sys.exit(0)

    if args.cmd == "doctor":
        import json
        import shutil
        import cloakmcp
        from .installer import hooks_path as _hooks_path
        from .policy import find_policy
        project_dir = os.path.abspath(args.dir)
        settings_file = os.path.join(project_dir, ".claude", "settings.local.json")

        print(f"CloakMCP Doctor v{cloakmcp.__version__}")
        print(f"{'─' * 50}")

        # Platform
        print(f"  Platform:       {sys.platform}")
        print(f"  Python:         {sys.version.split()[0]}")

        # cloak in PATH
        cloak_bin = shutil.which("cloak")
        if cloak_bin:
            print(f"  cloak CLI:      {cloak_bin} ({cloakmcp.__version__})")
        else:
            print(f"  cloak CLI:      NOT FOUND in PATH")

        # python -m cloakmcp.hooks
        try:
            from cloakmcp.hooks.__main__ import main as _hooks_main
            print(f"  python -m:      python -m cloakmcp.hooks [OK]")
        except ImportError:
            print(f"  python -m:      UNAVAILABLE")

        # Hook scripts
        hooks_dir_sh = _hooks_path("sh")
        sh_count = len([f for f in os.listdir(hooks_dir_sh)
                        if f.endswith(".sh")]) if os.path.isdir(hooks_dir_sh) else 0
        py_count = len([f for f in os.listdir(hooks_dir_sh)
                        if f.endswith(".py")]) if os.path.isdir(hooks_dir_sh) else 0
        print(f"  Hook scripts:   {sh_count} .sh + {py_count} .py in {hooks_dir_sh}")

        # Hook entrypoint validation
        expected_hooks = [
            "cloak-session-start", "cloak-session-end",
            "cloak-guard-write", "cloak-guard-read",
            "cloak-prompt-guard", "cloak-safety-guard",
            "cloak-audit-logger",
        ]
        py_present = []
        sh_present = []
        for name in expected_hooks:
            py_path = os.path.join(hooks_dir_sh, f"{name}.py")
            sh_path = os.path.join(hooks_dir_sh, f"{name}.sh")
            if os.path.isfile(py_path):
                py_present.append(name)
            if os.path.isfile(sh_path):
                sh_present.append(name)
        print(f"  .py hooks:      {len(py_present)}/{len(expected_hooks)}")
        if sys.platform != "win32":
            sh_exec = sum(
                1 for name in sh_present
                if os.access(os.path.join(hooks_dir_sh, f"{name}.sh"), os.X_OK)
            )
            print(f"  .sh hooks:      {len(sh_present)}/{len(expected_hooks)} "
                  f"({sh_exec} executable)")
        else:
            print(f"  .sh hooks:      {len(sh_present)}/{len(expected_hooks)}")
            if len(py_present) < len(expected_hooks):
                missing = set(expected_hooks) - set(py_present)
                print(f"  [WARN] Missing .py hooks on Windows: {', '.join(sorted(missing))}")

        # Installed hook method
        if os.path.isfile(settings_file):
            with open(settings_file) as f:
                sdata = json.load(f)
            hooks_cfg = sdata.get("hooks", {})
            if hooks_cfg:
                # Detect method by inspecting first hook command
                first_cmd = ""
                for entries in hooks_cfg.values():
                    for entry in entries:
                        for h in entry.get("hooks", []):
                            first_cmd = h.get("command", "")
                            break
                        if first_cmd:
                            break
                    if first_cmd:
                        break
                if first_cmd.endswith(".sh"):
                    method = "shell (.sh wrappers)"
                elif first_cmd.startswith("cloak hook"):
                    method = "cli (cloak hook <event>)"
                elif first_cmd.startswith("python"):
                    method = "python (.py scripts)"
                else:
                    method = f"custom ({first_cmd})"
                print(f"  Hook method:    {method}")
            else:
                print(f"  Hook method:    not configured")
        else:
            print(f"  Hook method:    not installed (no settings.local.json)")

        # Policy
        policy = find_policy(project_dir)
        if policy:
            print(f"  Policy:         {policy}")
        else:
            print(f"  Policy:         NONE (no policy found)")

        # Vault
        from .storage import KEYS_DIR, VAULTS_DIR, BACKUPS_DIR, _project_slug
        slug = _project_slug(project_dir)
        key_file = os.path.join(KEYS_DIR, f"{slug}.key")
        vault_file = os.path.join(VAULTS_DIR, f"{slug}.vault")
        print(f"  Project slug:   {slug}")
        print(f"  Vault key:      {'EXISTS' if os.path.isfile(key_file) else 'NONE'}")
        print(f"  Vault data:     {'EXISTS' if os.path.isfile(vault_file) else 'NONE'}")

        return

    if args.cmd == "scripts-path":
        from importlib.resources import files
        print(files("cloakmcp") / "scripts")
        return

    if args.cmd == "hooks-path":
        from .installer import hooks_path
        print(hooks_path(args.hook_format))
        return

    if args.cmd == "install":
        from .installer import install_hooks
        result = install_hooks(
            project_dir=args.dir,
            profile=args.profile,
            method=args.method,
            policy=args.policy,
            dry_run=args.dry_run,
            uninstall=args.uninstall,
        )
        action = result["action"]
        if result["dry_run"]:
            print(f"[DRY-RUN] Would {action} hooks:")
        else:
            print(f"[OK] Hooks {action}ed:")
        print(f"  Profile: {result['profile']}")
        print(f"  Method:  {result['method']}")
        if result.get("settings_template"):
            print(f"  Template: {result['settings_template']}")
        if result["hooks_installed"]:
            for h in result["hooks_installed"]:
                print(f"    - {h}")
        if result.get("policy"):
            print(f"  Policy: {result['policy']}")
        if result.get("backup_dir"):
            print(f"  Backup: {result['backup_dir']}")
        if result["errors"]:
            print(f"\n  Errors ({len(result['errors'])}):", file=sys.stderr)
            for e in result["errors"]:
                print(f"    - {e}", file=sys.stderr)
            sys.exit(1)
        return

if __name__ == "__main__":
    main()
