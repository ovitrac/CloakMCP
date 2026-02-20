from __future__ import annotations
import argparse
import os
import sys
from typing import Tuple

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

def main() -> None:
    p = argparse.ArgumentParser(prog="cloak", description="Micro-Cleanse Preprocessor (local secret-removal)")
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
                                          "safety-guard", "audit-log"],
                        help="Hook event type")
    s_hook.add_argument("--dir", default=".", help="Project root directory")

    # ── v0.4.0: Recovery ────────────────────────────────────────

    s_recover = sub.add_parser("recover", help="Detect stale session state and run unpack")
    s_recover.add_argument("--dir", default=".", help="Project root directory")

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
        from .policy import validate_policy, policy_to_yaml
        import json

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

    if args.cmd == "hook":
        from .hooks import dispatch_hook
        dispatch_hook(args.event, project_dir=args.dir)
        return

    if args.cmd == "recover":
        from .hooks import handle_recover
        _validate_dir_path(args.dir, "directory")
        handle_recover(project_dir=args.dir)
        return

if __name__ == "__main__":
    main()
