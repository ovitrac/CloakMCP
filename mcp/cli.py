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

if __name__ == "__main__":
    main()
