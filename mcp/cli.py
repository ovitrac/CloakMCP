from __future__ import annotations
import argparse
import sys
from typing import Tuple

from .normalizer import normalize
from .policy import Policy
from .scanner import scan
from .actions import apply_action
from .audit import write_event, now_iso
from .dirpack import pack_dir, unpack_dir

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
    p = argparse.ArgumentParser(prog="mcp", description="Micro-Cleanse Preprocessor (local secret-removal)")
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

    s_unpack = sub.add_parser("unpack", help="Unpack a directory: restore tags from vault")
    s_unpack.add_argument("--dir", required=True, help="Directory to process")

    args = p.parse_args()
    if args.cmd == "scan":
        policy = Policy.load(args.policy)
        text = _load_text(args.input)
        _ = sanitize_text(text, policy, dry_run=True)
        return

    if args.cmd == "sanitize":
        policy = Policy.load(args.policy)
        text = _load_text(args.input)
        out, blocked = sanitize_text(text, policy, dry_run=False)
        if blocked:
            print("ERROR: one or more blocked secrets detected; refusing to output.", file=sys.stderr)
            sys.exit(2)
        _write_text(args.output, out)
        return

    if args.cmd == "pack":
        policy = Policy.load(args.policy)
        pack_dir(args.dir, policy, prefix=args.prefix, in_place=True)
        return

    if args.cmd == "unpack":
        unpack_dir(args.dir)
        return

if __name__ == "__main__":
    main()
