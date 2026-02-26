"""Allow: python -m cloakmcp.hooks <event> [--dir .]"""
from __future__ import annotations

import argparse
import sys

from . import dispatch_hook


def main() -> None:
    p = argparse.ArgumentParser(
        prog="python -m cloakmcp.hooks",
        description="CloakMCP hook dispatcher (cross-platform entrypoint)",
    )
    p.add_argument(
        "event",
        choices=[
            "session-start", "session-end", "guard-write",
            "guard-read", "prompt-guard", "safety-guard", "audit-log",
        ],
        help="Hook event type",
    )
    p.add_argument("--dir", default=".", help="Project root directory")
    args = p.parse_args()
    dispatch_hook(args.event, project_dir=args.dir)


if __name__ == "__main__":
    main()
