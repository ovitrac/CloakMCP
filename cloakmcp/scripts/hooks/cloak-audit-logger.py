#!/usr/bin/env python3
"""Cross-platform hook: audit-log (equivalent to cloak-audit-logger.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("audit-log")
