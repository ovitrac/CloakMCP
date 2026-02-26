#!/usr/bin/env python3
"""Cross-platform hook: guard-write (equivalent to cloak-guard-write.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("guard-write")
