#!/usr/bin/env python3
"""Cross-platform hook: safety-guard (equivalent to cloak-safety-guard.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("safety-guard")
