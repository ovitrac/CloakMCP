#!/usr/bin/env python3
"""Cross-platform hook: guard-read (equivalent to cloak-guard-read.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("guard-read")
