#!/usr/bin/env python3
"""Cross-platform hook: session-end (equivalent to cloak-session-end.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("session-end")
