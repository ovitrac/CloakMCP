#!/usr/bin/env python3
"""Cross-platform hook: session-start (equivalent to cloak-session-start.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("session-start")
