#!/usr/bin/env python3
"""Cross-platform hook: prompt-guard (equivalent to cloak-prompt-guard.sh)."""
import sys
from cloakmcp.hooks import dispatch_hook
dispatch_hook("prompt-guard")
