#!/bin/bash
# [DEPRECATED] Use scripts/install_claude.sh instead.
# This script will be removed in a future release.
echo "[DEPRECATED] Use scripts/install_claude.sh instead" >&2
#
# install-claude-hooks.sh — Set up CloakMCP hooks for Claude Code
#
# Usage:
#   ./scripts/install-claude-hooks.sh [project-dir]
#
# This script:
#   1. Creates .claude/hooks/ with thin wrapper scripts
#   2. Merges hook config into .claude/settings.local.json (preserving existing settings)
#   3. Verifies `cloak` CLI is available
#
# The hooks enable automatic pack/unpack of secrets at session boundaries.

set -euo pipefail

PROJECT_DIR="${1:-.}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
CLAUDE_DIR="$PROJECT_DIR/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS_FILE="$CLAUDE_DIR/settings.local.json"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' NC=''
fi

info()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# ── Preflight checks ───────────────────────────────────────────

if ! command -v cloak &>/dev/null; then
    error "'cloak' CLI not found in PATH."
    echo "  Install CloakMCP first: pip install -e ."
    exit 1
fi

if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    error "Python not found."
    exit 1
fi

# ── Create hook scripts ────────────────────────────────────────

mkdir -p "$HOOKS_DIR"

cat > "$HOOKS_DIR/cloak-session-start.sh" << 'HOOK'
#!/bin/bash
exec cloak hook session-start
HOOK

cat > "$HOOKS_DIR/cloak-session-end.sh" << 'HOOK'
#!/bin/bash
exec cloak hook session-end
HOOK

cat > "$HOOKS_DIR/cloak-guard-write.sh" << 'HOOK'
#!/bin/bash
exec cloak hook guard-write
HOOK

chmod +x "$HOOKS_DIR"/cloak-*.sh
info "Hook scripts created in $HOOKS_DIR"

# ── Merge settings.local.json ──────────────────────────────────

HOOKS_JSON='{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/cloak-session-start.sh",
            "timeout": 60000
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/cloak-session-end.sh",
            "timeout": 60000
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/cloak-guard-write.sh",
            "timeout": 10000
          }
        ]
      }
    ]
  }
}'

if [ -f "$SETTINGS_FILE" ]; then
    # Merge hooks into existing settings using Python (no jq dependency)
    python3 -c "
import json, sys

with open('$SETTINGS_FILE', 'r') as f:
    existing = json.load(f)

new_hooks = json.loads('''$HOOKS_JSON''')

existing['hooks'] = new_hooks['hooks']

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(existing, f, indent=2)
    f.write('\n')
"
    info "Hook config merged into existing $SETTINGS_FILE"
else
    mkdir -p "$CLAUDE_DIR"
    echo "$HOOKS_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
with open('$SETTINGS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
"
    info "Created $SETTINGS_FILE with hook config"
fi

# ── Verify ──────────────────────────────────────────────────────

echo ""
info "CloakMCP Claude Code hooks installed successfully."
echo ""
echo "  What happens now:"
echo "    - Session start: files are packed (secrets -> TAG-xxxx tags)"
echo "    - During session: Write/Edit guard warns about raw secrets"
echo "    - Session end: files are unpacked (tags -> secrets restored)"
echo ""
echo "  Environment variables (optional):"
echo "    CLOAK_POLICY  — path to policy YAML (default: examples/mcp_policy.yaml)"
echo "    CLOAK_PREFIX   — tag prefix (default: TAG)"
echo ""
echo "  Recovery (if session exits abnormally):"
echo "    cloak recover --dir ."
echo ""
