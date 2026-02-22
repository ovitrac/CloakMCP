#!/bin/bash
# install_claude.sh — Install CloakMCP hooks for Claude Code
#
# Usage:
#   ./scripts/install_claude.sh [OPTIONS]
#
# Options:
#   --profile secrets-only|hardened   Hook profile (default: secrets-only)
#   --method  copy|symlink            Install method (default: copy)
#   --dry-run                         Show planned actions without changes
#   --uninstall                       Remove installed hooks
#   --help                            Show this help
#
# Profiles:
#   secrets-only  Pack/unpack + write guard + PostToolUse audit (default)
#   hardened       Same + Bash safety guard (blocks rm -rf /, curl|sh, etc.)
#
# This script is idempotent: safe to run multiple times.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────

PROFILE="secrets-only"
METHOD="copy"
DRY_RUN=false
UNINSTALL=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(pwd)"
CLAUDE_DIR="$PROJECT_DIR/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS_FILE="$CLAUDE_DIR/settings.local.json"
SOURCE_HOOKS="$SCRIPT_DIR/hooks"
SOURCE_SETTINGS="$SCRIPT_DIR/settings"

# ── Colors ────────────────────────────────────────────────────────

if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' CYAN='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
step()  { echo -e "${CYAN}[STEP]${NC} ${BOLD}$1${NC}"; }
dry()   { echo -e "${YELLOW}[DRY-RUN]${NC} $1"; }

# ── Parse arguments ───────────────────────────────────────────────

show_help() {
    sed -n '2,/^$/{ s/^# //; s/^#//; p }' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            if [[ "$PROFILE" != "secrets-only" && "$PROFILE" != "hardened" ]]; then
                error "Unknown profile: $PROFILE (expected: secrets-only, hardened)"
                exit 1
            fi
            shift 2 ;;
        --method)
            METHOD="$2"
            if [[ "$METHOD" != "copy" && "$METHOD" != "symlink" ]]; then
                error "Unknown method: $METHOD (expected: copy, symlink)"
                exit 1
            fi
            shift 2 ;;
        --dry-run)  DRY_RUN=true; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help|-h)  show_help ;;
        *)
            error "Unknown option: $1"
            echo "Run with --help for usage."
            exit 1 ;;
    esac
done

# ── Phase 1: Preflight ───────────────────────────────────────────

step "Phase 1: Preflight checks"

if ! command -v cloak &>/dev/null; then
    error "'cloak' CLI not found in PATH."
    echo "  Install CloakMCP first: pip install -e ."
    exit 1
fi
info "cloak CLI found: $(command -v cloak)"

if ! command -v python3 &>/dev/null; then
    error "python3 not found in PATH."
    exit 1
fi
info "python3 found: $(command -v python3)"

if [ ! -d "$SOURCE_HOOKS" ]; then
    error "Source hooks directory not found: $SOURCE_HOOKS"
    exit 1
fi

if [ "$PROFILE" = "secrets-only" ]; then
    SETTINGS_TEMPLATE="$SOURCE_SETTINGS/hooks.json"
else
    SETTINGS_TEMPLATE="$SOURCE_SETTINGS/hooks-hardened.json"
fi

if [ ! -f "$SETTINGS_TEMPLATE" ]; then
    error "Settings template not found: $SETTINGS_TEMPLATE"
    exit 1
fi
info "Profile: $PROFILE (template: $(basename "$SETTINGS_TEMPLATE"))"

# ── Uninstall mode ────────────────────────────────────────────────

if [ "$UNINSTALL" = true ]; then
    step "Uninstalling CloakMCP hooks"

    # Remove hook scripts
    if [ -d "$HOOKS_DIR" ]; then
        for f in "$HOOKS_DIR"/cloak-*.sh; do
            [ -f "$f" ] || continue
            if [ "$DRY_RUN" = true ]; then
                dry "Would remove: $f"
            else
                rm -f "$f"
                info "Removed: $f"
            fi
        done
    fi

    # Remove hooks key from settings JSON
    if [ -f "$SETTINGS_FILE" ]; then
        if [ "$DRY_RUN" = true ]; then
            dry "Would remove 'hooks' key from $SETTINGS_FILE"
        else
            python3 -c "
import json, sys, os, tempfile

with open('$SETTINGS_FILE', 'r') as f:
    data = json.load(f)

data.pop('hooks', None)

fd, tmp = tempfile.mkstemp(dir=os.path.dirname('$SETTINGS_FILE'))
with os.fdopen(fd, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
os.replace(tmp, '$SETTINGS_FILE')
"
            info "Removed 'hooks' key from $SETTINGS_FILE"
        fi
    fi

    echo ""
    info "CloakMCP hooks uninstalled."
    exit 0
fi

# ── Phase 2: Backup ──────────────────────────────────────────────

step "Phase 2: Backup existing configuration"

BACKUP_DIR="$CLAUDE_DIR/.backup-$(date +%Y%m%d-%H%M%S)"

needs_backup=false
if [ -f "$SETTINGS_FILE" ] || [ -d "$HOOKS_DIR" ]; then
    needs_backup=true
fi

if [ "$needs_backup" = true ]; then
    if [ "$DRY_RUN" = true ]; then
        dry "Would backup to: $BACKUP_DIR"
    else
        mkdir -p "$BACKUP_DIR"
        [ -f "$SETTINGS_FILE" ] && cp "$SETTINGS_FILE" "$BACKUP_DIR/"
        [ -d "$HOOKS_DIR" ] && cp -r "$HOOKS_DIR" "$BACKUP_DIR/"
        info "Backup created: $BACKUP_DIR"
    fi
else
    info "No existing configuration to backup"
fi

# ── Phase 3: Install hook scripts ────────────────────────────────

step "Phase 3: Install hook scripts ($METHOD)"

if [ "$DRY_RUN" = true ]; then
    dry "Would create: $HOOKS_DIR/"
else
    mkdir -p "$HOOKS_DIR"
fi

# Determine which scripts to install
HOOK_SCRIPTS=(
    "cloak-session-start.sh"
    "cloak-session-end.sh"
    "cloak-guard-write.sh"
    "cloak-prompt-guard.sh"
    "cloak-audit-logger.sh"
)

if [ "$PROFILE" = "hardened" ]; then
    HOOK_SCRIPTS+=("cloak-safety-guard.sh")
fi

for script in "${HOOK_SCRIPTS[@]}"; do
    src="$SOURCE_HOOKS/$script"
    dst="$HOOKS_DIR/$script"

    if [ ! -f "$src" ]; then
        warn "Source script not found: $src (skipped)"
        continue
    fi

    if [ "$DRY_RUN" = true ]; then
        dry "Would install: $script -> $dst"
    else
        if [ "$METHOD" = "symlink" ]; then
            ln -sf "$src" "$dst"
        else
            cp "$src" "$dst"
        fi
        chmod +x "$dst"
        info "Installed: $script"
    fi
done

# ── Phase 4: Merge settings ──────────────────────────────────────

step "Phase 4: Merge hook settings into settings.local.json"

if [ "$DRY_RUN" = true ]; then
    dry "Would merge $SETTINGS_TEMPLATE into $SETTINGS_FILE"
else
    mkdir -p "$CLAUDE_DIR"
    python3 -c "
import json, sys, os, tempfile

settings_file = '$SETTINGS_FILE'
template_file = '$SETTINGS_TEMPLATE'

# Read existing settings or start fresh
existing = {}
if os.path.isfile(settings_file):
    with open(settings_file, 'r') as f:
        existing = json.load(f)

# Read template
with open(template_file, 'r') as f:
    template = json.load(f)

# Merge: replace hooks key, preserve everything else
existing['hooks'] = template['hooks']

# Atomic write via temp + rename
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(settings_file) or '.')
with os.fdopen(fd, 'w') as f:
    json.dump(existing, f, indent=2)
    f.write('\n')
os.replace(tmp, settings_file)
"
    info "Hook settings merged into $SETTINGS_FILE"
fi

# ── Phase 5: Verify ──────────────────────────────────────────────

step "Phase 5: Verify installation"

if [ "$DRY_RUN" = true ]; then
    dry "Would verify scripts are executable and settings are valid JSON"
else
    errors=0

    # Check scripts are executable
    for script in "${HOOK_SCRIPTS[@]}"; do
        dst="$HOOKS_DIR/$script"
        if [ ! -x "$dst" ]; then
            error "Not executable: $dst"
            errors=$((errors + 1))
        fi
    done

    # Check settings is valid JSON
    if ! python3 -c "import json; json.load(open('$SETTINGS_FILE'))" 2>/dev/null; then
        error "Invalid JSON: $SETTINGS_FILE"
        errors=$((errors + 1))
    fi

    # Check hook commands reference existing files
    python3 -c "
import json, sys, os

with open('$SETTINGS_FILE', 'r') as f:
    data = json.load(f)

hooks = data.get('hooks', {})
for event, entries in hooks.items():
    for entry in entries:
        for hook in entry.get('hooks', []):
            cmd = hook.get('command', '')
            # Resolve relative to project dir
            full = os.path.join('$PROJECT_DIR', cmd)
            if not os.path.isfile(full):
                print(f'WARNING: Hook command not found: {cmd}', file=sys.stderr)
" 2>&1 | while read -r line; do warn "$line"; done

    if [ "$errors" -gt 0 ]; then
        error "Verification found $errors error(s)"
        exit 1
    fi
    info "All checks passed"
fi

# ── Phase 6: Summary ─────────────────────────────────────────────

step "Phase 6: Summary"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo -e "  ${BOLD}Dry-run complete. No changes were made.${NC}"
    echo "  Re-run without --dry-run to apply."
else
    echo -e "  ${BOLD}CloakMCP Claude Code hooks installed successfully.${NC}"
    echo ""
    echo "  Profile: $PROFILE"
    echo "  Method:  $METHOD"
    echo "  Hooks installed:"
    for script in "${HOOK_SCRIPTS[@]}"; do
        echo "    - $script"
    done
    echo ""
    echo "  What happens now:"
    echo "    - Session start: files are packed (secrets -> TAG-xxxx tags)"
    echo "    - During session: Write/Edit guard warns about raw secrets"
    if [ "$PROFILE" = "hardened" ]; then
        echo "    - Bash commands: safety guard blocks dangerous commands"
    fi
    echo "    - Post tool use: audit events logged to .cloak-session-audit.jsonl"
    echo "    - Session end: files are unpacked (tags -> secrets restored)"
    echo ""
    echo "  Environment variables (optional):"
    echo "    CLOAK_POLICY       path to policy YAML (default: examples/mcp_policy.yaml)"
    echo "    CLOAK_PREFIX        tag prefix (default: TAG)"
    echo "    CLOAK_AUDIT_TOOLS   set to 1 for full tool metadata logging"
    echo ""
    echo "  Recovery (if session exits abnormally):"
    echo "    cloak recover --dir ."
    if [ "$needs_backup" = true ] && [ "$DRY_RUN" = false ]; then
        echo ""
        echo "  Backup location: $BACKUP_DIR"
    fi
fi
echo ""
