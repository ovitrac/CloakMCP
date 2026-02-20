#!/bin/bash
# ============================================================================
# CloakMCP Demo Transcript — Screenshot-Friendly Before/After Diffs
# ============================================================================
#
# Generates a clean, non-interactive transcript showing exact diffs:
#   ORIGINAL (secrets) → PACKED (tags) → RESTORED (secrets back)
#
# Usage:
#   cd demo && bash transcript.sh            # colored terminal output
#   cd demo && bash transcript.sh > out.txt  # plain text (no colors)
#
# Requirements:
#   - CloakMCP installed: pip install -e ..
#   - HMAC key present
#
# ============================================================================

set -euo pipefail

# ── Colors (disabled when piped) ──────────────────────────────
if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    YELLOW='\033[1;33m'
    DIM='\033[2m'
    BG_RED='\033[41m'
    BG_GREEN='\033[42m'
    BG_CYAN='\033[44m'
    NC='\033[0m'
else
    BOLD='' GREEN='' RED='' CYAN='' YELLOW='' DIM='' NC=''
    BG_RED='' BG_GREEN='' BG_CYAN=''
fi

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"
POLICY="$PROJECT_ROOT/examples/mcp_policy.yaml"

JAVA_FILE="src/main/java/com/acme/payments/BankTransferService.java"
PROPS_FILE="src/main/resources/application.properties"
YAML_FILE="src/main/resources/application.yml"

# Files to track
FILES=("$JAVA_FILE" "$PROPS_FILE" "$YAML_FILE")
FILE_LABELS=("BankTransferService.java" "application.properties" "application.yml")

SNAP_DIR=$(mktemp -d)
trap 'rm -rf "$SNAP_DIR"' EXIT

# ── Preflight ─────────────────────────────────────────────────
cd "$DEMO_DIR"

if ! command -v cloak &>/dev/null; then
    echo -e "${RED}Error: 'cloak' not found. Run: pip install -e $PROJECT_ROOT${NC}" >&2
    exit 1
fi

ruler() {
    echo -e "${DIM}────────────────────────────────────────────────────────────────────${NC}"
}

section() {
    echo ""
    echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  $1$(printf '%*s' $((64 - ${#1})) '')│${NC}"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

file_header() {
    echo -e "  ${BOLD}${YELLOW}$1${NC}  ${DIM}($2)${NC}"
    ruler
}

show_secrets_excerpt() {
    local file="$1"
    local label="$2"
    local phase="$3"   # ORIGINAL | PACKED | RESTORED
    local color="$RED"
    [ "$phase" = "PACKED" ] && color="$GREEN"
    [ "$phase" = "RESTORED" ] && color="$CYAN"

    file_header "$label" "$phase"

    # Show lines containing secrets/tags (numbered)
    local pattern
    case "$label" in
        BankTransferService.java)
            pattern='(API_KEY|PASSWORD|SMTP_|PRIVATE_KEY|JWT|AWS_ACCESS|DB_URL|DB_USER|webhook|TAG-[0-9a-f]{12})'
            ;;
        application.properties)
            pattern='(password|key=|secret|username|TAG-[0-9a-f]{12})'
            ;;
        application.yml)
            pattern='(password|key|secret|username|email|endpoint|url|TAG-[0-9a-f]{12})'
            ;;
    esac

    grep -n -E "$pattern" "$file" 2>/dev/null \
        | grep -v '^#' \
        | head -18 \
        | while IFS= read -r line; do
            echo -e "  ${color}${line}${NC}"
        done
    echo ""
}

# ══════════════════════════════════════════════════════════════
# Phase 1: Snapshot originals
# ══════════════════════════════════════════════════════════════

section "PHASE 1 — ORIGINAL: Secrets in Source Code"

echo -e "  ${RED}${BOLD}WARNING:${NC} These files contain credentials that would leak to any LLM."
echo ""

for i in "${!FILES[@]}"; do
    cp "${FILES[$i]}" "$SNAP_DIR/original_$i"
    show_secrets_excerpt "${FILES[$i]}" "${FILE_LABELS[$i]}" "ORIGINAL"
done

echo -e "  ${DIM}Total files with secrets: ${#FILES[@]} config/source files${NC}"
echo -e "  ${DIM}Secret types: API keys, passwords, PEM blocks, JWTs, AWS keys, emails, internal URLs${NC}"

# ══════════════════════════════════════════════════════════════
# Phase 2: Pack
# ══════════════════════════════════════════════════════════════

section "PHASE 2 — PACK: cloak pack --policy mcp_policy.yaml --dir demo/"

echo -e "  ${DIM}\$ cloak pack --policy examples/mcp_policy.yaml --dir demo/ --no-backup${NC}"
echo ""

cloak pack --policy "$POLICY" --dir "$DEMO_DIR" --no-backup 2>&1 | sed 's/^/  /'

echo ""

for i in "${!FILES[@]}"; do
    cp "${FILES[$i]}" "$SNAP_DIR/packed_$i"
    show_secrets_excerpt "${FILES[$i]}" "${FILE_LABELS[$i]}" "PACKED"
done

echo -e "  ${GREEN}${BOLD}Result:${NC} Every secret replaced by a deterministic ${BOLD}TAG-xxxxxxxxxxxx${NC} token."
echo -e "  ${GREEN}These files are safe to send to Claude, Codex, or Gemini.${NC}"

# ══════════════════════════════════════════════════════════════
# Phase 3: Side-by-side diff (key lines)
# ══════════════════════════════════════════════════════════════

section "PHASE 3 — DIFF: Before vs After (key lines)"

for i in "${!FILES[@]}"; do
    echo -e "  ${BOLD}${FILE_LABELS[$i]}${NC}"
    ruler

    # Extract matching lines from original and packed
    orig_lines=$(grep -n -E '(password|key|secret|API_KEY|PASSWORD|SMTP_|PRIVATE_KEY|JWT|AWS_ACCESS|DB_URL|DB_USER|webhook)' \
        "$SNAP_DIR/original_$i" 2>/dev/null | grep -v '^#' | head -8) || true
    pack_lines=$(grep -n -E '(password|key|secret|API_KEY|PASSWORD|SMTP_|PRIVATE_KEY|JWT|AWS_ACCESS|DB_URL|DB_USER|webhook|TAG-[0-9a-f]{12})' \
        "$SNAP_DIR/packed_$i" 2>/dev/null | grep -v '^#' | head -8) || true

    # Show original lines as removals, packed lines as additions
    if [ -n "$orig_lines" ]; then
        while IFS= read -r line; do
            echo -e "  ${RED}- $line${NC}"
        done <<< "$orig_lines"
    fi
    if [ -n "$pack_lines" ]; then
        while IFS= read -r line; do
            echo -e "  ${GREEN}+ $line${NC}"
        done <<< "$pack_lines"
    fi
    echo ""
done

# ══════════════════════════════════════════════════════════════
# Phase 4: Unpack (restore)
# ══════════════════════════════════════════════════════════════

section "PHASE 4 — UNPACK: cloak unpack --dir demo/"

echo -e "  ${DIM}\$ cloak unpack --dir demo/ --no-backup${NC}"
echo ""

cloak unpack --dir "$DEMO_DIR" --no-backup 2>&1 | sed 's/^/  /'

echo ""

for i in "${!FILES[@]}"; do
    show_secrets_excerpt "${FILES[$i]}" "${FILE_LABELS[$i]}" "RESTORED"
done

echo -e "  ${CYAN}${BOLD}Result:${NC} All original secrets restored from encrypted vault."

# ══════════════════════════════════════════════════════════════
# Phase 5: Verify round-trip integrity
# ══════════════════════════════════════════════════════════════

section "PHASE 5 — VERIFY: Round-Trip Integrity Check"

all_ok=true
for i in "${!FILES[@]}"; do
    if diff -q "$SNAP_DIR/original_$i" "${FILES[$i]}" &>/dev/null; then
        echo -e "  ${GREEN}PASS${NC}  ${FILE_LABELS[$i]} — identical to original"
    else
        echo -e "  ${RED}FAIL${NC}  ${FILE_LABELS[$i]} — differs from original!"
        all_ok=false
    fi
done

echo ""
if $all_ok; then
    echo -e "  ${GREEN}${BOLD}All files restored perfectly. Zero data loss.${NC}"
else
    echo -e "  ${RED}${BOLD}Some files differ — check vault integrity.${NC}"
fi

# ══════════════════════════════════════════════════════════════
# Phase 6: Vault stats
# ══════════════════════════════════════════════════════════════

section "PHASE 6 — VAULT: Encrypted Storage Statistics"

cloak vault-stats --dir "$DEMO_DIR" 2>&1 | sed 's/^/  /'

echo ""
echo -e "  ${DIM}Vault location: ~/.cloakmcp/vaults/ (never committed, never sent to LLM)${NC}"
echo -e "  ${DIM}Encryption: Fernet (AES-128-CBC + HMAC-SHA256)${NC}"

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  CloakMCP — Demo Complete${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Lifecycle:${NC}  ORIGINAL → PACK (tags) → LLM works safely → UNPACK (restore)"
echo -e "  ${BOLD}Guarantee:${NC} Secrets never leave your machine. Round-trip is lossless."
echo -e "  ${BOLD}Vault:${NC}     Encrypted, local, deterministic. Same secret = same tag."
echo ""
echo -e "  ${DIM}CloakMCP: local-first secret sanitization before LLM exposure.${NC}"
echo ""
