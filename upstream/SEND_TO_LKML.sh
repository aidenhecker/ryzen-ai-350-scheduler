#!/usr/bin/env bash
# ============================================================================
# SEND_TO_LKML.sh — One-Command Upstream Linux Kernel Submission Helper
# Usage:
#   ./upstream/SEND_TO_LKML.sh dry-run    # Safe preview (no emails sent)
#   ./upstream/SEND_TO_LKML.sh self-test  # Send test copy ONLY to heckeraiden@gmail.com
#   ./upstream/SEND_TO_LKML.sh send       # Send LIVE to LKML & Maintainers
# ============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-dry-run}"

case "${MODE}" in
  dry-run)
    git send-email --dry-run --from="Aiden Hecker <heckeraiden@gmail.com>" --thread --no-chain-reply-to "${DIR}"/*.patch
    ;;
  self-test)
    git send-email --from="Aiden Hecker <heckeraiden@gmail.com>" --suppress-cc=all --to="heckeraiden@gmail.com" --thread --no-chain-reply-to "${DIR}"/*.patch
    ;;
  send)
    git send-email --from="Aiden Hecker <heckeraiden@gmail.com>" --thread --no-chain-reply-to "${DIR}"/*.patch
    ;;
  *)
    echo "Usage: ./upstream/SEND_TO_LKML.sh [dry-run|self-test|send]"
    exit 1
    ;;
esac
