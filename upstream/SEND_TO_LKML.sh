#!/usr/bin/env bash
# ============================================================================
# SEND_TO_LKML.sh — Upstream Linux Kernel Submission Helper (Fedora 45)
# ============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ge 2 ]]; then
    REAL_NAME="$1"
    REAL_EMAIL="$2"
    sed -i "s/Aiden <aiden@users.noreply.github.com>/${REAL_NAME} <${REAL_EMAIL}>/g" "${DIR}"/*.patch
    echo "[✓] Updated From:, Tested-by:, and Signed-off-by: to: ${REAL_NAME} <${REAL_EMAIL}>"
fi

if ! git send-email --version >/dev/null 2>&1; then
    echo "[!] Note: 'git-email' is not installed yet on Fedora."
    echo "    Install it with: sudo dnf install -y git-email"
    exit 0
fi

echo "============================================================================"
echo " Running Safe Dry-Run of LKML Patch Series ([PATCH 0/2] .. [PATCH 2/2])"
echo "============================================================================"
git send-email --dry-run "${DIR}"/*.patch
echo ""
echo "When ready to send live to LKML, run:"
echo "  git send-email ${DIR}/*.patch"
