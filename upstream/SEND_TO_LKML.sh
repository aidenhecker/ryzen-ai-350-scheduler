#!/usr/bin/env bash
# ============================================================================
# SEND_TO_LKML.sh — One-Command Upstream Linux Kernel [PATCH v2 0/2] Helper
# Usage:
#   ./upstream/SEND_TO_LKML.sh dry-run [in-reply-to-msg-id]
#   ./upstream/SEND_TO_LKML.sh self-test [in-reply-to-msg-id]
#   ./upstream/SEND_TO_LKML.sh send [in-reply-to-msg-id]
# ============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-dry-run}"
REPLY_TO="${2:-}"

REPLY_ARGS=()
if [[ -n "${REPLY_TO}" ]]; then
  REPLY_ARGS=(--in-reply-to="${REPLY_TO}")
fi

RECIPIENTS=(
  --to="Huang Rui <ray.huang@amd.com>"
  --to="Mario Limonciello <mario.limonciello@amd.com>"
  --to="Perry Yuan <perry.yuan@amd.com>"
  --to="K Prateek Nayak <kprateek.nayak@amd.com>"
  --to="Rafael J. Wysocki <rafael@kernel.org>"
  --to="Viresh Kumar <viresh.kumar@linaro.org>"
  --to="Hans de Goede <hansg@kernel.org>"
  --to="Ilpo Järvinen <ilpo.jarvinen@linux.intel.com>"
  --cc="Ingo Molnar <mingo@redhat.com>"
  --cc="Peter Zijlstra <peterz@infradead.org>"
  --cc="linux-pm@vger.kernel.org"
  --cc="platform-driver-x86@vger.kernel.org"
  --cc="linux-kernel@vger.kernel.org"
)

case "${MODE}" in
  dry-run)
    git -c user.name="Aiden Hecker" -c user.email="heckeraiden@gmail.com" send-email --dry-run --confirm=never --from="Aiden Hecker <heckeraiden@gmail.com>" "${RECIPIENTS[@]}" --thread --no-chain-reply-to "${REPLY_ARGS[@]}" "${DIR}"/v2-*.patch
    ;;
  self-test)
    git -c user.name="Aiden Hecker" -c user.email="heckeraiden@gmail.com" send-email --confirm=never --from="Aiden Hecker <heckeraiden@gmail.com>" --suppress-cc=all --to="heckeraiden@gmail.com" --thread --no-chain-reply-to "${REPLY_ARGS[@]}" "${DIR}"/v2-*.patch
    ;;
  send)
    git -c user.name="Aiden Hecker" -c user.email="heckeraiden@gmail.com" send-email --from="Aiden Hecker <heckeraiden@gmail.com>" "${RECIPIENTS[@]}" --thread --no-chain-reply-to "${REPLY_ARGS[@]}" "${DIR}"/v2-*.patch
    ;;
  *)
    echo "Usage: ./upstream/SEND_TO_LKML.sh [dry-run|self-test|send] [in-reply-to-msg-id]"
    exit 1
    ;;
esac
