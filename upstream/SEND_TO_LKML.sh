#!/usr/bin/env bash
# ============================================================================
# SEND_TO_LKML.sh — Upstream Linux Kernel Submission Helper
# Sends the AMD Ryzen AI 7 350 (Family 1Ah Model 60h) Entropy & Capacity
# patch series to the Linux Power Management, x86 Platform, and Scheduler
# maintainers (and LKML).
# ============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================================"
echo " AMD Ryzen AI 7 350 Upstream Linux Kernel Patch Series (Dry-Run Preview)"
echo "============================================================================"
echo " Patches ready in: ${DIR}"
echo "   0. 0000-cover-letter.patch"
echo "   1. 0001-cpufreq-amd-pstate-fix-prefcore-and-cpu-scale-on-zen5-hybrid.patch"
echo "   2. 0002-platform-x86-amd-hfi-enforce-zen5-vs-zen5c-asymmetric-capacity.patch"
echo ""
echo " Maintainers & Lists:"
echo "   To: Mario Limonciello <mario.limonciello@amd.com> (AMD P-State / HFI)"
echo "   To: Perry Yuan <perry.yuan@amd.com> (AMD P-State)"
echo "   To: Gautham R. Shenoy <gautham.shenoy@amd.com> (AMD Scheduler / P-State)"
echo "   To: Shyam Sundar S K <Shyam-sundar.S-k@amd.com> (AMD HFI)"
echo "   To: Rafael J. Wysocki <rafael@kernel.org> (Linux PM / cpufreq)"
echo "   To: Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org> (x86 / Scheduler)"
echo "   To: Tejun Heo <tj@kernel.org> (sched_ext)"
echo "   Cc: linux-pm@vger.kernel.org, platform-driver-x86@vger.kernel.org, linux-kernel@vger.kernel.org"
echo "============================================================================"
echo ""
echo "To perform a safe dry-run with git send-email:"
echo "  git send-email --dry-run ${DIR}/*.patch"
echo ""
echo "To transmit live to LKML once your ~/.gitconfig [sendemail] SMTP is set:"
echo "  git send-email ${DIR}/*.patch"
