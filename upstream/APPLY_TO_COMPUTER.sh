#!/usr/bin/env bash
# ============================================================================
# APPLY_TO_COMPUTER.sh — Apply Ring-0 Asymmetric Capacity & Patched Kernel
# Supports SecureBoot-enabled Fedora hosts safely.
#
# Usage:
#   ./upstream/APPLY_TO_COMPUTER.sh kmod    # Sign & load zen5_entropy_kmod.ko on running kernel
#   ./upstream/APPLY_TO_COMPUTER.sh kernel  # Install compiled 7.4.0-rc2-zen5hybrid kernel (keeps Fedora fallback)
# ============================================================================
set -euo pipefail

MODE="${1:-kmod}"
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KVER="$(uname -r)"
MOK_DIR="${HOME}/.config/zen5-scheduler/mok"
MOK_KEY="${MOK_DIR}/MOK.priv"
MOK_DER="${MOK_DIR}/MOK.der"

ensure_mok_key() {
  mkdir -p "${MOK_DIR}"
  if [[ ! -f "${MOK_KEY}" || ! -f "${MOK_DER}" ]]; then
    echo "Generating 2048-bit Machine Owner Key (MOK) in ${MOK_DIR}..."
    openssl req -new -x509 -newkey rsa:2048 \
      -keyout "${MOK_KEY}" -outform DER -out "${MOK_DER}" \
      -nodes -days 36500 -subj "/CN=Zen5 Entropy Scheduler MOK/"
    chmod 600 "${MOK_KEY}"
  fi
}

case "${MODE}" in
  kmod)
    make -C "${PROJ_DIR}" kmod
    KO="${PROJ_DIR}/bin/zen5_entropy_kmod.ko"
    SIGN_FILE="/usr/src/kernels/${KVER}/scripts/sign-file"

    if mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
      ensure_mok_key
      if ! mokutil --test-key "${MOK_DER}" 2>/dev/null | grep -qi "already enrolled"; then
        echo "=================================================================="
        echo "Secure Boot is enabled and MOK key is not enrolled yet."
        echo "Importing ${MOK_DER} into MOK (you will be asked for a one-time password)."
        echo "Reboot once and select 'Enroll MOK' -> Continue -> Yes, then re-run:"
        echo "  ./upstream/APPLY_TO_COMPUTER.sh kmod"
        echo "=================================================================="
        sudo mokutil --import "${MOK_DER}"
        exit 0
      fi
      "${SIGN_FILE}" sha256 "${MOK_KEY}" "${MOK_DER}" "${KO}"
      echo "Signed ${KO} cleanly with enrolled MOK."
    fi

    if lsmod | grep -q "^zen5_entropy_kmod "; then
      sudo rmmod zen5_entropy_kmod
    fi
    sudo insmod "${KO}"
    cat /proc/zen5_entropy
    ;;

  kernel)
    LINUX_DIR="${HOME}/Projects/linux-upstream"
    if [[ ! -f "${LINUX_DIR}/arch/x86/boot/bzImage" ]]; then
      echo "ERROR: ${LINUX_DIR}/arch/x86/boot/bzImage not found."
      exit 1
    fi
    echo "Installing patched kernel 7.4.0-rc2-zen5hybrid (existing Fedora ${KVER} remains intact in GRUB)..."
    sudo make -C "${LINUX_DIR}" modules_install
    sudo make -C "${LINUX_DIR}" install

    VMLINUZ="/boot/vmlinuz-7.4.0-rc2-zen5hybrid"
    if mokutil --sb-state 2>/dev/null | grep -qi "enabled" && [[ -f "${VMLINUZ}" ]]; then
      if command -v sbsign >/dev/null 2>&1; then
        ensure_mok_key
        if ! mokutil --test-key "${MOK_DER}" 2>/dev/null | grep -qi "already enrolled"; then
          echo "Enrolling MOK for Secure Boot..."
          sudo mokutil --import "${MOK_DER}"
        fi
        PEM="${MOK_DIR}/MOK.pem"
        openssl x509 -inform DER -in "${MOK_DER}" -out "${PEM}"
        sudo sbsign --key "${MOK_KEY}" --cert "${PEM}" --output "${VMLINUZ}" "${VMLINUZ}"
        echo "Signed ${VMLINUZ} for Secure Boot."
      else
        echo "NOTE: Secure Boot is enabled and 'sbsign' is not installed."
        echo "Install sbsigntools ('sudo dnf install -y sbsigntools') and re-sign ${VMLINUZ},"
        echo "or enroll MOK before booting 7.4.0-rc2-zen5hybrid."
      fi
    fi

    if command -v akmods >/dev/null 2>&1; then
      echo "Rebuilding out-of-tree akmods for 7.4.0-rc2-zen5hybrid..."
      sudo akmods --kernels "7.4.0-rc2-zen5hybrid" || true
    fi
    echo "Done! Select '7.4.0-rc2-zen5hybrid' at next boot (Fedora ${KVER} stays as fallback)."
    ;;

  *)
    echo "Usage: ./upstream/APPLY_TO_COMPUTER.sh [kmod|kernel]"
    exit 1
    ;;
esac
