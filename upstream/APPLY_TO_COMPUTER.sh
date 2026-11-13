#!/usr/bin/env bash
# ============================================================================
# APPLY_TO_COMPUTER.sh — Apply Ring-0 Asymmetric Capacity & Patched Kernel
# Supports SecureBoot-enabled Fedora hosts safely.
#
# Usage:
#   ./upstream/APPLY_TO_COMPUTER.sh kmod          # Sign, install, persist & load zen5_entropy_kmod
#   ./upstream/APPLY_TO_COMPUTER.sh remove-kmod   # Unload & remove persistent zen5_entropy_kmod install
#   ./upstream/APPLY_TO_COMPUTER.sh kernel        # Install compiled kernel (keeps Fedora fallback)
#   ./upstream/APPLY_TO_COMPUTER.sh remove-kernel # Remove custom kernel from /boot and /lib/modules
# ============================================================================
set -euo pipefail

MODE="${1:-kmod}"
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KVER="$(uname -r)"
MOK_DIR="${HOME}/.config/zen5-scheduler/mok"
MOK_KEY="${MOK_DIR}/MOK.priv"
MOK_DER="${MOK_DIR}/MOK.der"
MOD_DEST="/lib/modules/${KVER}/extra/zen5_entropy_kmod.ko"
UNIT_DEST="/etc/systemd/system/zen5-entropy-kmod.service"

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
    if [[ ! -d "/lib/modules/${KVER}/build" ]]; then
      echo "ERROR: Kernel build headers /lib/modules/${KVER}/build missing."
      echo "       Install them on Fedora with: sudo dnf install -y kernel-devel-${KVER}"
      exit 1
    fi

    make -C "${PROJ_DIR}" kmod
    KO="${PROJ_DIR}/bin/zen5_entropy_kmod.ko"
    SIGN_FILE="/usr/src/kernels/${KVER}/scripts/sign-file"

    if mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
      if [[ ! -x "${SIGN_FILE}" ]]; then
        echo "ERROR: ${SIGN_FILE} not found (install kernel-devel-${KVER})."
        exit 1
      fi
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

    sudo install -D -m 0644 "${KO}" "${MOD_DEST}"
    sudo depmod -a "${KVER}"

    UNIT_TMP="$(mktemp)"
    cat > "${UNIT_TMP}" <<'EOF'
[Unit]
Description=AMD Ryzen AI 7 350 Ring-0 Entropy Capacity & ITMT Module
ConditionPathExists=/lib/modules/%v/extra/zen5_entropy_kmod.ko
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/modprobe zen5_entropy_kmod
ExecStop=/usr/bin/modprobe -r zen5_entropy_kmod

[Install]
WantedBy=multi-user.target
EOF
    sudo install -m 0644 "${UNIT_TMP}" "${UNIT_DEST}"
    rm -f "${UNIT_TMP}"
    if command -v restorecon >/dev/null 2>&1; then
      sudo restorecon -F "${MOD_DEST}" "${UNIT_DEST}" >/dev/null 2>&1 || true
    fi

    sudo systemctl stop zen5-entropy-kmod.service 2>/dev/null || true
    if lsmod | grep -q "^zen5_entropy_kmod "; then
      sudo rmmod zen5_entropy_kmod
    fi
    sudo systemctl daemon-reload
    sudo systemctl enable zen5-entropy-kmod.service
    sudo systemctl restart zen5-entropy-kmod.service

    echo ""
    cat /proc/zen5_entropy
    echo -n "Live sysfs cpu_capacity [0..15]: "
    for c in /sys/devices/system/cpu/cpu{0..15}/cpu_capacity; do
      tr '\n' ' ' < "${c}"
    done
    echo ""
    echo ""
    if systemctl --user status zen5-arbiter.service >/dev/null 2>&1 || [[ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus" ]]; then
      systemctl --user restart zen5-arbiter.service 2>/dev/null || true
    fi
    if [[ -x "${PROJ_DIR}/bin/zen5" ]]; then
      "${PROJ_DIR}/bin/zen5" verify-install
    fi
    ;;

  remove-kmod)
    echo "Removing zen5_entropy_kmod persistence and unloading module..."
    sudo systemctl disable --now zen5-entropy-kmod.service 2>/dev/null || true
    if lsmod | grep -q "^zen5_entropy_kmod "; then
      sudo rmmod zen5_entropy_kmod
    fi
    sudo rm -f "${UNIT_DEST}" "/lib/modules/${KVER}/extra/zen5_entropy_kmod.ko"
    sudo depmod -a "${KVER}"
    sudo systemctl daemon-reload
    echo "Removed persistent kmod install and restored default cpu capacities."
    ;;

  kernel)
    LINUX_DIR="${HOME}/Projects/linux-upstream"
    if [[ ! -f "${LINUX_DIR}/arch/x86/boot/bzImage" ]]; then
      echo "ERROR: ${LINUX_DIR}/arch/x86/boot/bzImage not found."
      exit 1
    fi
    KREL="$(make -s -C "${LINUX_DIR}" kernelrelease)"
    echo "Installing patched kernel ${KREL} (existing Fedora ${KVER} remains intact in GRUB)..."
    sudo make -C "${LINUX_DIR}" modules_install
    sudo make -C "${LINUX_DIR}" install

    VMLINUZ="/boot/vmlinuz-${KREL}"
    if mokutil --sb-state 2>/dev/null | grep -qi "enabled" && sudo test -f "${VMLINUZ}"; then
      ensure_mok_key
      if ! mokutil --test-key "${MOK_DER}" 2>/dev/null | grep -qi "already enrolled"; then
        echo "Enrolling MOK for Secure Boot..."
        sudo mokutil --import "${MOK_DER}"
      fi
      PEM="${MOK_DIR}/MOK.pem"
      openssl x509 -inform DER -in "${MOK_DER}" -out "${PEM}"
      if [[ -x /usr/lib/systemd/systemd-sbsign ]]; then
        sudo /usr/lib/systemd/systemd-sbsign sign \
          --certificate="${PEM}" --private-key="${MOK_KEY}" \
          --output="${VMLINUZ}" "${VMLINUZ}"
        echo "Signed ${VMLINUZ} with systemd-sbsign for Secure Boot."
      elif command -v sbsign >/dev/null 2>&1; then
        sudo sbsign --key "${MOK_KEY}" --cert "${PEM}" --output "${VMLINUZ}" "${VMLINUZ}"
        echo "Signed ${VMLINUZ} with sbsign for Secure Boot."
      else
        echo "WARNING: Secure Boot is enabled and neither systemd-sbsign nor sbsign was found."
      fi
    fi

    if command -v akmods >/dev/null 2>&1; then
      echo "Rebuilding out-of-tree akmods for ${KREL}..."
      echo "NOTE: akmod-nvidia 620.70.06 fails on 7.4-rc2 (uvm_hmm.c VM_SPECIAL removal); use './upstream/APPLY_TO_COMPUTER.sh kmod' on ${KVER} if you need Nvidia."
      sudo akmods --kernels "${KREL}" || true
    fi
    echo "Done! Select '${KREL}' at next boot (Fedora ${KVER} stays as fallback)."
    ;;

  remove-kernel)
    LINUX_DIR="${HOME}/Projects/linux-upstream"
    KREL="${2:-}"
    if [[ -z "${KREL}" && -f "${LINUX_DIR}/include/config/kernel.release" ]]; then
      KREL="$(cat "${LINUX_DIR}/include/config/kernel.release")"
    fi
    if [[ -z "${KREL}" ]]; then
      echo "Usage: ./upstream/APPLY_TO_COMPUTER.sh remove-kernel <kernelrelease>"
      exit 1
    fi
    echo "Removing custom kernel ${KREL} from /boot and /lib/modules..."
    sudo kernel-install remove "${KREL}" || true
    sudo rm -rf "/lib/modules/${KREL}" "/boot/vmlinuz-${KREL}" "/boot/initramfs-${KREL}.img"
    echo "Removed ${KREL}."
    ;;

  *)
    echo "Usage: ./upstream/APPLY_TO_COMPUTER.sh [kmod|remove-kmod|kernel|remove-kernel]"
    exit 1
    ;;
esac
