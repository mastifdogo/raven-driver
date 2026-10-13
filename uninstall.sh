#!/usr/bin/env bash
# Remove the Raven Compact USB driver: restore SANE's original avision
# backend, remove the USB access rule, and delete the rebuilt backend, the
# raven-scanimage command and the build cache.
#
# Usage: ./uninstall.sh [--keep-profiles]
#   --keep-profiles  keep ~/.config/raven-driver (brightness and fringe
#                    calibration), e.g. before reinstalling.

set -euo pipefail
KEEP_PROFILES=0
for arg in "$@"; do
  case "$arg" in
    --keep-profiles) KEEP_PROFILES=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
if [[ -z "${HOME:-}" || "$HOME" == "/" ]]; then
  echo "HOME is not set sensibly; refusing to delete files under it." >&2
  exit 1
fi

say() { printf '==> %s\n' "$*"; }

# 1. SANE's avision backend: put the original back.
target=""
for d in /usr/lib/"$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"/sane \
         /usr/lib64/sane /usr/lib/sane; do
  if [[ -e "$d/libsane-avision.so.1" ]]; then
    target=$(readlink -f "$d/libsane-avision.so.1")
    break
  fi
done
if [[ -n "$target" && -e "$target.orig" ]]; then
  sudo mv -f "$target.orig" "$target"
  say "Restored the original avision backend ($target)"
elif [[ -n "$target" ]] && command -v dpkg >/dev/null; then
  pkg=$(dpkg -S "$target" 2>/dev/null | cut -d: -f1 | head -1 || true)
  if [[ -n "$pkg" ]] && grep -qa "raven: " "$target" 2>/dev/null; then
    sudo apt-get install -y --reinstall "$pkg"
    say "Reinstalled $pkg to restore the original avision backend"
  else
    say "The system avision backend is not the patched one; left as is"
  fi
else
  say "No system avision backend found; nothing to restore"
fi

# 2. USB access rule.
if [[ -e /etc/udev/rules.d/60-raven-compact.rules ]]; then
  sudo rm -f /etc/udev/rules.d/60-raven-compact.rules
  sudo udevadm control --reload || echo "warning: could not reload udev rules; they update at the next reboot" >&2
  say "Removed the USB access rule"
fi

# 3. A leftover line from early setup instructions.
if [[ -f /etc/sane.d/avision.conf ]] && grep -qE '^usb 0x0638 0x3200$' /etc/sane.d/avision.conf; then
  sudo sed -i '/^usb 0x0638 0x3200$/d' /etc/sane.d/avision.conf
  say "Removed the Raven line from /etc/sane.d/avision.conf"
fi

# 4. Per-user files.
rm -rf "$HOME/.local/lib/raven-sane" "$HOME/.cache/raven-driver"
rm -f "$HOME/.local/bin/raven-scanimage"
say "Removed the rebuilt backend, raven-scanimage and the build cache"
if ((KEEP_PROFILES)); then
  say "Kept the calibration profiles in ~/.config/raven-driver"
else
  rm -rf "$HOME/.config/raven-driver"
  say "Removed the calibration profiles"
fi

cat <<MSG

Done. Unplug the scanner and plug it in again. Not removed:
  - the build tools apt installed (build-essential, autoconf, libusb-1.0-0-dev, ...)
  - a saved Wi-Fi Direct connection: nmcli connection delete Raven-CBC3
  - this project folder
MSG
