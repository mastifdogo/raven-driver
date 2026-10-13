#!/usr/bin/env bash
# Install the Raven Compact USB driver: a patched SANE avision backend, the
# USB access rule and the raven-scanimage command. Then, if the scanner is
# connected, offer to calibrate brightness and colour fringes.
#
# Usage: ./install.sh [--no-calibrate]
# Remove everything again with ./uninstall.sh

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALIBRATE=1
for arg in "$@"; do
  case "$arg" in
    --no-calibrate) CALIBRATE=0 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }

if ! command -v apt-get >/dev/null; then
  echo "This installer needs a Debian-based system (Debian, Ubuntu, Mint, LMDE)." >&2
  exit 1
fi
if ! command -v scanimage >/dev/null; then
  say "Installing SANE (sane-utils)"
  sudo apt-get install -y sane-utils
fi

say "Building and installing the patched avision backend"
"$HERE/contrib/build-sane-avision.sh" --install

case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo
     echo "Note: ~/.local/bin is not on your PATH, so run raven-scanimage as"
     echo "  ~/.local/bin/raven-scanimage   (or log out and back in; most distros add it then)" ;;
esac

ask() {  # ask QUESTION -> 0 for yes
  local reply
  read -r -p "$1 [y/N] " reply || return 1
  [[ "$reply" == [yY]* ]]
}

if ((CALIBRATE)); then
  if lsusb 2>/dev/null | grep -qi '0638:3200'; then
    echo
    echo "The scanner is connected. Calibration makes scans even in brightness and"
    echo "removes colour fringes. It needs a blank white sheet and a page of text."
    if [[ -f "$HOME/.config/raven-driver/flatfield.txt" ]]; then
      echo "(A brightness profile already exists; calibrating again replaces it.)"
    fi
    if ask "Calibrate brightness now with a blank sheet?"; then
      "$HERE/contrib/calibrate-flatfield.sh"
    fi
    if ask "Calibrate colour fringes now with a page of black text or lines?"; then
      "$HERE/contrib/calibrate-fringe.sh"
    fi
  else
    echo
    echo "The scanner is not connected over USB (switch its Wi-Fi off and plug it in)."
    echo "Calibrate later with:"
    echo "  $HERE/contrib/calibrate-flatfield.sh"
    echo "  $HERE/contrib/calibrate-fringe.sh"
  fi
fi

say "Done"
cat <<MSG
Unplug the scanner and plug it in again, then scan from NAPS2, Document
Scanner or the command line:
  raven-scanimage --mode Color --resolution 300 --format=png > scan.png
After a SANE system update, run ./install.sh --no-calibrate again.
MSG
