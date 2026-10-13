#!/usr/bin/env bash
# Build SANE's avision backend with the Raven Compact (USB 0638:3200) added.
#
# Stock SANE refuses the Compact: the avision backend only attaches models in
# its built-in list, and the Compact is not in it. This script fetches the
# SANE source matching your installed version, adds one list entry, builds
# only the avision backend, and puts it in ~/.local/lib/raven-sane. Nothing
# in /usr is touched unless you pass --install.
#
# It also writes ~/.local/bin/raven-scanimage, which runs scanimage with only
# this avision backend loaded, so other broken backends cannot interfere.
#
# Usage:
#   contrib/build-sane-avision.sh            # build only
#   contrib/build-sane-avision.sh --udev     # also install the USB access rule
#   contrib/build-sane-avision.sh --install  # rule, plus replace the system
#                                            # avision backend (a backup is
#                                            # kept) so apps such as Document
#                                            # Scanner see the Compact
#
# Environment:
#   RAVEN_AVISION_FLAGS  model flags for the entry
#                        (default "AV_INT_BUTTON | AV_CANCEL_BUTTON")
#   SANE_VERSION         source tag to build (default: your scanimage version)

set -euo pipefail

FLAGS="${RAVEN_AVISION_FLAGS:-AV_INT_BUTTON | AV_CANCEL_BUTTON}"
WORK="${RAVEN_BUILD_DIR:-$HOME/.cache/raven-driver}"
OUT="${RAVEN_LIB_DIR:-$HOME/.local/lib/raven-sane}"
INSTALL=0
UDEV=0
for arg in "$@"; do
  case "$arg" in
    --install) INSTALL=1; UDEV=1 ;;
    --udev) UDEV=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n==> %s\n' "$*"; }

# 1. Which SANE version is installed?
if [[ -z "${SANE_VERSION:-}" ]]; then
  if ! command -v scanimage >/dev/null; then
    echo "scanimage is not installed. Install it first: sudo apt install sane-utils" >&2
    exit 1
  fi
  SANE_VERSION=$(scanimage --version | sed -n 's/.*(sane-backends) \([0-9][0-9.]*[0-9]\).*/\1/p' | head -1)
fi
if [[ -z "$SANE_VERSION" ]]; then
  echo "Could not work out the SANE version; set SANE_VERSION, e.g. SANE_VERSION=1.3.1" >&2
  exit 1
fi
say "Building the avision backend for SANE $SANE_VERSION"

# 2. Build tools (Debian/Ubuntu package names).
need=()
for pkg in build-essential git autoconf automake libtool autoconf-archive autopoint gettext pkg-config libusb-1.0-0-dev python3; do
  dpkg -s "$pkg" >/dev/null 2>&1 || need+=("$pkg")
done
if ((${#need[@]})); then
  say "Installing build tools: ${need[*]}"
  sudo apt-get install -y "${need[@]}"
fi

# 3. Source.
SRC="$WORK/sane-backends-$SANE_VERSION"
mkdir -p "$WORK"
if [[ ! -d "$SRC/.git" ]]; then
  say "Downloading SANE $SANE_VERSION source"
  git clone --quiet --depth 1 --branch "$SANE_VERSION" https://gitlab.com/sane-project/backends.git "$SRC"
fi

# 4. Add the Raven Compact to the avision model list (idempotent).
say "Adding Raven Compact (0638:3200) to the avision model list"
RAVEN_FLAGS="$FLAGS" python3 - "$SRC/backend/avision.c" <<'PY'
import os, re, sys
path = sys.argv[1]
src = open(path, encoding="latin-1").read()
flags = os.environ["RAVEN_FLAGS"]
entry = f'''    /* Raven Compact (Avision OEM), added by raven-driver */
    {{ NULL, NULL,
      0x0638, 0x3200,
      "Raven", "Compact",
      {flags},
      {{ 0, {{0, 0}}, {{{{0, 0}}, {{0, 0}}}} }}
    }},
    /* status="untested" */

'''
marker = "static Avision_HWEntry Avision_Device_List [] =\n  {\n"
if marker not in src:
    sys.exit("avision.c layout not recognised; cannot add the Raven Compact entry")
# Replace any entry from an earlier run, so a new RAVEN_AVISION_FLAGS applies.
src = re.sub(r"    /\* Raven Compact \(Avision OEM\), added by raven-driver \*/\n.*?/\* status=\"untested\" \*/\n\n",
             "", src, flags=re.S)
src = src.replace(marker, marker + entry, 1)
open(path, "w", encoding="latin-1").write(src)
print("entry flags:", flags)
PY

# 5. Configure and build only what the avision backend needs.
cd "$SRC"
if [[ ! -f Makefile ]]; then
  say "Configuring (this takes a minute)"
  { [[ -x configure ]] || ./autogen.sh; } >"$WORK/configure.log" 2>&1
  BACKENDS="avision" ./configure --disable-locking --without-snmp --disable-nls \
    >>"$WORK/configure.log" 2>&1 || { tail -30 "$WORK/configure.log" >&2; exit 1; }
fi
say "Compiling (log: $WORK/build.log)"
jobs=$(nproc 2>/dev/null || echo 2)
if ! { make -j"$jobs" -C lib && make -j"$jobs" -C sanei && make -j"$jobs" -C backend libsane-avision.la; } \
    >"$WORK/build.log" 2>&1; then
  tail -30 "$WORK/build.log" >&2
  echo "Build failed; the full log is $WORK/build.log" >&2
  exit 1
fi

# 6. Put the library where scanimage can find it via LD_LIBRARY_PATH.
mkdir -p "$OUT"
built=$(readlink -f backend/.libs/libsane-avision.so.1)
cp "$built" "$OUT/"
ln -sf "$(basename "$built")" "$OUT/libsane-avision.so.1"
say "Built $OUT/libsane-avision.so.1"

# 7. A config directory that loads only avision, and a wrapper that uses it.
mkdir -p "$OUT/etc"
echo "avision" > "$OUT/etc/dll.conf"
# The model entry makes the backend find the Compact by itself. A
# "usb 0x0638 0x3200" line in avision.conf would make it probe the scanner a
# second way that ignores the entry and logs "not yet in whitelist", so drop it.
if [[ -f /etc/sane.d/avision.conf ]]; then
  grep -viE '^[[:space:]]*usb[[:space:]]+0x0638[[:space:]]+0x3200[[:space:]]*$' \
    /etc/sane.d/avision.conf > "$OUT/etc/avision.conf" || true
else
  : > "$OUT/etc/avision.conf"
fi
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/raven-scanimage" <<WRAP
#!/bin/sh
# scanimage with only the Raven-enabled avision backend (raven-driver).
LD_LIBRARY_PATH="$OUT\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
SANE_CONFIG_DIR="$OUT/etc"
export LD_LIBRARY_PATH SANE_CONFIG_DIR
exec scanimage "\$@"
WRAP
chmod +x "$HOME/.local/bin/raven-scanimage"
say "Wrote $HOME/.local/bin/raven-scanimage"

if ((UDEV)); then
  sudo cp "$HERE/60-raven-compact.rules" /etc/udev/rules.d/60-raven-compact.rules
  sudo udevadm control --reload
  sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=0638
  say "Installed /etc/udev/rules.d/60-raven-compact.rules; unplug and replug the scanner"
fi

if ((INSTALL)); then
  sysdir=""
  for d in /usr/lib/"$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"/sane /usr/lib64/sane /usr/lib/sane; do
    [[ -e "$d/libsane-avision.so.1" ]] && { sysdir=$d; break; }
  done
  if [[ -z "$sysdir" ]]; then
    echo "Could not find the system avision backend to replace." >&2
    exit 1
  fi
  target=$(readlink -f "$sysdir/libsane-avision.so.1")
  if [[ ! -e "$target.orig" ]]; then
    sudo cp -p "$target" "$target.orig"
  fi
  sudo cp "$OUT/$(basename "$built")" "$target"
  say "Installed over $target (original kept as $target.orig)"
  echo "A SANE package update will put the original back; rerun with --install then."
  echo "To undo now: sudo cp -p '$target.orig' '$target'"
fi

cat <<MSG

Next, with the scanner on USB and its Wi-Fi off:
  raven-scanimage -L
  raven-scanimage --format=png > test.png

If it is not listed, collect a debug log:
  SANE_DEBUG_AVISION=7 SANE_DEBUG_SANEI_USB=5 raven-scanimage -L 2> avision-debug.txt
MSG
