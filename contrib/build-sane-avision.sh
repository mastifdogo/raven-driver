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
#                        (default "AV_INT_BUTTON | AV_CANCEL_BUTTON | AV_USE_GRAY_FILTER")
#   SANE_VERSION         source tag to build (default: your scanimage version)

set -euo pipefail

FLAGS="${RAVEN_AVISION_FLAGS:-AV_INT_BUTTON | AV_CANCEL_BUTTON | AV_USE_GRAY_FILTER}"
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

# 4. Patch avision.c. Start from the pristine file each time, so a newer
#    version of this script never stacks on an older patch.
git -C "$SRC" checkout --quiet -- backend/avision.c
say "Adding Raven Compact (0638:3200) support to the avision backend"
RAVEN_FLAGS="$FLAGS" RAVEN_FF_SRC="$HERE/sane-patches/raven-flatfield.c" \
  RAVEN_FR_SRC="$HERE/sane-patches/raven-fringe.c" \
  python3 - "$SRC/backend/avision.c" <<'PY'
import os, sys
path = sys.argv[1]
src = open(path, encoding="latin-1").read()
flags = os.environ["RAVEN_FLAGS"]

def insert(anchor, text, after=True):
    global src
    if src.count(anchor) != 1:
        sys.exit("avision.c layout not recognised near: " + anchor.strip()[:60])
    src = src.replace(anchor, anchor + text if after else text + anchor, 1)

# a) Model list entry: without it the backend rejects the Compact.
insert("static Avision_HWEntry Avision_Device_List [] =\n  {\n", f'''    /* Raven Compact (Avision OEM), added by raven-driver */
    {{ NULL, NULL,
      0x0638, 0x3200,
      "Raven", "Compact",
      {flags},
      {{ 0, {{0, 0}}, {{{{0, 0}}, {{0, 0}}}} }}
    }},
    /* status="untested" */

''')

# b) The Compact is sheet-fed but its INQUIRY reports type 0 (flatbed), so
#    the backend would default to a flatbed source it does not have.
insert("  dev->inquiry_new_protocol = BIT (result[39],2);\n", """  /* raven-driver: the Raven Compact is sheet-fed but reports a flatbed */
  if (dev->hw->usb_vendor == 0x0638 && dev->hw->usb_product == 0x3200) {
    dev->scanner_type = AV_SHEETFEED;
    dev->sane.type = "sheetfed scanner";
  }

""", after=False)

# c) Command filter. The Compact's firmware reboots on TEST UNIT READY (00)
#    and READ detect accessories (28:64), so those are skipped by default for
#    it. RAVEN_SKIP_OPS overrides the list (empty = skip nothing); tokens are
#    opcodes ("00") or opcode:datatype ("28:64"). RAVEN_TRACE_OPS, or setting
#    RAVEN_SKIP_OPS, logs one line per command at SANE_DEBUG_AVISION=1.
insert("static SANE_Status avision_cmd (Avision_Connection* av_con,\n",
       "static int raven_quirks = 0; /* raven-driver: set when a Raven Compact is open */\n\n",
       after=False)
insert('  DBG (7, "avision_cmd: %s\\n", strcmd);\n', """  /* raven-driver: RAVEN_SKIP_OPS */
  {
    const char* env = getenv ("RAVEN_SKIP_OPS");
    const char* skip = env ? env : (raven_quirks ? "00,28:64" : NULL);
    const uint8_t* c = (const uint8_t*) cmd;
    char tok[8], tok2[8], list[512];
    int skipped = 0;
    snprintf (tok, sizeof (tok), ",%02x,", c[0]);
    snprintf (tok2, sizeof (tok2), ",%02x:%02x,", c[0], cmd_size > 2 ? c[2] : 0);
    if (skip) {
      snprintf (list, sizeof (list), ",%s,", skip);
      skipped = strstr (list, tok) || strstr (list, tok2);
    }
    if (env || getenv ("RAVEN_TRACE_OPS"))
      DBG (1, "raven: %s %02x:%02x %s\\n", skipped ? "SKIP" : "send",
           c[0], cmd_size > 2 ? c[2] : 0, strcmd);
    if (skipped) {
      if (dst && dst_size && *dst_size)
        memset (dst, 0, *dst_size);
      return SANE_STATUS_GOOD;
    }
  }
""")
insert("  if (!dev)\n    return SANE_STATUS_INVAL;\n", """
  /* raven-driver: turn on the Raven Compact command filter */
  raven_quirks = (dev->hw->usb_vendor == 0x0638 && dev->hw->usb_product == 0x3200);
""")

# d) Flat-field correction: the Compact reads darker toward the sensor ends
#    and offers no calibration data, so scale each sample by a per-position
#    gain from a blank-sheet profile (see contrib/calibrate-flatfield.sh).
# e) Colour fringe correction: red and blue are read a fraction of a line
#    away from green; shift them back (see contrib/calibrate-fringe.sh).
fragment = open(os.environ["RAVEN_FF_SRC"], encoding="latin-1").read()
fragment += "\n" + open(os.environ["RAVEN_FR_SRC"], encoding="latin-1").read()
insert("SANE_Status\nsane_start (SANE_Handle handle)\n", fragment + "\n", after=False)
insert('  DBG (1, "sane_start:\\n");\n', "  raven_ff_reset ();  /* raven-driver */\n  raven_fr_reset ();\n")
insert("  *len = (SANE_Int) nread;\n", """  /* raven-driver: fringe and flat-field correction for the Raven Compact */
  if (raven_quirks && !raven_ff_ready) {
    SANE_Parameters rp;
    raven_ff_ready = 1;
    raven_fr_ready = 1;
    if (sane_get_parameters (s, &rp) == SANE_STATUS_GOOD) {
      raven_fr_build (&rp, (double) s->val[OPT_RESOLUTION].w);
      raven_ff_build (&rp, (double) s->val[OPT_RESOLUTION].w,
                      SANE_UNFIX (s->val[OPT_TL_X].w) / 25.4);
    }
  }
  if (raven_quirks) {
    raven_fr_apply (buf, (long) nread);   /* fringe first, on raw lines */
    raven_ff_apply (buf, (long) nread);
  }
""", after=False)

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
