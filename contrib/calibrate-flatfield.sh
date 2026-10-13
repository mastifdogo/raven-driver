#!/usr/bin/env bash
# Make the Raven Compact's flat-field profile from scans of a blank sheet.
#
# The Compact reads darker toward the ends of its sensor (and greener light
# falls off most, tinting the edges pink). Its firmware offers no calibration
# data, so the patched avision backend corrects scans with a profile made
# here. Use a clean, plain white sheet that covers the full width.
#
# Usage: contrib/calibrate-flatfield.sh [resolution]   (default 150)

set -eu
RES="${1:-150}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANIMAGE="${RAVEN_SCANIMAGE:-$HOME/.local/bin/raven-scanimage}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

scan() {  # scan MODE FILE
  echo
  read -r -p "Put the blank white sheet in the feeder, then press Enter. "
  RAVEN_FLATFIELD=off "$SCANIMAGE" --mode "$1" --resolution "$RES" --format=pnm > "$2"
}

echo "Scanning the blank sheet four times at $RES dpi: a warm-up scan that is"
echo "thrown away (the first scan after the scanner has been idle reads"
echo "differently), then two in colour and one in gray, which are averaged."
scan Color "$WORK/warmup.pnm"
scan Color "$WORK/color1.pnm"
scan Color "$WORK/color2.pnm"
scan Gray "$WORK/gray.pnm"
python3 "$HERE/make-flatfield.py" --resolution "$RES" \
  "$WORK/color1.pnm" "$WORK/color2.pnm" "$WORK/gray.pnm"

cat <<MSG

The correction now applies to every scan from the patched backend, including
apps such as NAPS2 (after contrib/build-sane-avision.sh --install).
To check it, scan the blank sheet again and measure:
  raven-scanimage --mode Color --resolution $RES --format=pnm > check.pnm
  python3 $HERE/make-flatfield.py --check --resolution $RES check.pnm
To turn it off for one scan: RAVEN_FLATFIELD=off raven-scanimage ...
MSG
