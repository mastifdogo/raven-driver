#!/usr/bin/env bash
# Measure the Raven Compact's colour fringe and save the correction.
#
# The Compact reads red, green and blue a fraction of a line apart, so black
# edges across the feed direction get coloured fringes in colour scans. This
# scans one black-and-white page with plenty of text or lines in colour at
# each resolution, with the fringe correction off, measures the offsets and
# saves them to ~/.config/raven-driver/fringe.txt for the patched backend.
#
# Usage: contrib/calibrate-fringe.sh [resolution...]   (default: 150 300 600)

set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANIMAGE="${RAVEN_SCANIMAGE:-$HOME/.local/bin/raven-scanimage}"
RESOLUTIONS=("$@")
((${#RESOLUTIONS[@]})) || RESOLUTIONS=(150 300 600)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Use a black-and-white page with lots of text or lines. It is fed once per"
echo "resolution: ${RESOLUTIONS[*]} dpi. If the scanner has been idle, feed any page"
echo "once first so it is warmed up."
for res in "${RESOLUTIONS[@]}"; do
  echo
  read -r -p "Put the page in the feeder for the $res dpi scan, then press Enter. "
  RAVEN_FRINGE=off "$SCANIMAGE" --mode Color --resolution "$res" --format=pnm > "$WORK/page-$res.pnm"
  python3 "$HERE/measure-color-fringe.py" "$WORK/page-$res.pnm" --save --resolution "$res"
done

cat <<MSG

Colour scans from the patched backend are now corrected, including apps such
as NAPS2 (after contrib/build-sane-avision.sh --install). To turn it off for
one scan: RAVEN_FRINGE=off raven-scanimage ...
MSG
