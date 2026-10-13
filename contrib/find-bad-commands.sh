#!/usr/bin/env bash
# Find every command that makes the Raven Compact reboot, without help.
#
# The Compact's firmware reboots on some SCSI commands that SANE's avision
# backend sends (TEST UNIT READY, READ "detect accessories", ...). This runs
# raven-scanimage, notes the last command sent before the scanner dropped off
# USB, adds it to RAVEN_SKIP_OPS, waits for the scanner to come back, and
# tries again: first until the option list opens, then until a test scan
# finishes. It stops on a command scanning cannot do without.
#
# Usage: contrib/find-bad-commands.sh [output-folder]
# Put a page in the feeder first. Each reboot takes up to a minute.

set -u
OUT="${1:-raven-bringup}"
SCANIMAGE="${RAVEN_SCANIMAGE:-$HOME/.local/bin/raven-scanimage}"
LSUSB="${LSUSB:-lsusb}"
skip="${RAVEN_SKIP_OPS:-00}"
max_rounds="${MAX_ROUNDS:-15}"
reboot_wait="${REBOOT_WAIT:-60}"
# Set window (24), start scan (1b) and read image data (28:00): skipping
# these means no image.
is_essential() { [[ "${1%%:*}" == 24 || "${1%%:*}" == 1b || "$1" == 28:00 ]]; }
# Mirrors the backend filter: a token matches by opcode or by opcode:datatype.
is_skipped() { [[ ",$skip," == *",$1,"* || ",$skip," == *",${1%%:*},"* ]]; }

mkdir -p "$OUT"
: > "$OUT/summary.txt"
log() { echo "$*" | tee -a "$OUT/summary.txt"; }

if [[ ! -x "$SCANIMAGE" ]]; then
  echo "raven-scanimage not found; run contrib/build-sane-avision.sh first" >&2
  exit 1
fi

device_id() {  # "Bus 001 Device 015" -> "001:015", or empty
  $LSUSB -d 0638:3200 2>/dev/null | sed -n 's/^Bus \([0-9]*\) Device \([0-9]*\):.*/\1:\2/p' | head -1
}

wait_for_scanner() {
  local i
  for ((i = 0; i < reboot_wait; i++)); do
    [[ -n "$(device_id)" ]] && { sleep 3; return 0; }
    sleep 1
  done
  return 1
}

# After a failure: did the scanner reboot (new device number)?
rebooted_since() {
  local before=$1 i now
  for ((i = 0; i < reboot_wait; i++)); do
    now=$(device_id)
    if [[ -n "$now" && "$now" != "$before" ]]; then
      sleep 3
      return 0
    fi
    sleep 1
  done
  return 1
}

stage() {  # stage NAME TIMEOUT ARGS...
  local name=$1 limit=$2 round before rc last
  shift 2
  for ((round = 1; round <= max_rounds; round++)); do
    if ! wait_for_scanner; then
      log "$name: the scanner is not on USB (lsusb shows no 0638:3200). Is its Wi-Fi off?"
      return 2
    fi
    before=$(device_id)
    RAVEN_SKIP_OPS="$skip" SANE_DEBUG_AVISION=1 \
      timeout --kill-after=10 "$limit" "$SCANIMAGE" "$@" \
      >"$OUT/$name.out" 2>"$OUT/$name-$round.log"
    rc=$?
    if ((rc == 0)); then
      log "$name: works with RAVEN_SKIP_OPS=$skip"
      return 0
    fi
    last=$(grep -o 'raven: send [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f] .*' "$OUT/$name-$round.log" | tail -1)
    token=$(awk '{print $3}' <<<"$last")
    log "$name round $round: failed (exit $rc); last command sent: ${last#raven: send }"
    if [[ -z "$token" ]]; then
      log "$name: no command was sent before the failure; see $OUT/$name-$round.log"
      return 1
    fi
    if ! rebooted_since "$before"; then
      log "$name: the scanner did not reboot, so this is a different failure; see $OUT/$name-$round.log"
      return 1
    fi
    if is_essential "$token"; then
      log "$name: the scanner reboots on ${last#raven: send }, which scanning cannot skip"
      return 1
    fi
    if is_skipped "$token"; then
      log "$name: $token is already skipped yet the scanner rebooted; see $OUT/$name-$round.log"
      return 1
    fi
    skip="$skip,$token"
    log "  -> skipping $token from now on"
  done
  log "$name: gave up after $max_rounds rounds"
  return 1
}

log "Starting with RAVEN_SKIP_OPS=$skip"
if stage options 120 -A; then
  grep -E '^ +-' "$OUT/options.out" | head -40 > "$OUT/options.txt"
  log "Options saved to $OUT/options.txt"
  if stage scan 300 --format=png; then
    mv "$OUT/scan.out" "$OUT/test.png"
    log "Test scan saved to $OUT/test.png ($(stat -c %s "$OUT/test.png") bytes)"
  fi
fi
log ""
log "Final RAVEN_SKIP_OPS=$skip"
log "Share $OUT/summary.txt; the per-round logs are next to it."
