# What the Raven Compact is on the network

Findings from a real Raven Compact in Wi-Fi Direct mode. The scanner's
network is `Raven-CBC3`. It gives the computer an address in
`10.10.10.0/24` and reports `0.0.0.0` as its router.

## Address and ports

The scanner itself is at `10.10.10.254`.

| Port | What answers |
|---|---|
| 23 | telnet, prompt `MBox login:` |
| 80 | lighttpd 1.4.20; redirects to `/Control/index.htm`, which asks for a password |
| 2568 | Apache 2.2.22; the same `/Control/` admin app, no password |
| 5549 | on connect sends `0638&3200&B103843122290367` |
| 5551 | on connect sends `SUCCESS` followed by a zero byte |
| 8000 | GoAhead-Webs; every path asks for a password |

## What that means

* **Avision hardware.** `0638` is Avision's USB vendor ID, so port 5549 is
  announcing a USB scanner `0638:3200` and its serial number. The Raven
  Compact appears to be an Avision-built scanner.
* **Avision Network Box.** The `MBox` prompt matches Avision's Network Box
  (MB01/MB02), which puts a USB scanner on the network for Avision's
  "Virtual Scanner Link" software. Ports 5549 and 5551 are most likely that
  USB-over-network service.
* **Admin app.** The admin app on port 2568 drives the Wi-Fi module through
  `/cgi-bin/WiFiDriveCtrl.cgi?TrendTecWiFi&cmd_<name>`. It covers settings
  such as language and Wi-Fi, not scanning.
* **SANE.** SANE's `avision` backend speaks the Avision USB command set but
  does not list product `3200`. It also expects a local USB device, not a
  network one.

## Result: the box wraps commands

A SCSI INQUIRY sent to port 5551, padded to 10 bytes as SANE's avision
backend sends it over USB, got no reply at all. Only the `SUCCESS` greeting
came back. The box does not pass raw scanner commands through; it expects
its own framing around them. Supporting Wi-Fi therefore needs a recording of
the official software scanning (see REVERSE_ENGINEERING.md). The commands
inside that framing are probably Avision's USB command set, so the recording
mainly has to reveal the wrapper.

## USB with SANE

With its Wi-Fi switched off, the Compact appears on USB as:

```
ID 0638:3200 Avision, Inc. Compact_WiFi
Manufacturer: Raven   Product: Compact_WiFi   SerialNumber: B103843122290367
```

Three things stop stock SANE from using it:

1. **Not on the model list.** SANE's avision backend only attaches models in
   its built-in list and rejects others as "not yet in whitelist". Adding a
   `usb 0x0638 0x3200` line to `avision.conf` does not help.
2. **The printer driver claims it.** The kernel's `usblp` driver binds to the
   Compact, and SANE does not detach kernel drivers.
3. **No user access.** Only scanners that libsane knows get user permissions.

`contrib/build-sane-avision.sh` fixes all three. It rebuilds only the avision
backend from the SANE source matching your installed version, with one model
entry added for `0638:3200`. It writes a `raven-scanimage` command that loads
only that backend, so other broken backends cannot interfere. With `--udev` it
installs `contrib/60-raven-compact.rules`, which releases the scanner from
`usblp` and grants access. With `--install` it also replaces the system avision
backend, keeping a backup, so desktop scanning apps see the scanner.

```sh
contrib/build-sane-avision.sh --udev
# unplug and replug the scanner, Wi-Fi off
raven-scanimage -L
raven-scanimage --format=png > test.png
```

On the real scanner this works: `raven-scanimage -L` reports
`device 'avision:libusb:001:007' is a Raven Compact flatbed scanner`, and the
scanner's INQUIRY identifies it as `Raven` / `Compact_WiFi`. Do not also list
`usb 0x0638 0x3200` in `/etc/sane.d/avision.conf`: that makes the backend probe
the scanner a second way and log "not yet in whitelist" warnings.

### The firmware reboots on TEST UNIT READY

Listing works, but opening the scanner fails with "Invalid argument". The
debug log shows why. INQUIRY succeeds, with its status byte on the bulk
endpoint. SANE then sends TEST UNIT READY (opcode `00`). The scanner accepts
the 10-byte command but never sends a status byte. About 20 seconds later it
reboots: it drops off USB and re-enumerates as a new device. Paper in the
feeder makes no difference. Every later command fails with "No such device".

To get past this, the rebuilt backend has a command filter for bring-up:

* `RAVEN_SKIP_OPS=00` skips the listed commands instead of sending them, and
  reports success. Tokens are opcodes (`00`) or opcode:datatype for READ and
  SEND (`28:64`), separated by commas.
* `RAVEN_TRACE_OPS=1` logs one line per command. `RAVEN_SKIP_OPS` does too.
  Both need `SANE_DEBUG_AVISION=1` or higher to show.

```sh
RAVEN_SKIP_OPS=00 SANE_DEBUG_AVISION=1 raven-scanimage -A 2>&1 | grep -E "raven:|scanimage:|^ +-"
```

With `00` skipped, the scanner rebooted on the next command, READ "detect
accessories" (`28:64`).

`contrib/find-bad-commands.sh` automates the search. It runs
`raven-scanimage`, takes the last command sent before the scanner dropped off
USB, adds it to the skip list, waits for the scanner to come back, and tries
again: first until the option list opens, then until a test scan finishes.
It stops if the scanner reboots on set window (`24`), start scan (`1b`) or
read image data (`28:00`), which a scan cannot do without, or if a failure
comes without a reboot. The final skip list and every round's log are saved.
Options after the folder name go to every run, e.g.
`contrib/find-bad-commands.sh raven-bringup --source "ADF Front"`.

On the real scanner it found only `00` and `28:64`. With `RAVEN_SKIP_OPS=00,28:64`
the option list opens and a scan runs. The first scans came out as bands that
fade from gray to white with no page content, because the paper never moved.
The inquiry reports scanner type 0 (flatbed) plus an ADF, so the backend
offers "Normal" (flatbed glass, which the Compact lacks) and "ADF Front", and
defaults to "Normal". "ADF Front" was not offered either: the backend takes
ADF presence from the "detect accessories" reply, and the skipped command
returns zeros.

The build script therefore patches three things for USB ID `0638:3200` only:

* the model list entry, so the backend accepts the Compact;
* the scanner type, forced to sheet-fed, so the only and default source is
  "ADF Front";
* the command filter, which now skips `00` and `28:64` by default whenever a
  Compact is open. `RAVEN_SKIP_OPS` still overrides the list, and an empty
  value skips nothing.

Each run of the script patches a fresh copy of `avision.c` from git, so
re-running after an update never stacks patches.

### First real scan

With the sheet-fed patch the page feeds and the scan shows the document, but
in gray mode every stroke is dotted and the image repeats in groups of three
rows: rows three apart correlate strongly, neighbouring rows not at all. That
is colour data arriving for a gray request. Without `AV_USE_GRAY_FILTER` the
backend sets "no filter" in SET WINDOW for gray scans, and the Compact then
sends RGB, which the backend splits into three gray rows per scan line.

The model entry now uses `AV_INT_BUTTON | AV_CANCEL_BUTTON | AV_USE_GRAY_FILTER`,
the same as the AV186+, AV188, AV220D2+ and AD345F. Others can be tried with,
for example, `RAVEN_AVISION_FLAGS="AV_INT_BUTTON" contrib/build-sane-avision.sh`.
This is untested on the Compact. If scanning fails, capture:

```sh
SANE_DEBUG_AVISION=7 SANE_DEBUG_SANEI_USB=5 raven-scanimage -L 2> avision-debug.txt
```

### Gray and colour scans

With `AV_USE_GRAY_FILTER`, gray scans of a full letter page are clean, and
colour scans reproduce red and blue pen marks. Colour scans of a gray page
show faint false colour at edges: roughly 0.8% of pixels have saturation over
40, about three times stronger on edges across the feed direction than along
it. Quality scan mode is already on by default. The uploads used to judge
this were lossy WebP, which adds colour at edges itself, so
`contrib/measure-color-fringe.py color.pnm` measures it on the original file:
it reports red and blue edge offsets relative to green, in fractions of a
pixel, for each direction. A consistent offset across the feed direction can
be corrected by shifting those channels.

### Uneven brightness across the page

Paper reads darker toward the edges of the sensor, the right edge most:
across a 150 dpi gray scan the paper level runs 224, 227, 232, 232, 232, 227,
222, 205 from left to right. In colour the green channel falls most, which
tints the edges pink (at 600 dpi the paper's green drops from 253 in the
middle to 210 at the right edge). Brightness does not vary down the page, so
it comes from the sensor, not the paper feed.

The backend skips calibration because the Compact's calibration format says
none is needed. Forcing it with `AV_FORCE_CALIB` does not work: READ
calibration format (`28:60`) succeeds, but READ calibration data (`28:62`)
fails with an I/O error a second later, and the scan aborts. Do not add
`AV_FORCE_CALIB`.

### Flat-field correction

Since the scanner offers no calibration data, the patched backend corrects
shading itself. `contrib/calibrate-flatfield.sh` scans a plain white sheet in
colour and in gray with the correction off, and `contrib/make-flatfield.py`
turns those scans into `~/.config/raven-driver/flatfield.txt`: one line per
position across the page, in inches, with gains for red, green, blue and gray.
Gains keep the brightest part of the sheet where it is and lift the rest to
match, clipped to 0.5-2.0.

While a Compact is open, the backend multiplies each 8-bit sample by its
column's gain in `sane_read`, so every frontend gets corrected images,
including NAPS2 once the backend is installed with `--install`. Positions are
in inches, so one profile serves any resolution and scan window. Line art is
left alone. `RAVEN_FLATFIELD=off` turns the correction off for a scan, and
`RAVEN_FLATFIELD=/path` picks another profile; `/etc/sane.d/raven-compact-flatfield.txt`
is used when the user has none.

Tested without the scanner: the C code against SANE 1.2.1 headers (gains per
channel, reads split mid-line, clipping, offset windows, clamping past the
profile, line art and disabled cases), and end to end on synthetic blank
scans shaped like the real falloff, where a 19% green drop at the right edge
came down to 0.5%.

First calibration on the real scanner: the blank sheet read up to 44% darker
in green at the right edge. A check scan with the profile applied came out
uneven the other way: the left was slightly low and the right over-corrected.
Undoing the gains shows the right half of the second blank scan read 6-7%
brighter than the first, so the falloff is not the same from scan to scan. A
fixed profile can only remove the repeatable part. `make-flatfield.py --check`
now also reports the top, middle and bottom thirds of a scan, to show whether
the shading changes down the sheet, as it would if the paper lifts off the
sensor glass while feeding.

Three uncorrected blank scans made one after another then agreed to within
about half a level in every eighth of the page and in every third down it,
so the shading is repeatable and the paper does not lift. The calibration
scan that failed was the first after the scanner had been idle, and its
colour balance differed (red 239, green 226, blue 247 mid-page, against 239,
240, 243 in the later scans): the scanner was still warming up.
`calibrate-flatfield.sh` now makes a warm-up scan it throws away, then
averages two colour scans and uses one gray scan, and `make-flatfield.py`
averages any number of colour (P6) and gray (P5) scans.
