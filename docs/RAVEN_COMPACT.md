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
   `usb 0x0638 0x3200` line to `avision.conf` is not enough.
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

The model entry uses the settings most similar Avision duplex sheet-fed
scanners use (`AV_INT_BUTTON | AV_CANCEL_BUTTON`). Others can be tried with,
for example, `RAVEN_AVISION_FLAGS="AV_INT_BUTTON" contrib/build-sane-avision.sh`.
This is untested on the Compact. If scanning fails, capture:

```sh
SANE_DEBUG_AVISION=7 SANE_DEBUG_SANEI_USB=5 raven-scanimage -L 2> avision-debug.txt
```
