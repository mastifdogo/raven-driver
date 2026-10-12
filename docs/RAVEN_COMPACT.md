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

## Open question

Does port 5551 pass the scanner's USB traffic through unchanged? Test it:

```sh
raven-scan avision-inquiry 10.10.10.254
```

This sends one read-only SCSI INQUIRY. If the reply contains the scanner's
vendor and model text, the Avision protocol can be driven over the network
directly. If not, the box wraps commands in its own format, and a recording
of Raven Desktop or Avision software scanning is needed (see
REVERSE_ENGINEERING.md).
