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

## Try USB with SANE

The box reports the scanner inside it as Avision USB device `0638:3200`. If
the Compact's USB port shows the same device, SANE's avision backend may
drive it once it is told the ID. This is untested, and SANE does not list the
model. Over a USB cable:

```sh
lsusb | grep -i 0638                     # expect: ID 0638:3200
sudo apt install sane-utils              # Debian/Ubuntu; provides scanimage
echo "usb 0x0638 0x3200" | sudo tee -a /etc/sane.d/avision.conf
scanimage -L                             # should list an avision: device
scanimage --format=png > test.png        # one test scan
```

If `scanimage -L` lists the scanner but scanning fails, run it again with
`SANE_DEBUG_AVISION=7 scanimage -L 2> avision-debug.txt` and keep the file.
