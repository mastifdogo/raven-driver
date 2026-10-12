# raven-driver

A Linux driver for the **Raven Compact** document scanner over Wi-Fi.

Raven never shipped Linux support, and it left the scanner business at the
end of 2023. It also never published the Compact's network protocol. This
driver therefore talks to the scanner through the two open network-scanning
protocols a Wi-Fi scanner of its generation is likely to implement:

| Protocol | What it is | Discovery |
|---|---|---|
| **eSCL** | Apple AirScan / Mopria scanning, HTTP + XML | `_uscan._tcp`, `_uscans._tcp` |
| **TWAIN Local** | The local-network part of TWAIN Direct, JSON over HTTP | `_privet._tcp` with `type=twaindirect` |

The `probe` command tells you which one your unit speaks. If it speaks
neither, see [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md).

> **Status:** both protocol clients are implemented and tested against
> simulated scanners. They have **not yet been tested on real Raven Compact
> hardware.** Please report what `raven-scan probe --json <ip>` prints.

## Install

Python 3.9 or newer is the only requirement. There are no other dependencies.

```sh
git clone https://github.com/mastifdogo/raven-driver.git
cd raven-driver
pip install --user .        # installs the `raven-scan` command
# or run without installing:
python3 -m raven_driver --help
```

## Connect the scanner to Wi-Fi

The Compact must join your network before Linux can see it. Do this once,
using either method:

* **With WPS:** press your router's WPS button, then the scanner's WPS button.
* **With Raven Desktop:** on a Windows or macOS computer, choose the wireless
  connection method in Raven Desktop and follow its prompts.

Press the scanner's Wi-Fi button for two seconds to turn Wi-Fi on. A blue
Wi-Fi light means it is connected. Find its IP address in your router's list
of connected devices.

## Use

```sh
# 1. Find it
raven-scan discover

# 2. See which protocol it speaks
raven-scan probe 192.168.1.40

# 3. Scan. A .pdf output combines all pages into one file.
raven-scan scan 192.168.1.40 -o invoice.pdf
raven-scan scan 192.168.1.40 -o receipts.pdf --duplex --mode gray -r 200
raven-scan scan -o page.jpg          # auto-discovers the scanner
```

Scan options:

| Option | Values | Default |
|---|---|---|
| `--source` | `auto`, `adf`, `flatbed` | `auto` |
| `--mode` | `color`, `gray`, `lineart` | `color` |
| `-r`, `--resolution` | dots per inch; snapped to what the scanner supports | `300` |
| `--duplex` | scan both sides | off |
| `--page-size` | `letter`, `legal`, `a4`, `a5`, `a6`, `b5`, `card` | `letter` |
| `--protocol` | `auto`, `escl`, `twainlocal` | `auto` |
| `--port`, `--tls` | force a port, and HTTPS on it | probed |
| `--insecure` | accept a self-signed TLS certificate | off |

When auto-detection finds the scanner only over HTTPS, the driver accepts the
scanner's self-signed certificate, because LAN scanners have no other kind.

## Use with SANE (simple-scan, Skanlite, XSane, gscan2pdf)

If `probe` finds **eSCL**, every SANE application can use the scanner through
the standard `sane-airscan` backend. Usually it appears automatically once
`sane-airscan` is installed. If it does not, pin it:

```sh
sudo apt install sane-airscan        # Debian/Ubuntu; dnf/pacman elsewhere
raven-scan sane-config 192.168.1.40  # prints the line to add
sudoedit /etc/sane.d/airscan.conf    # paste it under [devices]
scanimage -L
```

If the scanner speaks only **TWAIN Local**, SANE has no backend for it. Use
`raven-scan scan` directly, or call it from a script.

## Troubleshooting

* **`discover` finds nothing.** Multicast is often blocked by guest networks
  and some mesh routers. Use the IP address directly with `probe`.
* **`probe` finds no protocol.** The scanner may use Raven's private protocol.
  Save the output of `raven-scan probe --json <ip>` and follow
  [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md).
* **"conflict (paper jam or empty feeder?)".** Reload the paper and retry.
* **USB.** This driver covers Wi-Fi only. USB scanning is not supported.

## Development

```sh
python3 -m unittest -v
```

The tests run complete scan sessions against simulated eSCL and TWAIN Local
scanners in `tests/fakes.py`.

| Module | Purpose |
|---|---|
| `raven_driver/mdns.py` | dependency-free mDNS / DNS-SD discovery |
| `raven_driver/escl.py` | eSCL client |
| `raven_driver/twainlocal.py` | TWAIN Local client |
| `raven_driver/probe.py` | protocol detection and port report |
| `raven_driver/pdf.py` | JPEG pages to one PDF |
| `raven_driver/cli.py` | the `raven-scan` command |
