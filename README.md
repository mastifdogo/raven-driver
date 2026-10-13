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

> **Status:** a real Raven Compact speaks neither eSCL nor TWAIN Local. It is
> an Avision scanner behind an Avision network box that wraps commands in an
> undocumented format, so **Wi-Fi scanning does not work yet.** See
> [docs/RAVEN_COMPACT.md](docs/RAVEN_COMPACT.md) for what is known and how to
> help. The eSCL and TWAIN Local clients remain for other scanners.

## Install

Python 3.9 or newer is the only requirement. There are no other dependencies.

```sh
git clone https://github.com/mastifdogo/raven-driver.git
cd raven-driver
pip install --user .        # installs the `raven-scan` command
# or run without installing:
python3 -m raven_driver --help
```

## Connect over Wi-Fi Direct

If the scanner will not join your home network, connect to it directly. In
Wi-Fi Direct mode the scanner hosts its own Wi-Fi network, and your computer
joins that network instead of your home one. While joined, your computer has
no internet.

```sh
raven-scan direct                          # list networks; scanner ones first
raven-scan direct --ssid 'DIRECT-xx-Raven'   # join it and find the scanner
raven-scan scan -o scan.pdf                # scans from the scanner it found
```

`direct` uses NetworkManager's `nmcli` and asks for the network password on
the terminal. The password is on the scanner's label or in its manual. You can
also join the network from your desktop's Wi-Fi menu and then run
`raven-scan direct --probe-only`.

If `direct` says the network is not visible, it lists the networks it can
see. A partial name such as `Raven-CB3` is enough when only one network
matches. For a hidden network, add `--hidden`. The computer needs a Wi-Fi
adapter: many desktop PCs have none, and `nmcli device` shows whether yours does.

On Wi-Fi Direct the scanner is your computer's router, so `scan` with no
address tries the router address automatically.

## Connect the scanner to your Wi-Fi network

The Compact must join your network before Linux can see it there. Do this
once, using either method:

* **With WPS:** press your router's WPS button, then the scanner's WPS button.
* **With Raven Desktop:** on a Windows or macOS computer, choose the wireless
  connection method in Raven Desktop and follow its prompts.

Press the scanner's Wi-Fi button for two seconds to turn Wi-Fi on. A blue
Wi-Fi light means it is connected. Find its IP address in your router's list
of connected devices.

## Use

```sh
# 1. Find it. If the scanner does not advertise itself, this sweeps your
#    network and lists every device with web or scan ports open.
raven-scan discover

# 2. See which protocol it speaks. Use the address step 1 found;
#    192.168.1.40 is only an example.
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

* **`probe` says "Nothing answered".** The address is wrong, or the scanner
  is off or not on Wi-Fi. Run `raven-scan discover`, or look up the scanner
  in your router's list of connected devices.
* **`discover` finds nothing.** Multicast is often blocked by guest networks
  and some mesh routers, and the sweep only covers your own /24 network. Pass
  another one with `--subnet 10.0.5.0/24`, or use the router's device list.
* **`probe` finds no protocol.** The scanner uses Raven's private protocol.
  Run `raven-scan explore <ip>`, which reads the scanner's web interface
  without changing anything, and share its summary. See
  [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md).
* **"conflict (paper jam or empty feeder?)".** Reload the paper and retry.
* **USB.** This driver covers Wi-Fi only. The Raven Compact is an Avision
  scanner inside, so over USB it may work with SANE's own `avision` backend.
  See [docs/RAVEN_COMPACT.md](docs/RAVEN_COMPACT.md).

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
