# If the scanner speaks neither eSCL nor TWAIN Local

Raven's own Windows and macOS software, Raven Desktop, reaches the Compact
over Wi-Fi with an undocumented protocol. If `raven-scan probe` finds no
supported protocol, that private protocol is the only way in. Adding support
needs a recording of Raven Desktop talking to the scanner. You can make that
recording without any special hardware.

## 0. Map the scanner's web interface

If the scanner answers on port 80, start here. This is read-only: it only
reads pages, and it skips any link that looks like it would change the
scanner, such as reboot or reset.

```sh
raven-scan explore 192.168.1.1     # or: python3 -m raven_driver explore 192.168.1.1
```

It prints a short summary and saves every page and script it read to a
`raven-explore-<address>` folder. Often the scanner's own web app names the
API it uses to scan, and the summary is enough to add support.

## 1. Save the probe report

```sh
raven-scan probe --json 192.168.1.40 > probe.json
```

It lists the scanner's open TCP ports and what each HTTP port answers.

## 2. Record Raven Desktop scanning

### For the Raven Compact over Wi-Fi Direct

The Compact's network box is at `10.10.10.254`, and the scanning traffic is
on TCP ports 5549 and 5551. On a Windows or macOS computer:

1. Install Raven Desktop and [Wireshark](https://www.wireshark.org/).
2. Join the scanner's Wi-Fi network, for example `Raven-CBC3`.
3. In Wireshark, capture on the Wi-Fi interface with the capture filter
   `host 10.10.10.254`.
4. In Raven Desktop, connect to the scanner wirelessly. Then scan:
   * one page, color, 300 dpi, one side,
   * the same page again in grayscale at 200 dpi.
5. Stop the capture and save it as a `.pcapng` file.

The capture holds no passwords, because the computer had already joined the
scanner's network before recording started.

### General steps

Use a Windows or macOS computer with Raven Desktop installed. The scanner
must already be on Wi-Fi.

1. Install [Wireshark](https://www.wireshark.org/).
2. Start a capture on the computer's Wi-Fi interface with this capture
   filter, using the scanner's address:

   ```
   host 192.168.1.40
   ```

3. In Raven Desktop, add the scanner over Wi-Fi.
4. Make three scans, one at a time, and note the settings for each:
   * one page, color, 300 dpi, one side
   * one page, grayscale, 200 dpi, both sides
   * three pages from the feeder, color, 300 dpi
5. Stop the capture and save it as a `.pcapng` file.

Also capture the moment Raven Desktop *finds* the scanner, since that shows
the discovery method. A capture filter of `udp port 5353 or udp port 1900 or
udp port 3702 or host 192.168.1.40` covers mDNS, SSDP and WS-Discovery.

## 3. What to look for

* **HTTP on port 80 or 8080.** Use *Follow TCP stream*. Paths and JSON or XML
  bodies make a new client easy to write.
* **TLS on port 443.** The payload is encrypted. Note the server name and
  certificate subject. Then check whether the scanner also answers plain HTTP.
* **A custom TCP port.** Look for a fixed header, a length field, and the
  image data, which usually starts with `FF D8` for JPEG.

## 4. Share it

Open an issue on this repository and attach `probe.json` and the capture.
Captures can contain your network password if they include the Wi-Fi setup
step, so record only after the scanner has already joined the network.

A new protocol becomes a module next to `escl.py` and `twainlocal.py`, plus a
`try_*` function in `probe.py`.
