"""Avision network box support (the Wi-Fi module inside the Raven Compact).

What a real Raven Compact on Wi-Fi Direct showed (address 10.10.10.254):

* telnet on port 23 greets with "MBox login:", Avision's Network Box name;
* port 5549 sends ``VID&PID&SERIAL`` on connect, e.g.
  ``0638&3200&B103843122290367``; USB vendor 0x0638 is Avision;
* port 5551 sends ``SUCCESS\\0`` on connect;
* ports 80 and 8000 are password-protected admin pages; port 2568 serves
  the same admin app without a password, backed by
  ``/cgi-bin/WiFiDriveCtrl.cgi?TrendTecWiFi&cmd_...``.

The box most likely tunnels the scanner's USB connection to Avision's
"Virtual Scanner Link" software. If the tunnel passes the scanner's USB
bulk traffic through unchanged, the scanner speaks the Avision SCSI-over-USB
command set that SANE's avision backend implements: a command is a SCSI CDB
padded to 10 bytes, followed by data, then one status byte.

``inquiry_experiment`` tests that idea with one read-only INQUIRY command.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

INFO_PORT = 5549
CHANNEL_PORT = 5551
AVISION_VENDOR = 0x0638

SCSI_INQUIRY = 0x12
INQUIRY_LEN = 0x60


@dataclass
class BoxInfo:
    vendor: int
    product: int
    serial: str
    raw: str

    @property
    def is_avision(self) -> bool:
        return self.vendor == AVISION_VENDOR

    def describe(self) -> str:
        maker = "Avision" if self.is_avision else "unknown maker"
        return f"USB scanner {self.vendor:04x}:{self.product:04x} ({maker}), serial {self.serial}"


def parse_info(text: str) -> BoxInfo | None:
    """Parse the port 5549 greeting, e.g. ``0638&3200&B103843122290367``."""
    m = re.match(r"\s*([0-9A-Fa-f]{4})&([0-9A-Fa-f]{4})&([^&\x00\s.]*)", text)
    if not m:
        return None
    return BoxInfo(int(m.group(1), 16), int(m.group(2), 16), m.group(3), text.strip("\x00 .\r\n"))


def _recv(sock: socket.socket, seconds: float, limit: int = 65536) -> bytes:
    sock.settimeout(seconds)
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
            sock.settimeout(0.7)
    except OSError:
        pass
    return data


def read_info(host: str, port: int = INFO_PORT, timeout: float = 3.0) -> BoxInfo | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            data = _recv(s, timeout, 512)
    except OSError:
        return None
    return parse_info(data.decode("latin-1"))


def inquiry_cdb(length: int = INQUIRY_LEN) -> bytes:
    """SCSI INQUIRY, padded to the 10 bytes Avision's USB protocol uses."""
    return bytes([SCSI_INQUIRY, 0, 0, 0, length, 0]) + bytes(4)


@dataclass
class InquiryResult:
    greeting: bytes = b""
    reply: bytes = b""
    error: str = ""
    strings: list[str] = field(default_factory=list)

    @property
    def looks_like_scanner(self) -> bool:
        """True if the reply carries SCSI INQUIRY vendor/product text."""
        return any(len(s) >= 4 for s in self.strings) and len(self.reply) >= 36


def parse_inquiry(data: bytes) -> list[str]:
    """Printable runs of 4+ characters, e.g. the vendor and model strings."""
    return [m.decode("latin-1").strip() for m in re.findall(rb"[\x20-\x7e]{4,}", data) if m.strip()]


def inquiry_experiment(host: str, port: int = CHANNEL_PORT, timeout: float = 5.0) -> InquiryResult:
    """Send one INQUIRY to the box's channel port and capture the reply."""
    result = InquiryResult()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            result.greeting = _recv(s, 2.0, 256)
            s.sendall(inquiry_cdb())
            result.reply = _recv(s, timeout)
    except OSError as exc:
        result.error = str(exc)
    result.strings = parse_inquiry(result.reply)
    return result


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(lines)
