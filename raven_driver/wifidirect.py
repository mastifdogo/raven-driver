"""Wi-Fi Direct support.

In Wi-Fi Direct mode the scanner hosts its own Wi-Fi network (usually named
``DIRECT-xx-...``) and acts as that network's router. A Linux computer joins
it like any hotspot, and the scanner is then the computer's default gateway.
Joining uses NetworkManager's ``nmcli``, which most desktop distributions ship.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass

LIKELY_NAMES = re.compile(r"direct|raven", re.IGNORECASE)


@dataclass
class Network:
    ssid: str
    signal: int
    security: str
    in_use: bool = False

    @property
    def likely_scanner(self) -> bool:
        return bool(LIKELY_NAMES.search(self.ssid))


def split_terse(line: str) -> list[str]:
    """Split one line of ``nmcli -t`` output, honouring ``\\:`` escapes."""
    fields, cur, i = [], [], 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    fields.append("".join(cur))
    return fields


def parse_wifi_list(output: str) -> list[Network]:
    """Parse ``nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY dev wifi list``."""
    best: dict[str, Network] = {}
    for line in output.splitlines():
        cols = split_terse(line)
        if len(cols) < 4 or not cols[1]:
            continue
        net = Network(
            ssid=cols[1],
            signal=int(cols[2]) if cols[2].isdigit() else 0,
            security=cols[3],
            in_use=cols[0].strip() == "*",
        )
        old = best.get(net.ssid)
        if old is None or net.signal > old.signal or net.in_use:
            net.in_use = net.in_use or (old.in_use if old else False)
            best[net.ssid] = net
    return sorted(best.values(), key=lambda n: (not n.likely_scanner, -n.signal))


def have_nmcli() -> bool:
    return shutil.which("nmcli") is not None


def list_networks(rescan: bool = True) -> list[Network]:
    cmd = ["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list"]
    if rescan:
        cmd += ["--rescan", "yes"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "nmcli failed")
    return parse_wifi_list(out.stdout)


def connect(ssid: str) -> None:
    """Join ``ssid``. nmcli prompts for the password on the terminal if needed,
    so it never appears in the process list or shell history."""
    out = subprocess.run(["nmcli", "--ask", "dev", "wifi", "connect", ssid], timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"could not join {ssid!r}")


def parse_proc_route(text: str) -> list[str]:
    """Default gateways from /proc/net/route (hex, little-endian addresses)."""
    gateways = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or cols[1] != "00000000":
            continue
        flags = int(cols[3], 16)
        if not flags & 0x2:  # RTF_GATEWAY
            continue
        raw = bytes.fromhex(cols[2])[::-1]
        gw = ".".join(str(b) for b in raw)
        if gw not in gateways:
            gateways.append(gw)
    return gateways


def default_gateways() -> list[str]:
    try:
        with open("/proc/net/route") as f:
            return parse_proc_route(f.read())
    except OSError:
        return []


def wait_for_gateway(timeout: float = 20.0) -> list[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        gws = default_gateways()
        if gws:
            return gws
        time.sleep(1.0)
    return []
