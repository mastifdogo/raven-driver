"""Wi-Fi Direct support.

In Wi-Fi Direct mode the scanner hosts its own Wi-Fi network (usually named
``DIRECT-xx-...``) and acts as that network's router. A Linux computer joins
it like any hotspot, and the scanner is then the computer's default gateway.
Joining uses NetworkManager's ``nmcli``, which most desktop distributions ship.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field

LIKELY_NAMES = re.compile(r"direct|raven", re.IGNORECASE)  # e.g. DIRECT-xx-..., Raven-CB3


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


def parse_devices(output: str) -> list[tuple[str, str]]:
    """(device, state) for each Wi-Fi device in ``nmcli -t -f DEVICE,TYPE,STATE dev``."""
    devices = []
    for line in output.splitlines():
        cols = split_terse(line)
        if len(cols) >= 3 and cols[1] == "wifi":
            devices.append((cols[0], cols[2]))
    return devices


def wifi_devices() -> list[tuple[str, str]]:
    out = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"], capture_output=True, text=True, timeout=15)
    return parse_devices(out.stdout)


def match_ssid(wanted: str, networks: list[Network]) -> tuple[Network | None, list[str]]:
    """Find ``wanted`` among visible networks, forgiving case and a partial
    name. Returns (match, suggestions); match is None unless it is unambiguous."""
    for n in networks:
        if n.ssid == wanted:
            return n, []
    low = wanted.strip().lower()
    same_case = [n for n in networks if n.ssid.strip().lower() == low]
    if len(same_case) == 1:
        return same_case[0], []
    partial = [n for n in networks if low and low in n.ssid.lower()]
    if len(partial) == 1:
        return partial[0], []
    names = [n.ssid for n in networks]
    close = difflib.get_close_matches(wanted, names, n=3, cutoff=0.5)
    suggestions = list(dict.fromkeys([n.ssid for n in partial] + close))
    return None, suggestions


def connect(ssid: str, hidden: bool = False) -> None:
    """Join ``ssid``. nmcli prompts for the password on the terminal if needed,
    so it never appears in the process list or shell history."""
    cmd = ["nmcli", "--ask", "dev", "wifi", "connect", ssid]
    if hidden:
        cmd += ["hidden", "yes"]
    out = subprocess.run(cmd, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"could not join {ssid!r}")


def parse_proc_route(text: str, iface: str | None = None, default_only: bool = True) -> list[str]:
    """Gateways from /proc/net/route (hex, little-endian addresses).

    With ``iface`` only that interface's routes count. ``default_only=False``
    also returns gateways of non-default routes."""
    gateways = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or (default_only and cols[1] != "00000000"):
            continue
        if iface and cols[0] != iface:
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


@dataclass
class LinkInfo:
    """What the computer knows about its link to the scanner's network."""

    device: str = ""
    address: str = ""  # e.g. "192.168.1.23/24"
    gateway: str = ""
    dhcp_server: str = ""
    route_gateways: list[str] = field(default_factory=list)

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        if not self.address:
            return None
        return ipaddress.IPv4Interface(self.address).network

    @property
    def link_local(self) -> bool:
        return self.address.startswith("169.254.")

    def candidates(self) -> list[str]:
        """Addresses where the scanner most likely is, best first."""
        cands = [self.gateway, *self.route_gateways, self.dhcp_server]
        net = self.network
        if net is not None and not self.link_local and net.num_addresses > 2:
            first = str(next(net.hosts()))
            cands.append(first)
        own = self.address.split("/")[0]
        return [c for c in dict.fromkeys(cands) if c and c != own and usable_peer(c, net)]


def usable_peer(addr: str, net: ipaddress.IPv4Network | None = None) -> bool:
    """True for an address another device could really have.

    Wi-Fi Direct DHCP servers sometimes hand out 0.0.0.0 as the router, and
    connecting to 0.0.0.0 on Linux reaches this computer itself."""
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip == ipaddress.IPv4Address("255.255.255.255"):
        return False
    if net is not None and ip not in net:
        return False
    if net is not None and ip in (net.network_address, net.broadcast_address) and net.prefixlen < 31:
        return False
    return True


def parse_device_show(output: str) -> dict[str, str]:
    """Parse ``nmcli -t -f IP4.ADDRESS,IP4.GATEWAY,DHCP4.OPTION device show DEV``."""
    info: dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.partition(":")
        key = key.split("[")[0].strip()
        value = value.strip()
        if key == "IP4.ADDRESS" and value and "address" not in info:
            info["address"] = value
        elif key == "IP4.GATEWAY" and value and value != "--":
            info["gateway"] = value
        elif key == "DHCP4.OPTION":
            m = re.match(r"(\w+)\s*=\s*(\S+)", value)
            if m and m.group(1) == "dhcp_server_identifier":
                info["dhcp_server"] = m.group(2)
            elif m and m.group(1) == "routers" and "gateway" not in info:
                info["gateway"] = m.group(2).split()[0]
    return info


def active_wifi_device() -> str:
    for dev, state in wifi_devices():
        if state.startswith("connected"):
            return dev
    return ""


def link_info(device: str | None = None) -> LinkInfo:
    device = device or active_wifi_device()
    info = LinkInfo(device=device)
    if not device:
        return info
    try:
        out = subprocess.run(
            ["nmcli", "-t", "-f", "IP4.ADDRESS,IP4.GATEWAY,DHCP4.OPTION", "device", "show", device],
            capture_output=True, text=True, timeout=15,
        ).stdout
        parsed = parse_device_show(out)
    except (OSError, subprocess.SubprocessError):
        parsed = {}
    info.address = parsed.get("address", "")
    info.gateway = parsed.get("gateway", "")
    info.dhcp_server = parsed.get("dhcp_server", "")
    try:
        with open("/proc/net/route") as f:
            info.route_gateways = parse_proc_route(f.read(), iface=device, default_only=False)
    except OSError:
        pass
    return info


def wait_for_link(timeout: float = 45.0, device: str | None = None) -> LinkInfo:
    """Wait until the Wi-Fi device has a usable IPv4 address."""
    deadline = time.monotonic() + timeout
    info = link_info(device)
    while time.monotonic() < deadline:
        if info.address and not info.link_local:
            return info
        time.sleep(1.5)
        info = link_info(device)
    return info


def parse_ip_addr(output: str) -> list[tuple[str, str]]:
    """(device, address/prefix) pairs from ``ip -4 -o addr show``."""
    return re.findall(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", output, re.MULTILINE)


def overlapping_interfaces(link: LinkInfo, addrs: list[tuple[str, str]] | None = None) -> list[tuple[str, str]]:
    """Other interfaces whose network overlaps the scanner's network.

    If the wired network and the scanner's Wi-Fi Direct network share a range
    such as 192.168.1.0/24, traffic meant for the scanner can go out the wired
    link to the home router instead."""
    net = link.network
    if net is None:
        return []
    if addrs is None:
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        addrs = parse_ip_addr(out)
    clashes = []
    for dev, cidr in addrs:
        if dev == link.device or dev == "lo":
            continue
        if ipaddress.IPv4Interface(cidr).network.overlaps(net):
            clashes.append((dev, cidr))
    return clashes
