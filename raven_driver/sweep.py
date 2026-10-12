"""Find scanners on the local subnet by knocking on ports.

Used when mDNS discovery finds nothing, for example on routers that block
multicast or when the scanner does not advertise itself at all.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .probe import port_open

SWEEP_PORTS = (80, 443, 8080, 8443, 34034, 9100, 5357)


@dataclass
class Host:
    address: str
    open_ports: list[int] = field(default_factory=list)
    mac: str = ""
    hint: str = ""


def local_networks() -> list[ipaddress.IPv4Network]:
    """Return the IPv4 networks this machine sits on, narrowed to at most /24."""
    nets: list[ipaddress.IPv4Network] = []
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        for cidr in re.findall(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out):
            iface = ipaddress.IPv4Interface(cidr)
            if iface.ip.is_loopback or iface.ip.is_link_local:
                continue
            nets.append(_narrow(iface))
    except (OSError, subprocess.SubprocessError):
        pass
    if not nets:
        # Ask the kernel which source address it would use to reach the internet.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))
                nets.append(_narrow(ipaddress.IPv4Interface(s.getsockname()[0] + "/24")))
        except OSError:
            pass
    return list(dict.fromkeys(nets))


def _narrow(iface: ipaddress.IPv4Interface) -> ipaddress.IPv4Network:
    if iface.network.prefixlen >= 24:
        return iface.network
    return ipaddress.IPv4Interface(f"{iface.ip}/24").network


def arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                cols = line.split()
                if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00":
                    table[cols[0]] = cols[3]
    except OSError:
        pass
    return table


def sweep(networks: list[ipaddress.IPv4Network], ports=SWEEP_PORTS, timeout: float = 0.5) -> list[Host]:
    own = _own_addresses()
    targets = [(str(ip), p) for net in networks for ip in net.hosts() if str(ip) not in own for p in ports]
    found: dict[str, Host] = {}
    with ThreadPoolExecutor(max_workers=128) as pool:
        for (ip, port), ok in zip(targets, pool.map(lambda t: port_open(t[0], t[1], timeout), targets)):
            if ok:
                found.setdefault(ip, Host(ip)).open_ports.append(port)
    arp = arp_table()
    for host in found.values():
        host.mac = arp.get(host.address, "")
    return sorted(found.values(), key=lambda h: ipaddress.IPv4Address(h.address))


def _own_addresses() -> set[str]:
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))
    except (OSError, subprocess.SubprocessError):
        return set()
