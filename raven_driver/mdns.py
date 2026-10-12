"""Minimal, dependency-free multicast DNS (mDNS / DNS-SD) browser.

Sends one-shot PTR queries to 224.0.0.251:5353 and collects PTR, SRV, TXT and
A records from any responder. That is enough to find network scanners that
advertise ``_uscan._tcp`` (eSCL), ``_uscans._tcp`` (eSCL over TLS) or
``_privet._tcp`` (TWAIN Local).
"""

from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass, field

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

SCANNER_SERVICE_TYPES = (
    "_uscan._tcp.local",
    "_uscans._tcp.local",
    "_privet._tcp.local",
    "_scanner._tcp.local",
)


@dataclass
class Service:
    """One discovered DNS-SD service instance."""

    instance: str
    service_type: str
    host: str | None = None
    port: int | None = None
    addresses: list[str] = field(default_factory=list)
    txt: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        suffix = "." + self.service_type
        if self.instance.endswith(suffix):
            return self.instance[: -len(suffix)]
        return self.instance

    @property
    def address(self) -> str | None:
        if self.addresses:
            return self.addresses[0]
        return self.host


def build_query(names: list[str], qtype: int = TYPE_PTR) -> bytes:
    """Build a DNS query packet asking for ``qtype`` records of ``names``."""
    header = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b""
    for name in names:
        body += encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + body


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            hops += 1
            if hops > 64:
                raise ValueError("DNS name pointer loop")
            offset = pointer
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), end


def parse_txt(rdata: bytes) -> dict[str, str]:
    txt: dict[str, str] = {}
    i = 0
    while i < len(rdata):
        length = rdata[i]
        entry = rdata[i + 1 : i + 1 + length].decode("utf-8", "replace")
        i += 1 + length
        if not entry:
            continue
        key, _, value = entry.partition("=")
        txt[key.lower()] = value
    return txt


def parse_packet(packet: bytes) -> list[tuple[str, int, object]]:
    """Return every resource record in a DNS packet as (name, type, value)."""
    if len(packet) < 12:
        return []
    _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    for _ in range(qd):
        _, offset = read_name(packet, offset)
        offset += 4
    records: list[tuple[str, int, object]] = []
    for _ in range(an + ns + ar):
        name, offset = read_name(packet, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata_start = offset
        rdata = packet[offset : offset + rdlen]
        offset += rdlen
        value: object
        if rtype == TYPE_PTR:
            value, _ = read_name(packet, rdata_start)
        elif rtype == TYPE_SRV:
            _prio, _weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = read_name(packet, rdata_start + 6)
            value = (target, port)
        elif rtype == TYPE_TXT:
            value = parse_txt(rdata)
        elif rtype == TYPE_A and rdlen == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == TYPE_AAAA and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            continue
        records.append((name.lower(), rtype, value))
    return records


def assemble(records: list[tuple[str, int, object]], service_types=SCANNER_SERVICE_TYPES) -> list[Service]:
    """Turn a pile of DNS records into Service objects."""
    wanted = {t.lower() for t in service_types}
    services: dict[str, Service] = {}
    srv: dict[str, tuple[str, int]] = {}
    txt: dict[str, dict[str, str]] = {}
    addrs: dict[str, list[str]] = {}
    for name, rtype, value in records:
        if rtype == TYPE_PTR and name in wanted:
            inst = str(value)
            services.setdefault(inst.lower(), Service(instance=inst, service_type=name))
        elif rtype == TYPE_SRV:
            srv[name] = value  # type: ignore[assignment]
        elif rtype == TYPE_TXT:
            txt.setdefault(name, {}).update(value)  # type: ignore[arg-type]
        elif rtype in (TYPE_A, TYPE_AAAA):
            lst = addrs.setdefault(name, [])
            if value not in lst:
                lst.append(str(value))
    for key, svc in services.items():
        if key in srv:
            svc.host, svc.port = srv[key]
        svc.txt = txt.get(key, {})
        if svc.host:
            v4 = [a for a in addrs.get(svc.host.lower(), []) if ":" not in a]
            v6 = [a for a in addrs.get(svc.host.lower(), []) if ":" in a]
            svc.addresses = v4 + v6
    return list(services.values())


def browse(service_types=SCANNER_SERVICE_TYPES, timeout: float = 3.0) -> list[Service]:
    """Browse the local network for scanner services."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    try:
        # Ephemeral port: responders answer with unicast ("legacy" query),
        # so we don't fight avahi-daemon for port 5353.
        sock.bind(("", 0))
        sock.settimeout(0.25)
        query = build_query(list(service_types))
        query = struct.pack("!H", random.randint(1, 0xFFFF)) + query[2:]
        records: list[tuple[str, int, object]] = []
        deadline = time.monotonic() + timeout
        next_send = 0.0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
                next_send = time.monotonic() + 1.0
            try:
                data, _ = sock.recvfrom(9000)
            except socket.timeout:
                continue
            try:
                records.extend(parse_packet(data))
            except (ValueError, struct.error):
                continue
    finally:
        sock.close()
    services = assemble(records, service_types)
    # Resolve any host names we did not get an address record for.
    for svc in services:
        if not svc.addresses and svc.host:
            try:
                svc.addresses = [socket.gethostbyname(svc.host)]
            except OSError:
                pass
    return services
