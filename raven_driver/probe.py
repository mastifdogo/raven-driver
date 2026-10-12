"""Work out which network-scanning protocol a scanner speaks."""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

from .escl import ESCLError, ESCLScanner
from .http import Endpoint, HTTPFailure
from .twainlocal import TwainLocalError, TwainLocalScanner

# Ports worth knocking on. Anything open here that is not eSCL or TWAIN Local
# goes into the report so the protocol can be reverse engineered later.
COMMON_PORTS = (
    21, 22, 23, 80, 443, 515, 554, 631, 1900, 3000, 4000, 5000, 5001, 5357, 5555, 6000, 7000, 7777, 8000, 8001,
    8008, 8010, 8080, 8081, 8443, 8888, 9000, 9001, 9090, 9100, 9400, 9500, 9999, 10000, 34034, 49152, 54921, 60000,
)

ESCL_CANDIDATES = (("http", 80), ("http", 8080), ("https", 443), ("https", 8443), ("http", 631), ("https", 631))
TWAIN_CANDIDATES = (("http", 80), ("https", 443), ("http", 34034), ("https", 34034), ("http", 8080))


@dataclass
class Detected:
    protocol: str  # "escl" | "twainlocal"
    base_url: str
    root: str = ""
    model: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class ProbeReport:
    host: str
    open_ports: list[int] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)
    detected: list[Detected] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def best(self) -> Detected | None:
        # eSCL first: it is simpler and also usable from sane-airscan.
        for proto in ("escl", "twainlocal"):
            for d in self.detected:
                if d.protocol == proto:
                    return d
        return None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports=COMMON_PORTS, timeout: float = 1.0) -> list[int]:
    with ThreadPoolExecutor(max_workers=256 if len(ports) > 100 else 32) as pool:
        results = pool.map(lambda p: (p, port_open(host, p, timeout)), ports)
    return sorted(p for p, ok in results if ok)


def try_escl(host: str, scheme: str, port: int, root: str, insecure: bool, timeout: float) -> Detected:
    base = f"{scheme}://{_fmt_host(host)}:{port}"
    scanner = ESCLScanner(Endpoint(base, timeout=timeout, insecure=insecure), root=root)
    caps = scanner.capabilities()
    return Detected(
        protocol="escl",
        base_url=base,
        root=scanner.root,
        model=caps.make_and_model,
        details={
            "sources": {k: asdict(v) for k, v in caps.sources.items()},
            "duplex": caps.duplex,
            "serial": caps.serial,
            "version": caps.version,
        },
    )


def try_twainlocal(host: str, scheme: str, port: int, insecure: bool, timeout: float) -> Detected:
    base = f"{scheme}://{_fmt_host(host)}:{port}"
    scanner = TwainLocalScanner(Endpoint(base, timeout=timeout, insecure=insecure))
    info = scanner.info()
    if "twaindirect" not in json.dumps(info.get("type", "")) and not any(
        "twaindirect" in a for a in info.get("api", [])
    ):
        raise TwainLocalError("privet device is not a TWAIN Direct scanner")
    model = " ".join(x for x in (info.get("manufacturer", ""), info.get("model", "")) if x) or info.get("name", "")
    return Detected(protocol="twainlocal", base_url=base, root=scanner.api, model=model, details=info)


def http_banner(host: str, scheme: str, port: int, insecure: bool, timeout: float) -> str:
    resp = Endpoint(f"{scheme}://{_fmt_host(host)}:{port}", timeout=timeout, insecure=insecure).request(
        "GET", "/", ok=()
    )
    server = resp.header("server", "") or ""
    title = ""
    body = resp.body[:4096].decode("utf-8", "replace")
    lo = body.lower()
    if "<title>" in lo:
        start = lo.index("<title>") + 7
        end = lo.find("</title>", start)
        title = body[start:end].strip() if end > start else ""
    return f"HTTP {resp.status}; server={server!r}; title={title!r}"


def _fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def probe(
    host: str,
    escl_root: str = "eSCL",
    insecure: bool = True,
    timeout: float = 4.0,
    extra: list[tuple[str, int]] | None = None,
) -> ProbeReport:
    """Probe ``host`` for eSCL and TWAIN Local.

    ``insecure`` defaults to True here because probing only reads public
    capability documents, and LAN scanners use self-signed certificates.
    """
    report = ProbeReport(host=host)
    report.open_ports = scan_ports(host)
    open_set = set(report.open_ports)

    escl_try = [c for c in ESCL_CANDIDATES if c[1] in open_set]
    twain_try = [c for c in TWAIN_CANDIDATES if c[1] in open_set]
    for scheme, port in extra or []:
        escl_try.insert(0, (scheme, port))
        twain_try.insert(0, (scheme, port))

    for scheme, port in escl_try:
        key = f"escl {scheme}:{port}"
        try:
            report.detected.append(try_escl(host, scheme, port, escl_root, insecure, timeout))
            break
        except (ESCLError, HTTPFailure, OSError) as exc:
            report.errors[key] = str(exc)
    for scheme, port in twain_try:
        key = f"twainlocal {scheme}:{port}"
        try:
            report.detected.append(try_twainlocal(host, scheme, port, insecure, timeout))
            break
        except (TwainLocalError, HTTPFailure, OSError, ValueError) as exc:
            report.errors[key] = str(exc)

    for port in report.open_ports:
        for scheme in ("http", "https"):
            try:
                report.banners[f"{scheme}:{port}"] = http_banner(host, scheme, port, True, timeout)
                break
            except Exception:  # noqa: BLE001 - banner grabbing is best effort
                continue
    return report
