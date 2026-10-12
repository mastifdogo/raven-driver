"""``raven-scan`` command-line interface."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import ipaddress

from . import __version__, mdns, sweep, wifidirect
from .escl import PAGE_SIZES, ESCLError, ESCLScanner, ScanRequest
from .http import Endpoint, HTTPFailure
from .pdf import NotJPEG, jpegs_to_pdf
from .probe import Detected, http_banner, probe, try_escl, try_twainlocal
from .twainlocal import TwainLocalError, TwainLocalScanner

EXT_FOR_TYPE = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tif",
    "application/pdf": ".pdf",
}


def _err(msg: str) -> None:
    print(f"raven-scan: {msg}", file=sys.stderr)


NOT_REACHABLE = """Nothing answered at {host}. Either that is not the scanner's address,
or the scanner is off or not on Wi-Fi. To find its real address, run:
  raven-scan discover"""


def _identify(host: sweep.Host) -> str:
    """Best-effort one-line description of what a swept host is."""
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("https", 8443)):
        if port not in host.open_ports:
            continue
        try:
            return "eSCL scanner: " + (try_escl(host.address, scheme, port, "eSCL", True, 2.0).model or "?")
        except Exception:  # noqa: BLE001
            pass
        try:
            return "TWAIN Local scanner: " + (try_twainlocal(host.address, scheme, port, True, 2.0).model or "?")
        except Exception:  # noqa: BLE001
            pass
        try:
            return http_banner(host.address, scheme, port, True, 2.0)
        except Exception:  # noqa: BLE001
            pass
    return ""


def _sweep(args) -> int:
    if args.subnet:
        nets = [ipaddress.IPv4Network(args.subnet, strict=False)]
    else:
        nets = sweep.local_networks()
    if not nets:
        print("Could not work out this computer's network. Pass one, e.g. --subnet 192.168.0.0/24")
        return 1
    print(f"Sweeping {', '.join(map(str, nets))} for devices with web or scan ports open...")
    hosts = sweep.sweep(nets)
    if not hosts:
        print("No devices answered. Check that this computer is on the same Wi-Fi as the scanner.")
        return 1
    for h in hosts:
        h.hint = _identify(h)
    hosts.sort(key=lambda h: ("raven" not in h.hint.lower(), "scanner" not in h.hint.lower()))
    print()
    for h in hosts:
        mac = f"  mac {h.mac}" if h.mac else ""
        print(f"{h.address:<16} ports {','.join(map(str, h.open_ports)):<20}{mac}")
        if h.hint:
            print(f"                 {h.hint}")
    print("\nYour router, printers and computers will also be listed. To check a")
    print("candidate, run: raven-scan probe <address>")
    return 0


def cmd_discover(args) -> int:
    services = [] if args.sweep_only else mdns.browse(timeout=args.timeout)
    if not services:
        if not args.sweep_only:
            print("No scanner advertised itself over mDNS.")
        if args.no_sweep:
            print("Check that the scanner's Wi-Fi light is blue and that this computer is on")
            print("the same network. Then try: raven-scan discover --sweep-only")
            return 1
        return _sweep(args)
    for svc in services:
        proto = {
            "_uscan._tcp.local": "eSCL",
            "_uscans._tcp.local": "eSCL/TLS",
            "_privet._tcp.local": "TWAIN Local" if "twaindirect" in svc.txt.get("type", "") else "Privet",
            "_scanner._tcp.local": "Bonjour scanner",
        }.get(svc.service_type, svc.service_type)
        model = svc.txt.get("ty") or svc.txt.get("mdl") or ""
        root = svc.txt.get("rs", "")
        print(f"{svc.name}\n  protocol: {proto}\n  address:  {svc.address}:{svc.port}")
        if model:
            print(f"  model:    {model}")
        if root:
            print(f"  eSCL root: /{root}")
    return 0


def _extra(args) -> list[tuple[str, int]] | None:
    return [("https" if args.tls else "http", args.port)] if args.port else None


def cmd_probe(args) -> int:
    report = probe(args.host, escl_root=args.escl_root, timeout=args.timeout, extra=_extra(args))
    if args.json:
        print(report.to_json())
        return 0 if report.detected else 2
    if not report.open_ports and not report.detected:
        print(NOT_REACHABLE.format(host=args.host))
        return 3
    print(f"Host {report.host}")
    print(f"  open TCP ports: {', '.join(map(str, report.open_ports)) or 'none'}")
    for key, banner in report.banners.items():
        print(f"  {key}: {banner}")
    if report.detected:
        for d in report.detected:
            print(f"  FOUND {d.protocol} at {d.base_url}{d.root}  model={d.model!r}")
        best = report.best()
        print(f"\nScanning will use {best.protocol}. Try:\n  raven-scan scan {args.host} -o scan.pdf")
        if best.protocol == "escl":
            print("\nThis scanner also works with any SANE frontend through sane-airscan:")
            print(f"  raven-scan sane-config {args.host}")
        return 0
    print("\nNo supported protocol found. The scanner may use Raven's private protocol.")
    print("Run `raven-scan probe --json` and follow docs/REVERSE_ENGINEERING.md.")
    return 2


def _pick_host(args) -> str:
    if args.host:
        return args.host
    services = mdns.browse(timeout=3.0)
    if not services:
        # On Wi-Fi Direct the scanner is our router, so try the gateway.
        for gw in wifidirect.default_gateways():
            report = probe(gw, escl_root=args.escl_root, timeout=args.timeout, extra=_extra(args))
            if report.best():
                print(f"Using the scanner at gateway {gw}", file=sys.stderr)
                return gw
        raise SystemExit("raven-scan: no scanner found on the network; pass its IP address")
    raven = [s for s in services if "raven" in (s.name + str(s.txt)).lower()]
    chosen = (raven or services)[0]
    if not chosen.address:
        raise SystemExit(f"raven-scan: could not resolve an address for {chosen.name}")
    print(f"Using {chosen.name} at {chosen.address}", file=sys.stderr)
    return chosen.address


def _detect(args, host: str) -> Detected:
    if args.protocol == "auto":
        report = probe(host, escl_root=args.escl_root, timeout=args.timeout, extra=_extra(args))
        best = report.best()
        if not best and not report.open_ports:
            raise SystemExit("raven-scan: " + NOT_REACHABLE.format(host=host))
        if not best:
            raise SystemExit(
                "raven-scan: the scanner does not answer eSCL or TWAIN Local.\n"
                "Run `raven-scan probe " + host + "` for details."
            )
        return best
    scheme = "https" if args.tls else "http"
    port = args.port or (443 if args.tls else 80)
    return Detected(protocol=args.protocol, base_url=f"{scheme}://{host}:{port}", root=args.escl_root)


def _write_output(out: Path, pages: list[tuple[bytes, str]], resolution: int) -> list[Path]:
    if not pages:
        return []
    if out.suffix.lower() == ".pdf":
        types = {ct.split(";")[0].strip().lower() for _, ct in pages}
        if types == {"image/jpeg"}:
            try:
                out.write_bytes(jpegs_to_pdf([d for d, _ in pages], fallback_dpi=resolution))
                return [out]
            except NotJPEG:
                pass
        if len(pages) == 1 and types == {"application/pdf"}:
            out.write_bytes(pages[0][0])
            return [out]
    written = []
    stem, suffix = out.stem, out.suffix
    for n, (data, ctype) in enumerate(pages, start=1):
        ext = EXT_FOR_TYPE.get(ctype.split(";")[0].strip().lower(), suffix or ".bin")
        target = out if len(pages) == 1 and ext == suffix else out.with_name(f"{stem}-{n:03d}{ext}")
        target.write_bytes(data)
        written.append(target)
    return written


def cmd_scan(args) -> int:
    host = _pick_host(args)
    target = _detect(args, host)
    # A scanner found over HTTPS by auto-detection only has a self-signed
    # certificate for its LAN address, so accept it the way probing did.
    insecure = args.insecure or (args.protocol == "auto" and target.base_url.startswith("https"))
    endpoint = Endpoint(target.base_url, timeout=args.timeout, insecure=insecure)
    pages: list[tuple[bytes, str]] = []
    try:
        if target.protocol == "escl":
            scanner = ESCLScanner(endpoint, root=target.root or args.escl_root)
            req = ScanRequest(
                source=args.source,
                mode=args.mode,
                resolution=args.resolution,
                duplex=args.duplex,
                page_size=args.page_size,
                document_format="image/jpeg",
            )
            for page in scanner.scan(req):
                pages.append((page.data, page.content_type))
                print(f"  page {len(pages)} received ({len(page.data)} bytes)", file=sys.stderr)
        else:
            scanner = TwainLocalScanner(endpoint)
            for image in scanner.scan(args.source, args.mode, args.resolution, args.duplex):
                pages.append((image.data, image.content_type))
                print(f"  image {image.number} received ({len(image.data)} bytes)", file=sys.stderr)
    except (ESCLError, TwainLocalError, HTTPFailure, OSError) as exc:
        _err(str(exc))
        if not pages:
            return 1
        _err("saving the pages that arrived before the error")
    if not pages:
        _err("the scanner returned no pages; is paper loaded?")
        return 1
    written = _write_output(Path(args.output), pages, args.resolution)
    for path in written:
        print(path)
    if len(written) > 1 and Path(args.output).suffix.lower() == ".pdf":
        _err("pages came back as separate PDFs; merge with: qpdf --empty --pages "
             + " ".join(str(p) for p in written) + f" -- {args.output}")
    return 0


def _report_gateways(args) -> int:
    gateways = wifidirect.wait_for_gateway()
    if not gateways:
        print("Joined, but got no network address from the scanner. Wait a few")
        print("seconds and run: raven-scan direct --probe-only")
        return 1
    found = 0
    for gw in gateways:
        print(f"\nChecking the scanner at {gw}...")
        report = probe(gw, timeout=args.timeout)
        best = report.best()
        if best:
            found += 1
            print(f"  FOUND {best.protocol} scanner {best.model!r} at {gw}")
            print(f"\nScan with:\n  raven-scan scan {gw} -o scan.pdf")
        elif report.open_ports:
            print(f"  {gw} answers on ports {', '.join(map(str, report.open_ports))} but speaks")
            print("  neither eSCL nor TWAIN Local. Send the output of:")
            print(f"    raven-scan probe --json {gw}")
        else:
            print(f"  Nothing answered at {gw}. You may be on your home network, not the scanner's.")
    return 0 if found else 2


def _print_networks(networks, file=None) -> None:
    for n in networks:
        mark = "*" if n.likely_scanner else " "
        used = "  (connected)" if n.in_use else ""
        print(f" {mark} {n.ssid:<32} signal {n.signal:>3}  {n.security or 'open'}{used}", file=file)


def cmd_direct(args) -> int:
    if args.probe_only:
        return _report_gateways(args)
    if not wifidirect.have_nmcli():
        print("nmcli (NetworkManager) is not installed. Join the scanner's Wi-Fi network")
        print("from your desktop's Wi-Fi menu, then run: raven-scan direct --probe-only")
        return 1
    try:
        devices = wifidirect.wifi_devices()
    except (OSError, subprocess.SubprocessError):
        devices = None
    if devices == []:
        print("This computer has no Wi-Fi adapter that NetworkManager can use, so it")
        print("cannot see the scanner's network. Desktop PCs often have no Wi-Fi.")
        print("Add a USB Wi-Fi adapter, or run this driver on a laptop.")
        print("Check with: nmcli device")
        return 1
    if devices and all(state == "unavailable" for _, state in devices):
        print("Wi-Fi is switched off on this computer. Turn it on with:")
        print("  nmcli radio wifi on")
        return 1
    try:
        networks = wifidirect.list_networks()
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        _err(f"could not list Wi-Fi networks: {exc}")
        return 1
    if not args.ssid:
        if not networks:
            print("No Wi-Fi networks found. Is this computer's Wi-Fi on?")
            return 1
        _print_networks(networks)
        print("\nJoin the scanner's network with:\n  raven-scan direct --ssid 'NAME'")
        return 0
    ssid = args.ssid
    if not args.hidden:
        match, suggestions = wifidirect.match_ssid(args.ssid, networks)
        if match is None:
            _err(f"no network named {args.ssid!r} is visible from this computer.")
            if suggestions:
                print("Did you mean: " + ", ".join(repr(x) for x in suggestions), file=sys.stderr)
            if networks:
                print("\nNetworks this computer can see:", file=sys.stderr)
                _print_networks(networks, file=sys.stderr)
            else:
                print("This computer sees no Wi-Fi networks at all.", file=sys.stderr)
            print("\nCheck that the scanner's Wi-Fi Direct is on and the scanner is close by.", file=sys.stderr)
            print("If its network is hidden, retry with --hidden.", file=sys.stderr)
            return 1
        ssid = match.ssid
    print(f"Joining {ssid}. This computer leaves its current Wi-Fi network,")
    print("so it has no internet until you switch back.")
    try:
        wifidirect.connect(ssid, hidden=args.hidden)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        _err(str(exc))
        return 1
    return _report_gateways(args)


def cmd_sane_config(args) -> int:
    report = probe(args.host, escl_root=args.escl_root, timeout=args.timeout, extra=_extra(args))
    escl = [d for d in report.detected if d.protocol == "escl"]
    if not escl:
        _err("no eSCL endpoint found, so sane-airscan cannot drive this scanner.")
        _err("Use `raven-scan scan` instead.")
        return 2
    d = escl[0]
    name = d.model or "Raven Compact"
    print("# Add to /etc/sane.d/airscan.conf under the [devices] section:")
    print("[devices]")
    print(f'"{name}" = {d.base_url}{d.root}/, eSCL')
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="raven-scan", description="Linux driver for the Raven Compact Wi-Fi scanner")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def conn_opts(sp, host_required=True):
        if host_required:
            sp.add_argument("host", help="scanner IP address or host name")
        else:
            sp.add_argument("host", nargs="?", help="scanner IP or host name (default: auto-discover)")
        sp.add_argument("--port", type=int, help="force a TCP port")
        sp.add_argument("--tls", action="store_true", help="use HTTPS on --port")
        sp.add_argument("--escl-root", default="eSCL", help="eSCL path prefix (default: eSCL)")
        sp.add_argument("--timeout", type=float, default=30.0, help="network timeout in seconds")

    d = sub.add_parser("discover", help="find scanners on the local network")
    d.add_argument("--timeout", type=float, default=4.0)
    d.add_argument("--subnet", help="network to sweep, e.g. 192.168.0.0/24 (default: this computer's)")
    d.add_argument("--no-sweep", action="store_true", help="only use mDNS, never sweep the subnet")
    d.add_argument("--sweep-only", action="store_true", help="skip mDNS and sweep the subnet")
    d.set_defaults(func=cmd_discover)

    pr = sub.add_parser("probe", help="detect which protocol a scanner speaks")
    conn_opts(pr)
    pr.add_argument("--json", action="store_true", help="machine-readable report")
    pr.set_defaults(func=cmd_probe, timeout=4.0)

    s = sub.add_parser("scan", help="scan pages")
    conn_opts(s, host_required=False)
    s.add_argument("-o", "--output", default="scan.pdf", help="output file (.pdf combines pages)")
    s.add_argument("--protocol", choices=("auto", "escl", "twainlocal"), default="auto")
    s.add_argument("--source", choices=("auto", "adf", "flatbed"), default="auto")
    s.add_argument("--mode", choices=("color", "gray", "lineart"), default="color")
    s.add_argument("-r", "--resolution", type=int, default=300)
    s.add_argument("--duplex", action="store_true", help="scan both sides")
    s.add_argument("--page-size", choices=sorted(PAGE_SIZES), default="letter")
    s.add_argument("--insecure", action="store_true", help="accept the scanner's self-signed TLS certificate")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("direct", help="connect to the scanner over Wi-Fi Direct")
    w.add_argument("--ssid", help="the scanner's Wi-Fi Direct network name")
    w.add_argument("--hidden", action="store_true", help="the network is hidden; join it without seeing it")
    w.add_argument("--probe-only", action="store_true", help="already joined; just find the scanner")
    w.add_argument("--timeout", type=float, default=4.0)
    w.set_defaults(func=cmd_direct)

    c = sub.add_parser("sane-config", help="print a sane-airscan config line for this scanner")
    conn_opts(c)
    c.set_defaults(func=cmd_sane_config, timeout=4.0)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
