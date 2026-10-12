"""``raven-scan`` command-line interface."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import ipaddress

from . import __version__, explore, mdns, sweep, wifidirect
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


def _prog() -> str:
    """How the user started us, so suggested commands can be pasted as-is."""
    if sys.argv and sys.argv[0].endswith("__main__.py"):
        return "python3 -m raven_driver"
    return "raven-scan"


def _err(msg: str) -> None:
    print(f"raven-scan: {msg}", file=sys.stderr)


NOT_REACHABLE = """Nothing answered at {host}. Either that is not the scanner's address,
or the scanner is off or not on Wi-Fi. To find its real address, run:
  {prog} discover"""


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
    print(f"candidate, run: {_prog()} probe <address>")
    return 0


def cmd_discover(args) -> int:
    services = [] if args.sweep_only else mdns.browse(timeout=args.timeout)
    if not services:
        if not args.sweep_only:
            print("No scanner advertised itself over mDNS.")
        if args.no_sweep:
            print("Check that the scanner's Wi-Fi light is blue and that this computer is on")
            print(f"the same network. Then try: {_prog()} discover --sweep-only")
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
        print(NOT_REACHABLE.format(host=args.host, prog=_prog()))
        return 3
    print(f"Host {report.host}")
    print(f"  open TCP ports: {', '.join(map(str, report.open_ports)) or 'none'}")
    for key, banner in report.banners.items():
        print(f"  {key}: {banner}")
    if report.detected:
        for d in report.detected:
            print(f"  FOUND {d.protocol} at {d.base_url}{d.root}  model={d.model!r}")
        best = report.best()
        print(f"\nScanning will use {best.protocol}. Try:\n  {_prog()} scan {args.host} -o scan.pdf")
        if best.protocol == "escl":
            print("\nThis scanner also works with any SANE frontend through sane-airscan:")
            print(f"  {_prog()} sane-config {args.host}")
        return 0
    print("\nNo supported protocol found. The scanner may use Raven's private protocol.")
    print(f"Map it with `{_prog()} explore {args.host}` and share the summary,")
    print("or follow docs/REVERSE_ENGINEERING.md.")
    return 2


def _pick_host(args) -> str:
    if args.host:
        return args.host
    services = mdns.browse(timeout=3.0)
    if not services:
        # On Wi-Fi Direct the scanner is our router, so try the gateway.
        try:
            nearby = wifidirect.link_info().candidates() if wifidirect.have_nmcli() else []
        except (OSError, subprocess.SubprocessError, ValueError):
            nearby = []
        for gw in dict.fromkeys(nearby + wifidirect.default_gateways()):
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
            raise SystemExit("raven-scan: " + NOT_REACHABLE.format(host=host, prog=_prog()))
        if not best:
            raise SystemExit(
                "raven-scan: the scanner does not answer eSCL or TWAIN Local.\n"
                f"Run `{_prog()} probe " + host + "` for details."
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


def _check_scanner_at(addr: str, args) -> str:
    """Probe one address. Returns "found", "private", or "" for no answer."""
    report = probe(addr, timeout=args.timeout)
    best = report.best()
    if best:
        print(f"  FOUND {best.protocol} scanner {best.model!r} at {addr}")
        print(f"\nScan with:\n  {_prog()} scan {addr} -o scan.pdf")
        return "found"
    if report.open_ports:
        print(f"  {addr} answers on ports {', '.join(map(str, report.open_ports))} but speaks")
        print("  neither eSCL nor TWAIN Local, so it uses Raven's own protocol.")
        print("  Map it with this read-only command and share the summary:")
        print(f"    {_prog()} explore {addr}")
        return "private"
    print(f"  Nothing answered at {addr}.")
    return ""


def _report_gateways(args) -> int:
    print("Waiting for the scanner to give this computer a network address...")
    link = wifidirect.wait_for_link()
    if not link.device:
        print("This computer is not connected to any Wi-Fi network right now.")
        print(f"Join the scanner's network first: {_prog()} direct --ssid 'NAME'")
        return 1
    if not link.address or link.link_local:
        got = f"only the fallback address {link.address}" if link.address else "no address"
        print(f"Wi-Fi device {link.device} is connected but got {got} from the scanner.")
        print("The scanner did not answer this computer's address request. Try, in order:")
        print("  1. Reconnect:  nmcli device disconnect " + link.device + " && " + _prog() + " direct --ssid 'NAME'")
        print("  2. Turn the scanner's Wi-Fi Direct off and on, then reconnect.")
        print("  3. Show what the computer sees, and share it:")
        print(f"       nmcli -f GENERAL.CONNECTION,IP4,DHCP4 device show {link.device}")
        return 1
    print(f"Wi-Fi device {link.device} has address {link.address}.")
    clashes = wifidirect.overlapping_interfaces(link)
    if clashes:
        others = ", ".join(f"{dev} ({cidr})" for dev, cidr in clashes)
        print(f"\nThe scanner's network {link.network} overlaps another connection: {others}.")
        print("Traffic meant for the scanner could reach your home router instead, so")
        print("results would be wrong. Disconnect the other connection while scanning:")
        for dev, _ in clashes:
            print(f"  nmcli device disconnect {dev}")
        print(f"Then run: {_prog()} direct --probe-only")
        print("Reconnect it afterwards with: nmcli device connect " + clashes[0][0])
        return 1
    candidates = link.candidates()
    for addr in candidates:
        print(f"\nChecking for the scanner at {addr}...")
        outcome = _check_scanner_at(addr, args)
        if outcome:
            return 0 if outcome == "found" else 2
    net = link.network
    if net is not None and net.prefixlen >= 24:
        print(f"\nNot at the usual addresses. Searching all of {net}...")
        hosts = sweep.sweep([net])
        for h in hosts:
            if h.address in candidates:
                continue
            print(f"\nChecking for the scanner at {h.address}...")
            outcome = _check_scanner_at(h.address, args)
            if outcome:
                return 0 if outcome == "found" else 2
    print("\nNo device on the scanner's network answered. Share the output of:")
    print(f"  nmcli -f GENERAL.CONNECTION,IP4,DHCP4 device show {link.device}")
    return 2


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
        print(f"from your desktop's Wi-Fi menu, then run: {_prog()} direct --probe-only")
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
        print(f"\nJoin the scanner's network with:\n  {_prog()} direct --ssid 'NAME'")
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


def cmd_explore(args) -> int:
    out_dir = Path(args.output or f"raven-explore-{args.host}")
    scheme = "https" if args.tls else "http"
    port = args.port or (443 if args.tls else 80)
    print(f"Reading the scanner's web interface at {scheme}://{args.host}:{port} (read-only)...", file=sys.stderr)
    result = explore.explore(args.host, port=port, scheme=scheme, out_dir=out_dir, max_requests=args.max_requests)
    if not result.hits and result.errors:
        _err(f"could not read anything from {args.host}: {result.errors[0]}")
        return 1
    print(explore.summarize(result))
    print(f"\nEverything it fetched is saved in {out_dir}/", file=sys.stderr)
    print("Paste the summary above to get scanning support written for this protocol.", file=sys.stderr)
    return 0


def cmd_sane_config(args) -> int:
    report = probe(args.host, escl_root=args.escl_root, timeout=args.timeout, extra=_extra(args))
    escl = [d for d in report.detected if d.protocol == "escl"]
    if not escl:
        _err("no eSCL endpoint found, so sane-airscan cannot drive this scanner.")
        _err(f"Use `{_prog()} scan` instead.")
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

    e = sub.add_parser("explore", help="map the scanner's private web interface (read-only)")
    e.add_argument("host", help="scanner IP address, e.g. 192.168.1.1 on Wi-Fi Direct")
    e.add_argument("--port", type=int, help="web port (default 80)")
    e.add_argument("--tls", action="store_true", help="use HTTPS")
    e.add_argument("-o", "--output", help="folder for fetched files (default raven-explore-HOST)")
    e.add_argument("--max-requests", type=int, default=80)
    e.set_defaults(func=cmd_explore)

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
