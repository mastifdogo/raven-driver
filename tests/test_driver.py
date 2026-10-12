import json
import struct
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from raven_driver import mdns
from raven_driver.cli import main
from raven_driver.escl import NS, ESCLScanner, ScanRequest, build_scan_settings, parse_capabilities
from raven_driver.http import Endpoint
from raven_driver.pdf import jpeg_info, jpegs_to_pdf
from raven_driver.probe import probe
from raven_driver.twainlocal import TwainLocalScanner, build_task, parse_multipart

from tests.fakes import CAPS_XML, TINY_JPEG, FakeESCL, FakePrivateUI, FakeTwainLocal


class MDNSTests(unittest.TestCase):
    def _answer(self):
        def rr(name, rtype, rdata):
            return mdns.encode_name(name) + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata

        inst = "Raven Compact._uscan._tcp.local"
        txt = b"".join(bytes([len(e)]) + e for e in (b"ty=Raven Compact", b"rs=eSCL"))
        records = [
            rr("_uscan._tcp.local", mdns.TYPE_PTR, mdns.encode_name(inst)),
            rr(inst, mdns.TYPE_SRV, struct.pack("!HHH", 0, 0, 80) + mdns.encode_name("raven.local")),
            rr(inst, mdns.TYPE_TXT, txt),
            rr("raven.local", mdns.TYPE_A, bytes([192, 168, 1, 40])),
        ]
        return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)

    def test_parse_response_into_service(self):
        services = mdns.assemble(mdns.parse_packet(self._answer()))
        self.assertEqual(len(services), 1)
        svc = services[0]
        self.assertEqual(svc.name, "Raven Compact")
        self.assertEqual((svc.address, svc.port), ("192.168.1.40", 80))
        self.assertEqual(svc.txt["rs"], "eSCL")

    def test_compressed_names(self):
        # Pointer at offset 12 back to a name stored earlier in the packet.
        packet = b"\x00" * 12 + mdns.encode_name("a.local") + b"\x03foo\xc0\x0c"
        name, end = mdns.read_name(packet, 12 + len(mdns.encode_name("a.local")))
        self.assertEqual(name, "foo.a.local")
        self.assertEqual(end, len(packet))

    def test_pointer_loop_rejected(self):
        with self.assertRaises(ValueError):
            mdns.read_name(b"\x00" * 12 + b"\xc0\x0c", 12)


class ESCLTests(unittest.TestCase):
    def test_capabilities(self):
        caps = parse_capabilities(CAPS_XML)
        self.assertEqual(caps.make_and_model, "Raven Compact")
        self.assertTrue(caps.duplex)
        feeder = caps.source("adf")
        self.assertEqual(feeder.resolutions, [200, 300, 600])
        self.assertIn("Grayscale8", feeder.color_modes)

    def test_settings_snap_resolution_and_clamp_size(self):
        caps = parse_capabilities(CAPS_XML)
        xml = build_scan_settings(ScanRequest(resolution=250, duplex=True, page_size="legal"), caps)
        root = ET.fromstring(xml)
        self.assertEqual(root.find("scan:XResolution", NS).text, "300")
        self.assertEqual(root.find("pwg:InputSource", NS).text, "Feeder")
        self.assertEqual(root.find("scan:Duplex", NS).text, "true")
        self.assertEqual(root.find("pwg:ScanRegions/pwg:ScanRegion/pwg:Height", NS).text, "4200")

    def test_scan_retries_busy_and_stops_at_404(self):
        with FakeESCL(pages=3) as fake:
            scanner = ESCLScanner(Endpoint(f"http://127.0.0.1:{fake.port}"))
            pages = list(scanner.scan(ScanRequest(source="adf", mode="gray")))
            self.assertEqual(len(pages), 3)
            self.assertIn("<scan:ColorMode>Grayscale8</scan:ColorMode>", fake.settings)
            self.assertTrue(fake.deleted)


class TwainLocalTests(unittest.TestCase):
    def test_task_shape(self):
        task = build_task("auto", "lineart", 200, duplex=True)
        src = task["actions"][0]["streams"][0]["sources"][0]
        self.assertEqual(src["source"], "feederDuplex")
        self.assertEqual(src["pixelFormats"][0]["pixelFormat"], "bw1")

    def test_multipart(self):
        body = b"--b\r\nContent-Type: application/json\r\n\r\n{}\r\n--b\r\nContent-Type: application/pdf\r\n\r\nPDF\r\n--b--\r\n"
        parts = parse_multipart("multipart/mixed; boundary=b", body)
        self.assertEqual([p for _, p in parts], [b"{}", b"PDF"])

    def test_full_session_reassembles_multi_block_images(self):
        with FakeTwainLocal() as fake:
            scanner = TwainLocalScanner(Endpoint(f"http://127.0.0.1:{fake.port}"), poll_timeout=5)
            images = list(scanner.scan(source="adf", mode="color", resolution=300))
            self.assertEqual([i.number for i in images], [1, 2])
            self.assertEqual(images[0].data, b"%PDF-1.4 part-a part-b %%EOF")
            self.assertEqual(sorted(fake.released), [1, 2, 3])
            self.assertEqual(fake.calls[0], "createSession")
            self.assertEqual(fake.calls[-1], "closeSession")
            self.assertEqual(fake.task["actions"][0]["streams"][0]["sources"][0]["source"], "feederFront")


class PDFTests(unittest.TestCase):
    def test_jpeg_info(self):
        self.assertEqual(jpeg_info(TINY_JPEG), (85, 110, 3, (10, 10)))

    def test_pdf_pages(self):
        pdf = jpegs_to_pdf([TINY_JPEG, TINY_JPEG])
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"/Count 2", pdf)
        self.assertIn(b"/MediaBox [0 0 612.000 792.000]", pdf)
        with tempfile.NamedTemporaryFile(suffix=".pdf") as f:
            f.write(pdf)
            f.flush()
            try:
                out = subprocess.run(["pdfinfo", f.name], capture_output=True, text=True)
            except FileNotFoundError:
                self.skipTest("pdfinfo not installed")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("Pages:           2", out.stdout)


class ProbeAndCLITests(unittest.TestCase):
    def test_probe_finds_escl(self):
        with FakeESCL() as fake:
            report = probe("127.0.0.1", extra=[("http", fake.port)])
            self.assertEqual(report.best().protocol, "escl")
            self.assertEqual(report.best().model, "Raven Compact")
            json.loads(report.to_json())

    def test_probe_finds_twainlocal(self):
        with FakeTwainLocal() as fake:
            report = probe("127.0.0.1", extra=[("http", fake.port)])
            self.assertEqual([d.protocol for d in report.detected], ["twainlocal"])
            self.assertEqual(report.best().model, "Raven Compact")

    def test_cli_scan_escl_to_pdf(self):
        with FakeESCL(pages=2) as fake, tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "doc.pdf"
            rc = main(["scan", "127.0.0.1", "--port", str(fake.port), "-o", str(out), "--duplex"])
            self.assertEqual(rc, 0)
            self.assertIn(b"/Count 2", out.read_bytes())

    def test_cli_scan_twainlocal_writes_numbered_pdfs(self):
        with FakeTwainLocal() as fake, tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "doc.pdf"
            rc = main(["scan", "127.0.0.1", "--port", str(fake.port), "--protocol", "twainlocal", "-o", str(out)])
            self.assertEqual(rc, 0)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["doc-001.pdf", "doc-002.pdf"])

    def test_cli_sane_config(self):
        with FakeESCL() as fake:
            from io import StringIO
            from contextlib import redirect_stdout

            buf = StringIO()
            with redirect_stdout(buf):
                rc = main(["sane-config", "127.0.0.1", "--port", str(fake.port)])
            self.assertEqual(rc, 0)
            self.assertIn(f'"Raven Compact" = http://127.0.0.1:{fake.port}/eSCL/, eSCL', buf.getvalue())

    def test_module_entry_point(self):
        out = subprocess.run([sys.executable, "-m", "raven_driver", "--version"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("0.1.0", out.stdout)


class UnreachableAndSweepTests(unittest.TestCase):
    def _no_ports(self):
        from unittest import mock

        return mock.patch("raven_driver.probe.scan_ports", return_value=[])

    def test_probe_says_wrong_address_when_nothing_answers(self):
        from contextlib import redirect_stdout
        from io import StringIO

        buf = StringIO()
        with self._no_ports(), redirect_stdout(buf):
            rc = main(["probe", "192.0.2.77"])
        self.assertEqual(rc, 3)
        self.assertIn("Nothing answered at 192.0.2.77", buf.getvalue())
        self.assertNotIn("private protocol", buf.getvalue())

    def test_scan_says_wrong_address_when_nothing_answers(self):
        with self._no_ports(), self.assertRaises(SystemExit) as ctx:
            main(["scan", "192.0.2.77", "-o", "/dev/null"])
        self.assertIn("Nothing answered at 192.0.2.77", str(ctx.exception.code))

    def test_sweep_finds_and_identifies_scanner(self):
        import ipaddress

        from raven_driver import sweep

        with FakeESCL() as fake:
            hosts = sweep.sweep([ipaddress.IPv4Network("127.0.0.1/32")], ports=(fake.port,))
            self.assertEqual([(h.address, h.open_ports) for h in hosts], [("127.0.0.1", [fake.port])])

    def test_identify_reports_escl_model(self):
        from unittest import mock

        from raven_driver import sweep
        from raven_driver.cli import _identify

        with mock.patch("raven_driver.cli.try_escl") as try_escl:
            try_escl.return_value.model = "Raven Compact"
            self.assertEqual(_identify(sweep.Host("127.0.0.1", [80])), "eSCL scanner: Raven Compact")

    def test_local_networks_are_at_most_slash_24(self):
        from raven_driver import sweep

        for net in sweep.local_networks():
            self.assertGreaterEqual(net.prefixlen, 24)


class SSIDMatchTests(unittest.TestCase):
    def _nets(self, *names):
        from raven_driver.wifidirect import Network

        return [Network(n, 50, "WPA2") for n in names]

    def test_exact_case_and_partial_matches(self):
        from raven_driver.wifidirect import match_ssid

        nets = self._nets("HomeNet", "raven-cb3a1f", "Neighbour")
        self.assertEqual(match_ssid("raven-cb3a1f", nets)[0].ssid, "raven-cb3a1f")
        self.assertEqual(match_ssid("RAVEN-CB3A1F", nets)[0].ssid, "raven-cb3a1f")
        self.assertEqual(match_ssid("Raven-CB3", nets)[0].ssid, "raven-cb3a1f")

    def test_no_match_gives_suggestions(self):
        from raven_driver.wifidirect import match_ssid

        match, suggestions = match_ssid("Raven-CB3", self._nets("Raven-C83", "HomeNet"))
        self.assertIsNone(match)
        self.assertEqual(suggestions, ["Raven-C83"])

    def test_ambiguous_partial_is_not_guessed(self):
        from raven_driver.wifidirect import match_ssid

        match, suggestions = match_ssid("raven", self._nets("Raven-1", "Raven-2"))
        self.assertIsNone(match)
        self.assertEqual(sorted(suggestions), ["Raven-1", "Raven-2"])

    def test_parse_devices(self):
        from raven_driver.wifidirect import parse_devices

        out = "enp3s0:ethernet:connected\nwlp2s0:wifi:disconnected\nlo:loopback:unmanaged\n"
        self.assertEqual(parse_devices(out), [("wlp2s0", "disconnected")])


class DirectCommandTests(unittest.TestCase):
    def _run(self, argv, devices, networks=()):
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO
        from unittest import mock

        from raven_driver.wifidirect import Network

        nets = [Network(n, 60, "WPA2") for n in networks]
        out, err = StringIO(), StringIO()
        with mock.patch("raven_driver.wifidirect.have_nmcli", return_value=True), \
                mock.patch("raven_driver.wifidirect.wifi_devices", return_value=devices), \
                mock.patch("raven_driver.wifidirect.list_networks", return_value=nets), \
                mock.patch("raven_driver.wifidirect.connect") as connect, \
                mock.patch("raven_driver.cli._report_gateways", return_value=0), \
                redirect_stdout(out), redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue() + err.getvalue(), connect

    def test_no_wifi_adapter(self):
        rc, text, connect = self._run(["direct", "--ssid", "Raven-CB3"], devices=[])
        self.assertEqual(rc, 1)
        self.assertIn("no Wi-Fi adapter", text)
        connect.assert_not_called()

    def test_wifi_radio_off(self):
        rc, text, _ = self._run(["direct", "--ssid", "Raven-CB3"], devices=[("wlan0", "unavailable")])
        self.assertIn("nmcli radio wifi on", text)

    def test_not_visible_lists_networks(self):
        rc, text, connect = self._run(
            ["direct", "--ssid", "Raven-CB3"], [("wlan0", "connected")], ["HomeNet", "Raven-C83"]
        )
        self.assertEqual(rc, 1)
        self.assertIn("Did you mean: 'Raven-C83'", text)
        self.assertIn("HomeNet", text)
        self.assertIn("--hidden", text)
        connect.assert_not_called()

    def test_partial_name_joins_full_name(self):
        rc, _, connect = self._run(["direct", "--ssid", "Raven-CB3"], [("wlan0", "connected")], ["Raven-CB3A1F"])
        self.assertEqual(rc, 0)
        connect.assert_called_once_with("Raven-CB3A1F", hidden=False)

    def test_hidden_skips_visibility_check(self):
        rc, _, connect = self._run(["direct", "--ssid", "Raven-CB3", "--hidden"], [("wlan0", "connected")])
        self.assertEqual(rc, 0)
        connect.assert_called_once_with("Raven-CB3", hidden=True)


class ExploreTests(unittest.TestCase):
    def test_follows_links_and_scripts_read_only(self):
        from raven_driver import explore

        with FakePrivateUI() as fake, tempfile.TemporaryDirectory() as tmp:
            result = explore.explore("127.0.0.1", port=fake.port, out_dir=Path(tmp))
            urls = {h.url: h for h in result.hits}
            self.assertIn("/ui/home.html", urls)
            self.assertIn("/js/app.js", urls)
            self.assertIn("/api/v2/status", urls)
            self.assertNotIn("/api/v2/scan/start", fake.gets)
            self.assertNotIn("/cgi-bin/reboot.cgi", fake.gets)
            self.assertNotIn("/admin?action=factoryReset", fake.gets)
            self.assertIn("/cgi-bin/reboot.cgi", result.skipped_unsafe)
            self.assertIn("resolution", urls["/api/v2/status"].keywords)
            self.assertIn("/cgi-bin/save", result.skipped_unsafe)
            self.assertEqual(fake.posts, [])
            self.assertIn("RavenHTTP/1.2", result.server_headers)
            saved = json.loads((Path(tmp) / "summary.json").read_text())
            self.assertEqual(len(saved["hits"]), len(result.hits))
            for h in result.hits:
                self.assertTrue((Path(tmp) / h.saved_as).exists())
            text = explore.summarize(result)
            self.assertIn("200 /api/v2/status", text)
            self.assertIn("| <html><meta http-equiv=", text)

    def test_ssh_banner(self):
        import socket
        import threading

        from raven_driver.explore import ssh_banner

        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve():
            conn, _ = srv.accept()
            conn.sendall(b"SSH-2.0-dropbear_2019.78\r\n")
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        self.assertEqual(ssh_banner("127.0.0.1", srv.getsockname()[1]), "SSH-2.0-dropbear_2019.78")
        srv.close()

    def test_follows_meta_refresh_and_js_redirects(self):
        from raven_driver.explore import extract_links

        base = "http://10.10.10.254:80/"
        self.assertEqual(
            extract_links(base, '<meta http-equiv="refresh" content="0; URL=/web/home.html">'), ["/web/home.html"]
        )
        self.assertEqual(extract_links(base, "<script>window.location='app/index.html'</script>"), ["/app/index.html"])
        self.assertEqual(extract_links(base, '<script>location.replace("main.cgi?p=1")</script>'), ["/main.cgi?p=1"])

    def test_extract_links_stays_on_host(self):
        from raven_driver.explore import extract_links

        body = '<a href="http://evil.example/x">x</a><script src="app.js"></script> "/api/a?b=1" mailto:x'
        self.assertEqual(extract_links("http://10.0.0.1:80/dir/", body), ["/dir/app.js", "/api/a?b=1"])

    def test_cli_explore_prints_summary(self):
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO

        with FakePrivateUI() as fake, tempfile.TemporaryDirectory() as tmp:
            out = StringIO()
            with redirect_stdout(out), redirect_stderr(StringIO()):
                rc = main(["explore", "127.0.0.1", "--port", str(fake.port), "-o", tmp])
            self.assertEqual(rc, 0)
            self.assertIn("/api/v2/status", out.getvalue())

    def test_cli_explore_without_web_port(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from unittest import mock

        err = StringIO()
        with mock.patch("raven_driver.cli.port_open", return_value=False), redirect_stderr(err):
            rc = main(["explore", "10.10.10.1"])
        self.assertEqual(rc, 1)
        self.assertIn("no web port open", err.getvalue())


class LinkTests(unittest.TestCase):
    clashes: list = []

    NMCLI = (
        "IP4.ADDRESS[1]:192.168.1.23/24\n"
        "IP4.GATEWAY:\n"
        "DHCP4.OPTION[1]:dhcp_lease_time = 86400\n"
        "DHCP4.OPTION[2]:dhcp_server_identifier = 192.168.1.1\n"
        "DHCP4.OPTION[3]:ip_address = 192.168.1.23\n"
    )

    def test_parse_device_show_without_gateway(self):
        from raven_driver.wifidirect import parse_device_show

        self.assertEqual(
            parse_device_show(self.NMCLI), {"address": "192.168.1.23/24", "dhcp_server": "192.168.1.1"}
        )

    def test_parse_device_show_routers_option(self):
        from raven_driver.wifidirect import parse_device_show

        out = "IP4.ADDRESS[1]:10.5.0.9/24\nDHCP4.OPTION[4]:routers = 10.5.0.254\n"
        self.assertEqual(parse_device_show(out)["gateway"], "10.5.0.254")

    def test_candidates_without_gateway_use_dhcp_server_then_first_host(self):
        from raven_driver.wifidirect import LinkInfo

        link = LinkInfo(device="wlp9s0", address="192.168.1.23/24", dhcp_server="192.168.1.1")
        self.assertEqual(link.candidates(), ["192.168.1.1"])
        link = LinkInfo(device="wlp9s0", address="192.168.49.7/24")
        self.assertEqual(link.candidates(), ["192.168.49.1"])

    def test_candidates_drop_bogus_router_addresses(self):
        from raven_driver.wifidirect import LinkInfo

        # What Marcus's scanner reported: router 0.0.0.0 on 10.10.10.0/24.
        link = LinkInfo(device="wlp9s0", address="10.10.10.100/24", gateway="0.0.0.0",
                        route_gateways=["0.0.0.0"], dhcp_server="10.10.10.1")
        self.assertEqual(link.candidates(), ["10.10.10.1"])
        link = LinkInfo(device="wlp9s0", address="10.10.10.100/24", gateway="192.168.1.1")
        self.assertEqual(link.candidates(), ["10.10.10.1"])

    def test_keeps_checking_after_a_device_without_known_protocol(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest import mock

        from raven_driver.wifidirect import LinkInfo

        link = LinkInfo(device="wlp9s0", address="10.10.10.100/24", gateway="10.10.10.254", dhcp_server="10.10.10.1")
        outcomes = {"10.10.10.254": "private", "10.10.10.1": "found"}
        buf = StringIO()
        with mock.patch("raven_driver.wifidirect.wait_for_link", return_value=link), \
                mock.patch("raven_driver.wifidirect.overlapping_interfaces", return_value=[]), \
                mock.patch("raven_driver.cli._check_scanner_at", side_effect=lambda a, args: outcomes.get(a, "")), \
                redirect_stdout(buf):
            rc = main(["direct", "--probe-only"])
        self.assertEqual(rc, 0)
        self.assertIn("Checking for the scanner at 10.10.10.1", buf.getvalue())

    def test_cli_rejects_unspecified_address(self):
        from contextlib import redirect_stderr
        from io import StringIO

        err = StringIO()
        with redirect_stderr(err):
            rc = main(["explore", "0.0.0.0"])
        self.assertEqual(rc, 2)
        self.assertIn("reaches this computer itself", err.getvalue())

    def test_candidates_skip_own_address(self):
        from raven_driver.wifidirect import LinkInfo

        self.assertEqual(LinkInfo(address="192.168.1.1/24").candidates(), [])

    def test_routes_filtered_by_interface(self):
        from raven_driver.wifidirect import parse_proc_route

        text = (
            "Iface\tDestination\tGateway\tFlags\n"
            "enp3s0\t00000000\t0100A8C0\t0003\n"
            "wlp9s0\t00000000\t0101A8C0\t0003\n"
        )
        self.assertEqual(parse_proc_route(text, iface="wlp9s0"), ["192.168.1.1"])

    def _probe_only(self, link, hosts=()):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest import mock

        from raven_driver import sweep

        buf = StringIO()
        with mock.patch("raven_driver.wifidirect.wait_for_link", return_value=link), \
                mock.patch("raven_driver.wifidirect.overlapping_interfaces", return_value=self.clashes), \
                mock.patch("raven_driver.sweep.sweep", return_value=[sweep.Host(h, [80]) for h in hosts]), \
                mock.patch("raven_driver.cli._check_scanner_at", side_effect=lambda a, args: "private" if a == "192.168.1.77" else ""), \
                redirect_stdout(buf):
            rc = main(["direct", "--probe-only"])
        return rc, buf.getvalue()

    def test_no_address_explains_and_suggests_fixes(self):
        from raven_driver.wifidirect import LinkInfo

        rc, text = self._probe_only(LinkInfo(device="wlp9s0"))
        self.assertEqual(rc, 1)
        self.assertIn("connected but got no address", text)
        self.assertIn("nmcli device disconnect wlp9s0", text)

    def test_link_local_address_is_reported(self):
        from raven_driver.wifidirect import LinkInfo

        rc, text = self._probe_only(LinkInfo(device="wlp9s0", address="169.254.3.4/16"))
        self.assertEqual(rc, 1)
        self.assertIn("fallback address 169.254.3.4/16", text)

    def test_overlap_with_wired_network_stops_with_instructions(self):
        from raven_driver.wifidirect import LinkInfo

        self.clashes = [("enp4s0", "192.168.1.50/24")]
        rc, text = self._probe_only(LinkInfo(device="wlp9s0", address="192.168.1.23/24", gateway="192.168.1.1"))
        self.assertEqual(rc, 1)
        self.assertIn("overlaps another connection: enp4s0 (192.168.1.50/24)", text)
        self.assertIn("nmcli device disconnect enp4s0", text)
        self.assertNotIn("Checking for the scanner", text)

    def test_overlapping_interfaces(self):
        from raven_driver.wifidirect import LinkInfo, overlapping_interfaces, parse_ip_addr

        out = (
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
            "2: enp4s0    inet 192.168.1.50/24 brd 192.168.1.255 scope global enp4s0\n"
            "3: wlp9s0    inet 192.168.1.23/24 brd 192.168.1.255 scope global wlp9s0\n"
        )
        addrs = parse_ip_addr(out)
        self.assertEqual(len(addrs), 3)
        link = LinkInfo(device="wlp9s0", address="192.168.1.23/24")
        self.assertEqual(overlapping_interfaces(link, addrs), [("enp4s0", "192.168.1.50/24")])
        link = LinkInfo(device="wlp9s0", address="192.168.49.2/24")
        self.assertEqual(overlapping_interfaces(link, addrs), [])

    def test_sweeps_subnet_when_usual_addresses_are_silent(self):
        from raven_driver.wifidirect import LinkInfo

        rc, text = self._probe_only(LinkInfo(device="wlp9s0", address="192.168.1.23/24"), hosts=["192.168.1.77"])
        self.assertEqual(rc, 2)
        self.assertIn("Searching the rest of 192.168.1.0/24", text)
        self.assertIn("most likely 192.168.1.77", text)
        self.assertIn("Checking for the scanner at 192.168.1.77", text)


class WifiDirectTests(unittest.TestCase):
    def test_parse_wifi_list_ranks_scanner_first_and_unescapes(self):
        from raven_driver.wifidirect import parse_wifi_list

        out = (
            "*:HomeNet:80:WPA2\n"
            " :DIRECT-7f-Raven Compact:55:WPA2\n"
            " :DIRECT-7f-Raven Compact:40:WPA2\n"
            " :Cafe\\:Guest:90:\n"
            " ::30:WPA2\n"
        )
        nets = parse_wifi_list(out)
        self.assertEqual([n.ssid for n in nets], ["DIRECT-7f-Raven Compact", "Cafe:Guest", "HomeNet"])
        self.assertEqual(nets[0].signal, 55)
        self.assertTrue(nets[2].in_use)

    def test_parse_proc_route(self):
        from raven_driver.wifidirect import parse_proc_route

        text = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "wlan0\t00000000\t0131A8C0\t0003\t0\t0\t600\t00000000\n"
            "wlan0\t0031A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n"
        )
        self.assertEqual(parse_proc_route(text), ["192.168.49.1"])

    def test_scan_without_host_falls_back_to_gateway(self):
        from unittest import mock

        with FakeESCL(pages=1) as fake, tempfile.TemporaryDirectory() as tmp, \
                mock.patch("raven_driver.mdns.browse", return_value=[]), \
                mock.patch("raven_driver.wifidirect.have_nmcli", return_value=False), \
                mock.patch("raven_driver.wifidirect.default_gateways", return_value=["127.0.0.1"]):
            out = Path(tmp) / "doc.pdf"
            rc = main(["scan", "--port", str(fake.port), "-o", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn(b"/Count 1", out.read_bytes())

    def test_direct_probe_only_reports_scanner(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest import mock

        from raven_driver.wifidirect import LinkInfo

        link = LinkInfo(device="wlp9s0", address="127.0.0.5/32", gateway="127.0.0.1")
        with FakeESCL() as fake, mock.patch("raven_driver.wifidirect.wait_for_link", return_value=link), \
                mock.patch.object(LinkInfo, "candidates", return_value=["127.0.0.1"]), \
                mock.patch("raven_driver.wifidirect.overlapping_interfaces", return_value=[]), \
                mock.patch("raven_driver.cli.probe", side_effect=lambda h, **kw: probe(h, extra=[("http", fake.port)])):
            buf = StringIO()
            with redirect_stdout(buf):
                rc = main(["direct", "--probe-only"])
        self.assertEqual(rc, 0)
        self.assertIn("FOUND escl scanner 'Raven Compact' at 127.0.0.1", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
