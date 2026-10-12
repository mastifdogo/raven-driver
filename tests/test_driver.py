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

from tests.fakes import CAPS_XML, TINY_JPEG, FakeESCL, FakeTwainLocal


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


if __name__ == "__main__":
    unittest.main()
