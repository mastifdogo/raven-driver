"""Simulated scanners for tests: an eSCL device and a TWAIN Local device."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 85x110 px red JPEG, 10 dpi, so a PDF page is 8.5 x 11 inches.
TINY_JPEG = base64.b64decode("/9j/4AAQSkZJRgABAQEACgAKAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCABuAFUDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDkKKKK8U/TAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/9k=")

CAPS_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<scan:ScannerCapabilities xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03"
    xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm">
  <pwg:Version>2.63</pwg:Version>
  <pwg:MakeAndModel>Raven Compact</pwg:MakeAndModel>
  <pwg:SerialNumber>RC123</pwg:SerialNumber>
  <scan:Adf>
    <scan:AdfSimplexInputCaps>
      <scan:MaxWidth>2550</scan:MaxWidth>
      <scan:MaxHeight>4200</scan:MaxHeight>
      <scan:SettingProfiles><scan:SettingProfile>
        <scan:ColorModes>
          <scan:ColorMode>RGB24</scan:ColorMode>
          <scan:ColorMode>Grayscale8</scan:ColorMode>
        </scan:ColorModes>
        <scan:DocumentFormats>
          <pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>
          <pwg:DocumentFormat>application/pdf</pwg:DocumentFormat>
        </scan:DocumentFormats>
        <scan:SupportedResolutions><scan:DiscreteResolutions>
          <scan:DiscreteResolution><scan:XResolution>200</scan:XResolution><scan:YResolution>200</scan:YResolution></scan:DiscreteResolution>
          <scan:DiscreteResolution><scan:XResolution>300</scan:XResolution><scan:YResolution>300</scan:YResolution></scan:DiscreteResolution>
          <scan:DiscreteResolution><scan:XResolution>600</scan:XResolution><scan:YResolution>600</scan:YResolution></scan:DiscreteResolution>
        </scan:DiscreteResolutions></scan:SupportedResolutions>
      </scan:SettingProfile></scan:SettingProfiles>
    </scan:AdfSimplexInputCaps>
    <scan:AdfOptions><scan:AdfOption>Duplex</scan:AdfOption></scan:AdfOptions>
  </scan:Adf>
</scan:ScannerCapabilities>
"""


class _Server:
    handler: type

    def __init__(self) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.httpd.owner = self  # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def send(self, status, body=b"", ctype="text/plain", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


class _ESCLHandler(_Quiet):
    def do_GET(self):
        owner = self.server.owner
        if self.path == "/eSCL/ScannerCapabilities":
            return self.send(200, CAPS_XML, "text/xml")
        if self.path == "/eSCL/ScanJobs/1/NextDocument":
            if owner.busy_once:
                owner.busy_once = False
                return self.send(503)
            if owner.pages_left > 0:
                owner.pages_left -= 1
                return self.send(200, TINY_JPEG, "image/jpeg")
            return self.send(404)
        self.send(404)

    def do_POST(self):
        owner = self.server.owner
        length = int(self.headers.get("Content-Length", 0))
        owner.settings = self.rfile.read(length).decode()
        self.send(201, headers={"Location": f"http://127.0.0.1:{owner.port}/eSCL/ScanJobs/1"})

    def do_DELETE(self):
        self.server.owner.deleted = True
        self.send(200)


class FakeESCL(_Server):
    handler = _ESCLHandler

    def __init__(self, pages: int = 2) -> None:
        super().__init__()
        self.pages_left = pages
        self.busy_once = True
        self.settings = ""
        self.deleted = False


class _TwainHandler(_Quiet):
    def do_GET(self):
        if self.path == "/privet/info":
            if "X-Privet-Token" not in self.headers:
                return self.send(400)
            info = {
                "version": "1.0",
                "name": "Raven Compact",
                "manufacturer": "Raven",
                "model": "Compact",
                "type": ["twaindirect"],
                "x-privet-token": "tok123",
                "api": ["/privet/twaindirect/session"],
            }
            return self.send(200, json.dumps(info).encode(), "application/json")
        self.send(404)

    def do_POST(self):
        owner = self.server.owner
        if self.headers.get("X-Privet-Token") != "tok123":
            return self.send(400, b'{"error":"invalid_x_privet_token"}', "application/json")
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = req["method"]
        owner.calls.append(method)
        params = req.get("params", {})
        if method != "createSession" and params.get("sessionId") != "S1":
            return self._reply(req, {"success": False, "code": "invalidSessionId"})
        if method == "sendTask":
            owner.task = params["task"]
        if method == "startCapturing":
            owner.capturing = True
        if method == "releaseImageBlocks":
            owner.released.append(params["imageBlockNum"])
        if method == "readImageBlock":
            return self._image_block(req, params["imageBlockNum"])
        if method == "waitForEvents":
            return self._reply(req, {"success": False, "code": "notImplemented"})
        self._reply(req, {"success": True, "session": self._session()})

    def _session(self):
        owner = self.server.owner
        blocks = [b for b in (1, 2, 3) if owner.capturing and b not in owner.released]
        owner.revision += 1
        return {
            "sessionId": "S1",
            "revision": owner.revision,
            "state": "capturing" if blocks else "ready",
            "imageBlocks": blocks,
            "imageBlocksDrained": owner.capturing and not blocks,
            "doneCapturing": owner.capturing,
        }

    def _reply(self, req, results):
        body = {"kind": "twainlocalscanner", "commandId": req["commandId"], "method": req["method"], "results": results}
        self.send(200, json.dumps(body).encode(), "application/json")

    def _image_block(self, req, block):
        # Image 1 spans blocks 1 and 2; image 2 is block 3.
        address = {
            1: {"imageNumber": 1, "imagePart": 1, "moreParts": "morePartsPending"},
            2: {"imageNumber": 1, "imagePart": 2, "moreParts": "lastPartInFile"},
            3: {"imageNumber": 2, "imagePart": 1, "moreParts": "lastPartInFile"},
        }[block]
        payload = {1: b"%PDF-1.4 part-a ", 2: b"part-b %%EOF", 3: b"%PDF-1.4 second %%EOF"}[block]
        meta = {
            "kind": "twainlocalscanner",
            "commandId": req["commandId"],
            "method": "readImageBlock",
            "results": {"success": True, "session": self._session(), "metadata": {"address": address}},
        }
        boundary = "BOUNDARYxyz"
        body = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode()
            + json.dumps(meta).encode()
            + f"\r\n--{boundary}\r\nContent-Type: application/pdf\r\n\r\n".encode()
            + payload
            + f"\r\n--{boundary}--\r\n".encode()
        )
        self.send(200, body, f"multipart/mixed; boundary={boundary}")


class FakeTwainLocal(_Server):
    handler = _TwainHandler

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []
        self.released: list[int] = []
        self.capturing = False
        self.revision = 0
        self.task = None
