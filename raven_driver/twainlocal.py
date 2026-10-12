"""TWAIN Local client (the LAN half of the TWAIN Direct specification).

TWAIN Local scanners advertise ``_privet._tcp`` with ``type=twaindirect`` in
their TXT record and expose a small JSON-over-HTTP(S) API:

* ``GET /privet/info`` returns device info and an ``x-privet-token``.
* ``POST`` the ``api`` path (normally ``/privet/twaindirect/session``) with
  ``{"kind": "twainlocalscanner", "method": ...}`` commands: createSession,
  sendTask, startCapturing, waitForEvents/getSession, readImageBlock,
  releaseImageBlocks, stopCapturing and closeSession.

Images arrive as numbered "image blocks", each a multipart/mixed reply that
holds JSON metadata and a slice of a PDF/raster file.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field

from .http import Endpoint, HTTPFailure

KIND = "twainlocalscanner"

PIXEL_FORMATS = {"color": "rgb24", "gray": "gray8", "lineart": "bw1"}
SOURCES = {"auto": "any", "adf": "feederFront", "flatbed": "flatbed"}


class TwainLocalError(Exception):
    pass


def build_task(source: str = "auto", mode: str = "color", resolution: int = 300, duplex: bool = False) -> dict:
    """Build a TWAIN Direct task asking for one stream with our settings."""
    src = "feederDuplex" if duplex and source in ("auto", "adf") else SOURCES.get(source, source)
    return {
        "actions": [
            {
                "action": "configure",
                "streams": [
                    {
                        "sources": [
                            {
                                "source": src,
                                "pixelFormats": [
                                    {
                                        "pixelFormat": PIXEL_FORMATS.get(mode, mode),
                                        "attributes": [
                                            {"attribute": "resolution", "values": [{"value": resolution}]},
                                            {"attribute": "compression", "values": [{"value": "autoVersion1"}]},
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }


def parse_multipart(content_type: str, body: bytes) -> list[tuple[dict[str, str], bytes]]:
    """Split a multipart/mixed body into (headers, payload) pairs."""
    boundary = None
    for piece in content_type.split(";"):
        key, _, value = piece.strip().partition("=")
        if key.lower() == "boundary":
            boundary = value.strip().strip('"')
    if not boundary:
        raise TwainLocalError(f"multipart reply without boundary: {content_type!r}")
    delim = b"--" + boundary.encode("latin-1")
    parts: list[tuple[dict[str, str], bytes]] = []
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        head, sep, payload = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        headers: dict[str, str] = {}
        for line in head.decode("latin-1").split("\r\n"):
            name, colon, value = line.partition(":")
            if colon:
                headers[name.strip().lower()] = value.strip()
        parts.append((headers, payload))
    return parts


@dataclass
class Image:
    number: int
    data: bytes
    content_type: str = "application/pdf"
    metadata: dict = field(default_factory=dict)


class TwainLocalScanner:
    def __init__(self, endpoint: Endpoint, poll_timeout: float = 30.0) -> None:
        self.endpoint = endpoint
        self.poll_timeout = poll_timeout
        self.token = ""
        self.api = "/privet/twaindirect/session"
        self.session_id: str | None = None
        self.revision = 0

    # -- low level -----------------------------------------------------------

    def info(self) -> dict:
        resp = self.endpoint.request("GET", "/privet/info", headers={"X-Privet-Token": ""})
        try:
            info = json.loads(resp.body)
        except ValueError as exc:
            raise TwainLocalError(f"/privet/info did not return JSON: {exc}") from exc
        self.token = info.get("x-privet-token", "")
        for api in info.get("api", []):
            if "twaindirect" in api:
                self.api = api
        return info

    def command(self, method: str, **params) -> tuple[dict, list[tuple[dict[str, str], bytes]]]:
        """Run one session command. Returns (results, extra multipart parts)."""
        if not self.token:
            self.info()
        if self.session_id and "sessionId" not in params:
            params["sessionId"] = self.session_id
        payload = {"kind": KIND, "commandId": str(uuid.uuid4()), "method": method}
        if params:
            payload["params"] = params
        try:
            resp = self.endpoint.request(
                "POST",
                self.api,
                body=json.dumps(payload).encode("utf-8"),
                headers={"X-Privet-Token": self.token, "Content-Type": "application/json; charset=UTF-8"},
            )
        except HTTPFailure as exc:
            raise TwainLocalError(f"{method} failed: {exc}") from exc
        ctype = resp.header("content-type", "") or ""
        extra: list[tuple[dict[str, str], bytes]] = []
        if ctype.lower().startswith("multipart/"):
            parts = parse_multipart(ctype, resp.body)
            if not parts:
                raise TwainLocalError(f"{method}: empty multipart reply")
            body = parts[0][1]
            extra = parts[1:]
        else:
            body = resp.body
        try:
            reply = json.loads(body)
        except ValueError as exc:
            raise TwainLocalError(f"{method}: reply is not JSON: {exc}") from exc
        results = reply.get("results", {})
        if not results.get("success", False):
            code = results.get("code", "unknown")
            raise TwainLocalError(f"{method} rejected by scanner: {code}")
        session = results.get("session")
        if session:
            self.session_id = session.get("sessionId", self.session_id)
            self.revision = max(self.revision, int(session.get("revision", 0)))
        return results, extra

    # -- high level ----------------------------------------------------------

    def open(self) -> dict:
        results, _ = self.command("createSession")
        return results.get("session", {})

    def close(self) -> None:
        if not self.session_id:
            return
        try:
            self.command("closeSession")
        except (TwainLocalError, OSError):
            pass
        finally:
            self.session_id = None

    def _session_state(self) -> dict:
        try:
            results, _ = self.command("waitForEvents", sessionRevision=self.revision)
            events = results.get("events", [])
            if events:
                return events[-1].get("session", {})
            return results.get("session", {})
        except TwainLocalError:
            # Not every scanner implements long-polling; fall back to polling.
            time.sleep(0.5)
            results, _ = self.command("getSession")
            return results.get("session", {})

    def scan(self, source="auto", mode="color", resolution=300, duplex=False):
        """Yield completed Image objects as the scanner produces them."""
        self.open()
        try:
            self.command("sendTask", task=build_task(source, mode, resolution, duplex))
            self.command("startCapturing")
            pending: dict[int, list[bytes]] = {}
            seen: set[int] = set()
            deadline = time.monotonic() + self.poll_timeout
            while True:
                session = self._session_state()
                blocks = [b for b in session.get("imageBlocks", []) if b not in seen]
                if blocks:
                    deadline = time.monotonic() + self.poll_timeout
                for block in sorted(blocks):
                    image = self._read_block(block, pending)
                    seen.add(block)
                    self.command("releaseImageBlocks", imageBlockNum=block, lastImageBlockNum=block)
                    if image is not None:
                        yield image
                drained = session.get("imageBlocksDrained") or session.get("state") in ("ready", "closed")
                if drained and not blocks and seen:
                    break
                if session.get("doneCapturing") and session.get("imageBlocksDrained"):
                    break
                if time.monotonic() > deadline:
                    if not seen:
                        raise TwainLocalError("no images arrived; is there paper in the feeder?")
                    break
            try:
                self.command("stopCapturing")
            except TwainLocalError:
                pass
        finally:
            self.close()

    def _read_block(self, block: int, pending: dict[int, list[bytes]]) -> Image | None:
        results, parts = self.command("readImageBlock", imageBlockNum=block, withMetadata=True)
        metadata = results.get("metadata", {})
        address = metadata.get("address", {})
        number = int(address.get("imageNumber", block))
        data = b"".join(p for _, p in parts)
        ctype = parts[0][0].get("content-type", "application/pdf") if parts else "application/pdf"
        pending.setdefault(number, []).append(data)
        more = str(address.get("moreParts", "lastPartInFile"))
        if more.startswith("lastPartInFile"):
            return Image(number, b"".join(pending.pop(number)), ctype, metadata)
        return None
