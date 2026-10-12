"""Tiny HTTP helper on top of http.client (no third-party dependencies)."""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

USER_AGENT = "raven-driver/0.1 (Linux)"


class HTTPFailure(Exception):
    def __init__(self, status: int, reason: str, body: bytes = b"") -> None:
        super().__init__(f"HTTP {status} {reason}")
        self.status = status
        self.reason = reason
        self.body = body


@dataclass
class Response:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)


class Endpoint:
    """A base URL such as ``http://192.168.1.40:80`` plus connection settings."""

    def __init__(self, base_url: str, timeout: float = 30.0, insecure: bool = False) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"unsupported URL scheme in {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.scheme = parts.scheme
        self.host = parts.hostname or ""
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.timeout = timeout
        self.insecure = insecure

    def url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path)

    def _connection(self, host: str, port: int, scheme: str) -> http.client.HTTPConnection:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                # Scanners ship self-signed certificates for their LAN address.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        ok: tuple[int, ...] = (200,),
    ) -> Response:
        target = self.url(path)
        parts = urlsplit(target)
        scheme = parts.scheme
        host = parts.hostname or self.host
        port = parts.port or (443 if scheme == "https" else 80)
        request_path = parts.path or "/"
        if parts.query:
            request_path += "?" + parts.query
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        conn = self._connection(host, port, scheme)
        try:
            conn.request(method, request_path, body=body, headers=hdrs)
            raw = conn.getresponse()
            data = raw.read()
            resp = Response(
                status=raw.status,
                reason=raw.reason,
                headers={k.lower(): v for k, v in raw.getheaders()},
                body=data,
            )
        finally:
            conn.close()
        if ok and resp.status not in ok:
            raise HTTPFailure(resp.status, resp.reason, resp.body)
        return resp
