"""Map a scanner's private web interface so its protocol can be supported.

Read-only: it only sends GET requests and reads the SSH greeting. It fetches
the home page, follows links and script references on the same host, tries
paths that scanners commonly use, and saves every response to a folder. The
printed summary is short enough to paste into an issue or chat.
"""

from __future__ import annotations

import json
import re
import socket
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .http import Endpoint

COMMON_PATHS = (
    "/",
    "/index.html",
    "/index.htm",
    "/index.cgi",
    "/index.php",
    "/home.html",
    "/main.html",
    "/default.html",
    "/robots.txt",
    "/eSCL/ScannerCapabilities",
    "/escl/ScannerCapabilities",
    "/eSCL/ScannerStatus",
    "/privet/info",
    "/info",
    "/status",
    "/device",
    "/deviceinfo",
    "/version",
    "/api",
    "/api/v1",
    "/api/status",
    "/api/info",
    "/api/device",
    "/api/scanner",
    "/scan",
    "/scanner",
    "/scanner/status",
    "/scan/status",
    "/twain",
    "/rest",
    "/json",
    "/config",
    "/settings",
    "/cgi-bin/",
    "/cgi-bin/status.cgi",
    "/cgi-bin/info.cgi",
    "/cgi-bin/index.cgi",
    "/cgi-bin/main.cgi",
    "/DevMgmt/ScanCaps.xml",
    "/WebServices/ScannerService",
)

# Quoted absolute paths inside HTML, JS and JSON, e.g. "/api/v1/scan".
PATH_IN_TEXT = re.compile(r"""["'`](/[A-Za-z0-9_\-./]*[A-Za-z0-9_\-/](?:\?[^"'`\s<>]*)?)["'`]""")
ATTR_LINK = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
# <meta http-equiv="refresh" content="0; url=main.html">
META_REFRESH = re.compile(r"""content\s*=\s*["']\s*\d+\s*;\s*url\s*=\s*['"]?([^"'>\s]+)""", re.IGNORECASE)
# location.href = "x", window.location = 'x', location.replace("x"), frames: <frame src=x>
JS_REDIRECT = re.compile(
    r"""location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
# Words that make a response worth a human's attention.
INTERESTING = re.compile(r"scan|resolution|duplex|adf|feeder|dpi|jpeg|pdf|twain|page|paper|job", re.IGNORECASE)

# Never fetch anything that looks like it changes the device. Some embedded
# web servers act on plain GETs, so these are listed but not requested.
UNSAFE = re.compile(
    r"reboot|restart|reset|factory|shutdown|power.?off|delete|remove|erase|wipe|format|"
    r"upgrade|update|firmware|flash|logout|log.?off|save|apply|set[_-]|/set\b|write|"
    r"commit|install|unpair|forget|clear|start|stop|cancel|create|submit|login",
    re.IGNORECASE,
)

# Command names used by CGI-driven admin apps, e.g. WiFiDriveCtrl.cgi?...&cmd_get_lang
CGI_COMMAND = re.compile(r"\bcmd_[A-Za-z0-9_]+")

TEXT_TYPES = ("text/", "json", "xml", "javascript", "ecmascript")
MAX_BODY = 2 * 1024 * 1024


@dataclass
class Hit:
    url: str
    status: int
    content_type: str
    size: int
    saved_as: str = ""
    found_via: str = ""
    keywords: list[str] = field(default_factory=list)
    preview: str = ""  # whole body, for short text pages
    auth: str = ""  # WWW-Authenticate challenge on a 401, e.g. Basic realm="..."


@dataclass
class Exploration:
    host: str
    ssh_banner: str = ""
    open_ports: list[int] = field(default_factory=list)
    server_headers: list[str] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    paths_seen_in_code: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_unsafe: list[str] = field(default_factory=list)
    cgi_commands: list[str] = field(default_factory=list)


def ssh_banner(host: str, port: int = 22, timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(256).decode("latin-1", "replace").strip()
    except OSError:
        return ""


def extract_links(base_url: str, body: str) -> list[str]:
    """Same-host paths referenced from an HTML/JS/JSON body."""
    found: list[str] = []
    host = urlsplit(base_url).netloc
    redirects = [a or b for a, b in JS_REDIRECT.findall(body)]
    for raw in META_REFRESH.findall(body) + redirects + ATTR_LINK.findall(body) + PATH_IN_TEXT.findall(body):
        raw = raw.strip()
        if raw.startswith(("javascript:", "mailto:", "data:", "//")):
            continue
        url = urljoin(base_url, raw)
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or parts.netloc != host:
            continue
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if path not in found:
            found.append(path)
    return found


def _safe_name(path: str, n: int, ctype: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.strip("/")) or "index"
    ext = ""
    if "." not in stem.rsplit("_", 1)[-1]:
        ext = {"json": ".json", "xml": ".xml", "html": ".html", "javascript": ".js"}.get(
            next((k for k in ("json", "xml", "html", "javascript") if k in ctype), ""), ".txt"
        )
    return f"{n:03d}_{stem[:80]}{ext}"


def explore(host: str, port: int = 80, scheme: str = "http", out_dir: Path | None = None,
            max_requests: int = 80, timeout: float = 5.0) -> Exploration:
    from .probe import scan_ports

    result = Exploration(host=host, ssh_banner=ssh_banner(host), open_ports=scan_ports(host))
    base = f"{scheme}://{host}:{port}"
    endpoint = Endpoint(base, timeout=timeout, insecure=True)
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    queue: deque[tuple[str, str]] = deque((p, "common path") for p in COMMON_PATHS)
    seen: set[str] = set()
    code_paths: list[str] = []
    while queue and len(seen) < max_requests:
        path, via = queue.popleft()
        if path in seen:
            continue
        seen.add(path)
        if via != "common path" and UNSAFE.search(path):
            result.skipped_unsafe.append(path)
            continue
        try:
            resp = endpoint.request("GET", path, ok=())
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            continue
        ctype = (resp.header("content-type", "") or "").lower()
        server = resp.header("server", "")
        if server and server not in result.server_headers:
            result.server_headers.append(server)
        if resp.status == 404:
            continue
        body = resp.body[:MAX_BODY]
        hit = Hit(url=path, status=resp.status, content_type=ctype, size=len(resp.body), found_via=via,
                  auth=resp.header("www-authenticate", "") or "")
        is_text = any(t in ctype for t in TEXT_TYPES) or (not ctype and body[:1] in (b"{", b"<", b"["))
        if is_text:
            text = body.decode("utf-8", "replace")
            hit.keywords = sorted({m.lower() for m in INTERESTING.findall(text)})
            if len(body) <= 400:
                hit.preview = " ".join(text.split())
            for link in extract_links(endpoint.url(path), text):
                if link not in code_paths:
                    code_paths.append(link)
                if link not in seen:
                    queue.append((link, f"linked from {path}"))
            for name in CGI_COMMAND.findall(text):
                if name not in result.cgi_commands:
                    result.cgi_commands.append(name)
                    # Read-only "get" commands are fetched through any CGI
                    # URL we have already seen carry a command.
                    if name.startswith("cmd_get_"):
                        for known in list(seen) + [p for p, _ in queue]:
                            m = re.match(r"(.*[?&])cmd_[A-Za-z0-9_]+(.*)$", known)
                            if m:
                                queue.append((m.group(1) + name + m.group(2), f"command named in {path}"))
                                break
        if out_dir:
            hit.saved_as = _safe_name(path, len(result.hits) + 1, ctype)
            (out_dir / hit.saved_as).write_bytes(body)
        result.hits.append(hit)
    result.paths_seen_in_code = code_paths
    if out_dir:
        (out_dir / "summary.json").write_text(json.dumps(asdict(result), indent=2))
    return result


def summarize(result: Exploration, limit: int = 40) -> str:
    lines = [f"Scanner {result.host}"]
    if result.ssh_banner:
        lines.append(f"  ssh: {result.ssh_banner}")
    if result.open_ports:
        lines.append(f"  open ports: {', '.join(map(str, result.open_ports))}")
    if result.server_headers:
        lines.append(f"  web server: {', '.join(result.server_headers)}")
    lines.append(f"  pages that answered: {len(result.hits)}")
    ranked = sorted(result.hits, key=lambda h: (h.status >= 400, not h.keywords, h.url))
    for h in ranked[:limit]:
        kw = f"  [{', '.join(h.keywords)}]" if h.keywords else ""
        lines.append(f"  {h.status} {h.url}  {h.content_type or '?'} {h.size}B{kw}")
        if h.auth:
            lines.append(f"      password prompt: {h.auth}")
        elif h.preview:
            lines.append(f"      | {h.preview[:400]}")
    if result.cgi_commands:
        lines.append(f"  commands named in the scanner's scripts ({len(result.cgi_commands)}):")
        for i in range(0, len(result.cgi_commands), 4):
            lines.append("    " + "  ".join(result.cgi_commands[i : i + 4]))
    if result.skipped_unsafe:
        lines.append("  not fetched because they may change the scanner:")
        for p in result.skipped_unsafe[:limit]:
            lines.append(f"    {p}")
    extra = [
        p for p in result.paths_seen_in_code
        if p not in {h.url for h in result.hits} and p not in result.skipped_unsafe
    ]
    if extra:
        lines.append("  paths mentioned in the scanner's code but not fetched:")
        for p in extra[:limit]:
            lines.append(f"    {p}")
    return "\n".join(lines)


@dataclass
class PortGreeting:
    port: int
    kind: str  # "http", "telnet", "silent", "binary", "text", "closed"
    text: str = ""
    hex: str = ""
    replied_to_http: bool = False


def strip_telnet(data: bytes) -> bytes:
    """Remove telnet IAC negotiation sequences (FF xx yy / FF FA ... FF F0)."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0xFF and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == 0xFF:
                out.append(0xFF)
                i += 2
            elif cmd == 0xFA:
                end = data.find(b"\xff\xf0", i + 2)
                i = len(data) if end < 0 else end + 2
            elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):
                i += 3
            else:
                i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


def _printable(data: bytes) -> str:
    text = data.decode("latin-1")
    return "".join(c if c.isprintable() or c in "\n\t" else "." for c in text).strip()


def _recv_for(sock: socket.socket, seconds: float) -> bytes:
    sock.settimeout(seconds)
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 4096:
                break
            sock.settimeout(0.5)
    except OSError:
        pass
    return b"".join(chunks)


def port_greeting(host: str, port: int, timeout: float = 3.0) -> PortGreeting:
    """Read what a TCP port says on connect. If it says nothing, send one
    harmless HTTP GET to see whether it is a web server. Never logs in."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return PortGreeting(port, "closed")
    with sock:
        data = _recv_for(sock, timeout)
        replied = False
        if not data:
            try:
                sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = _recv_for(sock, timeout)
                replied = bool(data)
            except OSError:
                data = b""
    if not data:
        return PortGreeting(port, "silent")
    if data.startswith(b"HTTP/"):
        kind = "http"
        clean = data
    elif data[:1] == b"\xff":
        kind = "telnet"
        clean = strip_telnet(data)
    else:
        clean = data
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:256])
        kind = "text" if printable >= 0.9 * min(len(data), 256) else "binary"
    return PortGreeting(port, kind, text=_printable(clean)[:600], hex=data[:64].hex(" "), replied_to_http=replied)


def summarize_greetings(greetings: list[PortGreeting]) -> str:
    lines = ["Other ports"]
    for g in greetings:
        how = " (after an HTTP request)" if g.replied_to_http else ""
        lines.append(f"  {g.port}: {g.kind}{how}")
        if g.text:
            for row in g.text.splitlines()[:12]:
                lines.append(f"      | {row}")
        if g.kind == "binary" and g.hex:
            lines.append(f"      hex: {g.hex}")
    return "\n".join(lines)
