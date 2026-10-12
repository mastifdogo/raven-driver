"""eSCL ("AirScan") client.

eSCL is the HTTP + XML scanning protocol behind Apple AirScan and Mopria
scanning. Flow:

1. ``GET  {root}/ScannerCapabilities`` describes sources, modes, resolutions.
2. ``POST {root}/ScanJobs`` with ScanSettings XML; the reply's ``Location``
   header names the job.
3. ``GET  {job}/NextDocument`` repeatedly; each 200 is one page, 404 means
   the feeder is empty, 503 means "busy, try again".
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from .http import Endpoint, HTTPFailure

NS = {
    "scan": "http://schemas.hp.com/imaging/escl/2011/05/03",
    "pwg": "http://www.pwg.org/schemas/2010/12/sm",
}

COLOR_MODES = {"color": "RGB24", "gray": "Grayscale8", "lineart": "BlackAndWhite1"}

# Page sizes in 1/300 inch.
PAGE_SIZES = {
    "letter": (2550, 3300),
    "legal": (2550, 4200),
    "a4": (2480, 3508),
    "a5": (1748, 2480),
    "a6": (1240, 1748),
    "b5": (2079, 2953),
    "card": (1050, 600),
}


class ESCLError(Exception):
    pass


@dataclass
class SourceCaps:
    name: str  # "Platen", "Feeder"
    color_modes: list[str] = field(default_factory=list)
    resolutions: list[int] = field(default_factory=list)
    formats: list[str] = field(default_factory=list)
    max_width: int | None = None
    max_height: int | None = None


@dataclass
class Capabilities:
    make_and_model: str = ""
    serial: str = ""
    version: str = "2.0"
    sources: dict[str, SourceCaps] = field(default_factory=dict)
    duplex: bool = False

    def source(self, wanted: str) -> SourceCaps:
        key = {"flatbed": "Platen", "platen": "Platen", "adf": "Feeder", "feeder": "Feeder"}.get(
            wanted.lower(), wanted
        )
        if key in self.sources:
            return self.sources[key]
        if wanted.lower() == "auto" and self.sources:
            return self.sources.get("Feeder") or next(iter(self.sources.values()))
        raise ESCLError(f"scanner has no {wanted!r} source; it offers {sorted(self.sources)}")


def _text(el: ET.Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path, NS)
    return found.text.strip() if found is not None and found.text else default


def _input_caps(el: ET.Element, name: str) -> SourceCaps:
    caps = SourceCaps(name=name)
    w = _text(el, "scan:MaxWidth")
    h = _text(el, "scan:MaxHeight")
    caps.max_width = int(w) if w.isdigit() else None
    caps.max_height = int(h) if h.isdigit() else None
    for profile in el.iterfind("scan:SettingProfiles/scan:SettingProfile", NS):
        for cm in profile.iterfind("scan:ColorModes/scan:ColorMode", NS):
            if cm.text and cm.text.strip() not in caps.color_modes:
                caps.color_modes.append(cm.text.strip())
        for fmt in profile.iterfind("scan:DocumentFormats/pwg:DocumentFormat", NS):
            if fmt.text and fmt.text.strip() not in caps.formats:
                caps.formats.append(fmt.text.strip())
        for fmt in profile.iterfind("scan:DocumentFormats/scan:DocumentFormatExt", NS):
            if fmt.text and fmt.text.strip() not in caps.formats:
                caps.formats.append(fmt.text.strip())
        for res in profile.iterfind(
            "scan:SupportedResolutions/scan:DiscreteResolutions/scan:DiscreteResolution", NS
        ):
            x = _text(res, "scan:XResolution")
            if x.isdigit() and int(x) not in caps.resolutions:
                caps.resolutions.append(int(x))
        rng = profile.find("scan:SupportedResolutions/scan:ResolutionRange", NS)
        if rng is not None:
            lo = _text(rng, "scan:XResolutionRange/scan:Min")
            hi = _text(rng, "scan:XResolutionRange/scan:Max")
            if lo.isdigit() and hi.isdigit():
                for r in (75, 100, 150, 200, 300, 400, 600, 1200):
                    if int(lo) <= r <= int(hi) and r not in caps.resolutions:
                        caps.resolutions.append(r)
    caps.resolutions.sort()
    return caps


def parse_capabilities(xml_bytes: bytes) -> Capabilities:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ESCLError(f"bad ScannerCapabilities XML: {exc}") from exc
    caps = Capabilities(
        make_and_model=_text(root, "pwg:MakeAndModel"),
        serial=_text(root, "pwg:SerialNumber"),
        version=_text(root, "pwg:Version", "2.0"),
    )
    platen = root.find("scan:Platen/scan:PlatenInputCaps", NS)
    if platen is not None:
        caps.sources["Platen"] = _input_caps(platen, "Platen")
    adf = root.find("scan:Adf", NS)
    if adf is not None:
        simplex = adf.find("scan:AdfSimplexInputCaps", NS)
        duplex = adf.find("scan:AdfDuplexInputCaps", NS)
        if simplex is not None:
            caps.sources["Feeder"] = _input_caps(simplex, "Feeder")
        elif duplex is not None:
            caps.sources["Feeder"] = _input_caps(duplex, "Feeder")
        caps.duplex = duplex is not None or any(
            (o.text or "").strip() == "Duplex" for o in adf.iterfind("scan:AdfOptions/scan:AdfOption", NS)
        )
    return caps


@dataclass
class ScanRequest:
    source: str = "auto"  # auto | adf | flatbed
    mode: str = "color"  # color | gray | lineart
    resolution: int = 300
    duplex: bool = False
    page_size: str = "letter"
    document_format: str = "image/jpeg"


def build_scan_settings(req: ScanRequest, caps: Capabilities) -> str:
    src = caps.source(req.source)
    color = COLOR_MODES.get(req.mode, req.mode)
    if src.color_modes and color not in src.color_modes:
        raise ESCLError(f"color mode {color} not supported by {src.name}; choose from {src.color_modes}")
    resolution = req.resolution
    if src.resolutions and resolution not in src.resolutions:
        # Snap to the closest supported resolution rather than failing;
        # on a tie prefer the sharper one.
        resolution = min(src.resolutions, key=lambda r: (abs(r - req.resolution), -r))
    width, height = PAGE_SIZES.get(req.page_size.lower(), PAGE_SIZES["letter"])
    if src.max_width:
        width = min(width, src.max_width)
    if src.max_height:
        height = min(height, src.max_height)
    fmt = req.document_format
    if src.formats and fmt not in src.formats:
        fmt = "image/jpeg" if "image/jpeg" in src.formats else src.formats[0]
    duplex = ""
    if src.name == "Feeder" and caps.duplex:
        duplex = f"\n  <scan:Duplex>{'true' if req.duplex else 'false'}</scan:Duplex>"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<scan:ScanSettings xmlns:scan="{NS['scan']}" xmlns:pwg="{NS['pwg']}">
  <pwg:Version>{escape(caps.version or '2.0')}</pwg:Version>
  <scan:Intent>Document</scan:Intent>
  <pwg:ScanRegions>
    <pwg:ScanRegion>
      <pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>
      <pwg:XOffset>0</pwg:XOffset>
      <pwg:YOffset>0</pwg:YOffset>
      <pwg:Width>{width}</pwg:Width>
      <pwg:Height>{height}</pwg:Height>
    </pwg:ScanRegion>
  </pwg:ScanRegions>
  <pwg:InputSource>{src.name}</pwg:InputSource>{duplex}
  <scan:ColorMode>{escape(color)}</scan:ColorMode>
  <scan:XResolution>{resolution}</scan:XResolution>
  <scan:YResolution>{resolution}</scan:YResolution>
  <pwg:DocumentFormat>{escape(fmt)}</pwg:DocumentFormat>
  <scan:DocumentFormatExt>{escape(fmt)}</scan:DocumentFormatExt>
</scan:ScanSettings>
"""


@dataclass
class Page:
    data: bytes
    content_type: str


class ESCLScanner:
    def __init__(self, endpoint: Endpoint, root: str = "eSCL") -> None:
        self.endpoint = endpoint
        self.root = "/" + root.strip("/")

    def capabilities(self) -> Capabilities:
        resp = self.endpoint.request("GET", f"{self.root}/ScannerCapabilities")
        return parse_capabilities(resp.body)

    def status(self) -> str:
        resp = self.endpoint.request("GET", f"{self.root}/ScannerStatus")
        try:
            root = ET.fromstring(resp.body)
        except ET.ParseError:
            return "Unknown"
        return _text(root, "pwg:State", "Unknown")

    def scan(self, req: ScanRequest, caps: Capabilities | None = None, busy_timeout: float = 60.0):
        """Yield Page objects until the scanner reports no more documents."""
        caps = caps or self.capabilities()
        settings = build_scan_settings(req, caps).encode("utf-8")
        job_url = self._create_job(settings, busy_timeout)
        try:
            while True:
                page = self._next_document(job_url, busy_timeout)
                if page is None:
                    return
                yield page
                if caps.source(req.source).name == "Platen":
                    return  # flatbed gives exactly one page
        finally:
            try:
                self.endpoint.request("DELETE", job_url, ok=())
            except OSError:
                pass

    def _create_job(self, settings: bytes, busy_timeout: float) -> str:
        deadline = time.monotonic() + busy_timeout
        while True:
            try:
                resp = self.endpoint.request(
                    "POST",
                    f"{self.root}/ScanJobs",
                    body=settings,
                    headers={"Content-Type": "text/xml"},
                    ok=(200, 201),
                )
            except HTTPFailure as exc:
                if exc.status == 503 and time.monotonic() < deadline:
                    time.sleep(1.0)
                    continue
                raise ESCLError(f"scanner refused the scan job: {exc}") from exc
            location = resp.header("location")
            if not location:
                raise ESCLError("scanner accepted the job but sent no Location header")
            return location.rstrip("/")

    def _next_document(self, job_url: str, busy_timeout: float) -> Page | None:
        deadline = time.monotonic() + busy_timeout
        while True:
            try:
                resp = self.endpoint.request("GET", f"{job_url}/NextDocument")
            except HTTPFailure as exc:
                if exc.status == 404:
                    return None
                if exc.status == 503 and time.monotonic() < deadline:
                    time.sleep(0.5)
                    continue
                if exc.status == 409:
                    raise ESCLError("scanner reports a conflict (paper jam or empty feeder?)") from exc
                raise ESCLError(f"failed to fetch page: {exc}") from exc
            return Page(resp.body, resp.header("content-type", "application/octet-stream") or "")
