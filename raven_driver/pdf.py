"""Combine JPEG pages into one PDF without third-party libraries."""

from __future__ import annotations

import struct


class NotJPEG(ValueError):
    pass


def jpeg_info(data: bytes) -> tuple[int, int, int, tuple[int, int] | None]:
    """Return (width, height, components, dpi_or_None) for a baseline/progressive JPEG."""
    if data[:2] != b"\xff\xd8":
        raise NotJPEG("not a JPEG")
    i = 2
    dpi = None
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        (length,) = struct.unpack(">H", data[i + 2 : i + 4])
        seg = data[i + 4 : i + 2 + length]
        if marker == 0xE0 and seg[:5] == b"JFIF\x00" and len(seg) >= 12:
            units = seg[7]
            xd, yd = struct.unpack(">HH", seg[8:12])
            if units == 1 and xd and yd:
                dpi = (xd, yd)
            elif units == 2 and xd and yd:
                dpi = (round(xd * 2.54), round(yd * 2.54))
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            height, width = struct.unpack(">HH", seg[1:5])
            return width, height, seg[5], dpi
        i += 2 + length
    raise NotJPEG("no SOF marker found")


def jpegs_to_pdf(pages: list[bytes], fallback_dpi: int = 300) -> bytes:
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    catalog = add(b"")  # placeholder, filled below
    pages_obj = add(b"")
    page_ids = []
    for jpeg in pages:
        width, height, comps, dpi = jpeg_info(jpeg)
        xdpi, ydpi = dpi or (fallback_dpi, fallback_dpi)
        pw = width * 72.0 / xdpi
        ph = height * 72.0 / ydpi
        colorspace = {1: b"/DeviceGray", 4: b"/DeviceCMYK"}.get(comps, b"/DeviceRGB")
        img = add(
            b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace %s "
            b"/BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n"
            % (width, height, colorspace, len(jpeg))
            + jpeg
            + b"\nendstream"
        )
        content = b"q %.3f 0 0 %.3f 0 0 cm /Im0 Do Q" % (pw, ph)
        cs = add(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
        page = add(
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.3f %.3f] "
            b"/Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>"
            % (pages_obj, pw, ph, img, cs)
        )
        page_ids.append(page)
    objects[catalog - 1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pages_obj
    kids = b" ".join(b"%d 0 R" % p for p in page_ids)
    objects[pages_obj - 1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_ids))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        catalog,
        xref,
    )
    return bytes(out)
