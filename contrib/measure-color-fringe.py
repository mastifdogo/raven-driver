#!/usr/bin/env python3
"""Measure colour misregistration in a colour scan of a black-and-white page.

Usage:
  contrib/measure-color-fringe.py SCAN.pnm
  contrib/measure-color-fringe.py SCAN.pnm --save --resolution 300 [-o FILE]

Reads a binary PPM (P6, as `scanimage --mode Color --format=pnm` writes),
and finds the shift, in fractions of a pixel, that best lines the red and
blue channels up with green: across the feed direction (down the page) and
along it (across the page). Make the scan with the fringe correction off
(RAVEN_FRINGE=off) and of a page with plenty of black text or lines.

To judge a corrected scan, compare the share of visibly coloured pixels
with an uncorrected scan of the same page: the offsets themselves read a
little high on corrected thin lines.

--save stores the down-the-page offsets for that resolution in the profile
the patched avision backend reads (~/.config/raven-driver/fringe.txt),
replacing any earlier entry for the same resolution.
Only the Python standard library is used.
"""

import argparse
import os
import sys


def read_ppm(path):
    with open(path, "rb") as f:
        data = f.read()
    fields, pos = [], 0
    while len(fields) < 4:
        while data[pos : pos + 1].isspace():
            pos += 1
        if data[pos : pos + 1] == b"#":
            pos = data.index(b"\n", pos) + 1
            continue
        end = pos
        while not data[end : end + 1].isspace():
            end += 1
        fields.append(data[pos:end])
        pos = end
    if fields[0] != b"P6" or int(fields[3]) != 255:
        sys.exit(f"{path}: need an 8-bit colour PPM (scanimage --mode Color --format=pnm)")
    return int(fields[1]), int(fields[2]), data[pos + 1 :]


def lines_of(px, width, height, down):
    """Yield (red, green, blue) sequences: columns if down, else rows."""
    stride = width * 3
    if down:
        step = max(1, width // 400)
        for x in range(0, width, step):
            yield tuple(px[x * 3 + c :: stride] for c in range(3))
    else:
        step = max(1, height // 400)
        for y in range(0, height, step):
            row = px[y * stride : (y + 1) * stride]
            yield tuple(row[c::3] for c in range(3))


def edge_samples(lines, threshold=30, limit=80000):
    """Positions near sharp green edges, as (red, green, blue, index) tuples."""
    picked = []
    for r, g, b in lines:
        n = len(g)
        for i in range(2, n - 3):
            if abs(g[i + 1] - g[i - 1]) >= threshold:
                picked.append((r, g, b, i))
    if len(picked) > limit:
        picked = picked[:: len(picked) // limit + 1]
    return picked


def misfit(samples, channel, shift):
    """Least-squares error of channel(i + shift) ~ a * green(i) + b."""
    whole = int(shift // 1)
    frac = shift - whole
    sx = sy = sxx = sxy = syy = 0.0
    n = 0
    for line in samples:
        ch, g, i = line[channel], line[1], line[3]
        j = i + whole
        if j < 0 or j + 1 >= len(ch):
            continue
        y = ch[j] * (1 - frac) + ch[j + 1] * frac
        x = g[i]
        sx += x; sy += y; sxx += x * x; sxy += x * y; syy += y * y
        n += 1
    if n < 10:
        return float("inf")
    var_x = sxx - sx * sx / n
    cov = sxy - sx * sy / n
    var_y = syy - sy * sy / n
    if var_x <= 0:
        return float("inf")
    return (var_y - cov * cov / var_x) / n


def best_shift(samples, channel):
    coarse = min((misfit(samples, channel, s / 10), s / 10) for s in range(-15, 16))[1]
    fine = min((misfit(samples, channel, coarse + s / 100), coarse + s / 100) for s in range(-10, 11))[1]
    return fine


def measure(path):
    width, height, px = read_ppm(path)
    result = {}
    for down in (True, False):
        samples = edge_samples(lines_of(px, width, height, down))
        result[down] = (best_shift(samples, 0), best_shift(samples, 2), len(samples))
    return width, height, result


def save(path, resolution, red, blue):
    entries = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3 and not line.startswith("#"):
                    entries[float(parts[0])] = (float(parts[1]), float(parts[2]))
    entries[resolution] = (red, blue)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        f.write("# raven-driver colour fringe profile for the Raven Compact\n")
        f.write("# dpi red_offset blue_offset  (pixels down the page, relative to green)\n")
        for dpi in sorted(entries):
            f.write(f"{dpi:g} {entries[dpi][0]:+.3f} {entries[dpi][1]:+.3f}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scan")
    ap.add_argument("--save", action="store_true")
    ap.add_argument("--resolution", type=float)
    ap.add_argument("-o", "--output",
                    default=os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                                         "raven-driver", "fringe.txt"))
    args = ap.parse_args()
    if args.save and not args.resolution:
        ap.error("--save needs --resolution, the dpi the scan was made at")

    width, height, result = measure(args.scan)
    _, _, px = read_ppm(args.scan)
    sat = [max(px[i : i + 3]) - min(px[i : i + 3]) for i in range(0, len(px), 3 * 13)]
    print(f"{args.scan}: {width} x {height}; "
          f"{100 * sum(s > 40 for s in sat) / len(sat):.2f}% of pixels visibly coloured (saturation > 40)")
    for down, label in ((True, "down the page (across the feed direction)"),
                        (False, "across the page (along the feed direction)")):
        red, blue, n = result[down]
        print(f"{label}: red {red:+.2f} px, blue {blue:+.2f} px relative to green ({n} edge samples)")
    if args.save:
        red, blue, n = result[True]
        if n < 1000:
            sys.exit("too few edges to measure reliably; scan a page with more black text or lines")
        save(args.output, args.resolution, red, blue)
        print(f"Saved {args.resolution:g} dpi offsets to {args.output}")


if __name__ == "__main__":
    main()
