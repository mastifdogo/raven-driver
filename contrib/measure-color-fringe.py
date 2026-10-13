#!/usr/bin/env python3
"""Measure colour misregistration in a colour scan of a black-and-white page.

Usage: contrib/measure-color-fringe.py color.pnm

Reads a binary PPM (P6, as `scanimage --format=pnm` writes for colour), finds
sharp edges in the green channel, and reports where the red and blue edges
sit relative to green, in fractions of a pixel. It does this separately for
edges across the feed direction (rows) and along it (columns).

A consistent offset across the feed direction means the scanner lights each
colour at a slightly different paper position, which software can correct by
shifting red and blue. Offsets near zero mean the colour comes from blur or
noise instead. Only the Python standard library is used.
"""

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
    if fields[0] != b"P6":
        sys.exit(f"{path} is not a colour PPM (P6); scan with --mode Color --format=pnm")
    width, height, maxval = int(fields[1]), int(fields[2]), int(fields[3])
    if maxval != 255:
        sys.exit("only 8-bit PPM files are supported")
    return width, height, data[pos + 1 :]


def edge_offsets(get, n_lines, line_len, step, threshold=40, window=3):
    """For each sampled line, find strong green edges along it and return the
    red and blue edge centroids minus the green one."""
    offsets = {"R": [], "B": []}
    for line in range(0, n_lines, step):
        g = [get(line, i, 1) for i in range(line_len)]
        r = [get(line, i, 0) for i in range(line_len)]
        b = [get(line, i, 2) for i in range(line_len)]
        i = window
        while i < line_len - window - 1:
            if abs(g[i + 1] - g[i]) < threshold:
                i += 1
                continue

            # Only count changes in the same direction as the green edge, so
            # the far edge of a thin line (opposite direction) is ignored.
            sign = 1 if g[i + 1] > g[i] else -1

            def centroid(ch):
                w = [max(0, sign * (ch[k + 1] - ch[k])) for k in range(i - window, i + window + 1)]
                total = sum(w)
                return None if total == 0 else sum(k * x for k, x in zip(range(-window, window + 1), w)) / total

            cg, cr, cb = centroid(g), centroid(r), centroid(b)
            if None not in (cg, cr, cb):
                offsets["R"].append(cr - cg)
                offsets["B"].append(cb - cg)
            i += 2 * window
    return offsets


def summary(values):
    if not values:
        return "no edges"
    values = sorted(values)
    mean = sum(values) / len(values)
    median = values[len(values) // 2]
    return f"mean {mean:+.2f} px, median {median:+.2f} px ({len(values)} edges)"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    width, height, px = read_ppm(sys.argv[1])

    def at(y, x, c):
        return px[(y * width + x) * 3 + c]

    sat = [max(px[i : i + 3]) - min(px[i : i + 3]) for i in range(0, len(px), 3 * 7)]
    print(f"{sys.argv[1]}: {width} x {height}")
    print(f"colour saturation: mean {sum(sat) / len(sat):.1f}, "
          f"{100 * sum(s > 40 for s in sat) / len(sat):.2f}% of pixels above 40")
    across = edge_offsets(lambda col, row, c: at(row, col, c), width, height, step=8)
    along = edge_offsets(lambda row, col, c: at(row, col, c), height, width, step=8)
    print("edges across the feed direction (scanning down the page):")
    print("  red vs green:  " + summary(across["R"]))
    print("  blue vs green: " + summary(across["B"]))
    print("edges along the feed direction (scanning across the page):")
    print("  red vs green:  " + summary(along["R"]))
    print("  blue vs green: " + summary(along["B"]))


if __name__ == "__main__":
    main()
