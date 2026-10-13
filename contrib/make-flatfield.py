#!/usr/bin/env python3
"""Make a flat-field profile for the Raven Compact from blank-sheet scans.

Usage:
  contrib/make-flatfield.py COLOR.pnm GRAY.pnm [--resolution 150] [-o FILE]
  contrib/make-flatfield.py --check SCAN.pnm [--resolution 150]

COLOR.pnm and GRAY.pnm are scans of a plain white sheet, made with the
correction off (RAVEN_FLATFIELD=off) at the given resolution and full width.
The profile goes to ~/.config/raven-driver/flatfield.txt unless -o says
otherwise; the patched avision backend reads it on every scan.

--check reports how even a blank scan is, without writing anything.
Only the Python standard library is used.
"""

import argparse
import os
import sys
import time


def read_pnm(path):
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
    magic = fields[0]
    if magic not in (b"P5", b"P6") or int(fields[3]) != 255:
        sys.exit(f"{path}: need an 8-bit binary PNM (scanimage --format=pnm)")
    return int(fields[1]), int(fields[2]), 3 if magic == b"P6" else 1, data[pos + 1 :]


def column_profiles(path):
    """Mean level of each column, per channel, over the rows that show paper."""
    width, height, channels, px = read_pnm(path)
    stride = width * channels
    row_means = [sum(px[y * stride : (y + 1) * stride : 7]) / len(px[y * stride : (y + 1) * stride : 7])
                 for y in range(height)]
    ordered = sorted(row_means)
    typical = ordered[len(ordered) // 2]
    rows = [y for y in range(height) if row_means[y] >= 0.9 * typical]  # skip the strip after the paper ends
    rows = rows[len(rows) // 20 : len(rows) - len(rows) // 20] or rows
    rows = rows[:: max(1, len(rows) // 400)]
    sums = [[0] * width for _ in range(channels)]
    for y in rows:
        line = px[y * stride : (y + 1) * stride]
        for c in range(channels):
            s = sums[c]
            for x, v in enumerate(line[c::channels]):
                s[x] += v
    return width, [[v / len(rows) for v in s] for s in sums]


def smooth(values, radius):
    out, n = [], len(values)
    prefix = [0.0]
    for v in values:
        prefix.append(prefix[-1] + v)
    for i in range(n):
        lo, hi = max(0, i - radius), min(n, i + radius + 1)
        out.append((prefix[hi] - prefix[lo]) / (hi - lo))
    return out


def percentile(values, q):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def describe(name, profile):
    top = percentile(profile, 0.95)
    eighths = [sum(profile[i * len(profile) // 8 : (i + 1) * len(profile) // 8]) /
               max(1, len(profile) // 8) for i in range(8)]
    return (f"  {name:<5} brightest {top:5.1f}, darkest {min(profile):5.1f} "
            f"({100 * (top - min(profile)) / top:4.1f}% darker); eighths: "
            + " ".join(f"{v:5.1f}" for v in eighths))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scans", nargs="+")
    ap.add_argument("--resolution", type=float, default=150)
    ap.add_argument("--left", type=float, default=0.0, help="inches from the scan area's left edge")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("-o", "--output",
                    default=os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                                         "raven-driver", "flatfield.txt"))
    args = ap.parse_args()
    radius = max(2, int(args.resolution / 50))

    if args.check:
        for path in args.scans:
            width, profiles = column_profiles(path)
            names = ["red", "green", "blue"] if len(profiles) == 3 else ["gray"]
            print(f"{path}: {width} columns")
            for name, prof in zip(names, profiles):
                print(describe(name, smooth(prof, radius)))
        return

    if len(args.scans) != 2:
        ap.error("give a colour scan and a gray scan of the same blank sheet")
    width_c, colour = column_profiles(args.scans[0])
    width_g, gray = column_profiles(args.scans[1])
    if len(colour) != 3 or len(gray) != 1:
        sys.exit("the first scan must be colour (P6) and the second gray (P5)")
    if width_c != width_g:
        sys.exit("the two scans have different widths; use the same resolution for both")
    profiles = [smooth(p, radius) for p in colour + gray]

    gains, warnings = [], []
    for name, prof in zip(["red", "green", "blue", "gray"], profiles):
        top = percentile(prof, 0.95)
        if min(prof) < 0.5 * top:
            warnings.append(f"{name} drops below half brightness: the sheet may not cover the full width")
        gains.append([min(2.0, max(0.5, top / max(v, 1.0))) for v in prof])

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        f.write("# raven-driver flat-field profile for the Raven Compact\n")
        f.write(f"# made {time.strftime('%Y-%m-%d %H:%M')} from {args.scans[0]} and {args.scans[1]}"
                f" at {args.resolution:g} dpi\n")
        f.write("# inches_from_left red green blue gray\n")
        for x in range(width_c):
            inch = args.left + (x + 0.5) / args.resolution
            f.write(f"{inch:.4f} " + " ".join(f"{g[x]:.4f}" for g in gains) + "\n")

    print("Blank sheet as scanned:")
    for name, prof in zip(["red", "green", "blue", "gray"], profiles):
        print(describe(name, prof))
    print(f"Largest correction: x{max(max(g) for g in gains):.2f}")
    for w in warnings:
        print("warning: " + w)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
