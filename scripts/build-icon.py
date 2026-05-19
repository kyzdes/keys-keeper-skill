#!/usr/bin/env python3
"""One-off icon generator. Run once, commit the .icns output.
Design: navy rounded square + warm-gold keyhole.
Pure stdlib — no PIL dep.
"""
from __future__ import annotations
import struct, zlib, subprocess, tempfile
from pathlib import Path

BG = (26, 31, 54)       # #1A1F36 deep navy
FG = (251, 210, 95)     # #FBD25F warm gold
SIZE = 1024
CORNER_R = SIZE * 0.22  # rounded-corner radius
KEY_HEAD_CX = SIZE * 0.50
KEY_HEAD_CY = SIZE * 0.42
KEY_HEAD_R = SIZE * 0.13
KEY_HOLE_R = SIZE * 0.06    # inner hole (cut back to navy)
KEY_STEM_X1 = SIZE * 0.465
KEY_STEM_X2 = SIZE * 0.535
KEY_STEM_Y1 = SIZE * 0.42
KEY_STEM_Y2 = SIZE * 0.78
KEY_TOOTH1_X1 = SIZE * 0.535
KEY_TOOTH1_X2 = SIZE * 0.64
KEY_TOOTH1_Y1 = SIZE * 0.62
KEY_TOOTH1_Y2 = SIZE * 0.68
KEY_TOOTH2_X1 = SIZE * 0.535
KEY_TOOTH2_X2 = SIZE * 0.60
KEY_TOOTH2_Y1 = SIZE * 0.72
KEY_TOOTH2_Y2 = SIZE * 0.78


def in_rounded_square(x: float, y: float, size: float, r: float) -> bool:
    if r <= 0:
        return 0 <= x < size and 0 <= y < size
    if x < 0 or y < 0 or x >= size or y >= size:
        return False
    # which corner region?
    if x < r and y < r:
        return (r - x) ** 2 + (r - y) ** 2 <= r * r
    if x >= size - r and y < r:
        return (x - (size - r - 1)) ** 2 + (r - y) ** 2 <= r * r
    if x < r and y >= size - r:
        return (r - x) ** 2 + (y - (size - r - 1)) ** 2 <= r * r
    if x >= size - r and y >= size - r:
        return (x - (size - r - 1)) ** 2 + (y - (size - r - 1)) ** 2 <= r * r
    return True


def in_circle(x: float, y: float, cx: float, cy: float, r: float) -> bool:
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_rect(x: float, y: float, x1: float, y1: float, x2: float, y2: float) -> bool:
    return x1 <= x < x2 and y1 <= y < y2


def pixel(x: int, y: int) -> tuple[int, int, int]:
    if not in_rounded_square(x, y, SIZE, CORNER_R):
        return (0, 0, 0)  # outside the icon — will be alpha=0
    # key body
    is_key = (
        in_circle(x, y, KEY_HEAD_CX, KEY_HEAD_CY, KEY_HEAD_R)
        or in_rect(x, y, KEY_STEM_X1, KEY_STEM_Y1, KEY_STEM_X2, KEY_STEM_Y2)
        or in_rect(x, y, KEY_TOOTH1_X1, KEY_TOOTH1_Y1, KEY_TOOTH1_X2, KEY_TOOTH1_Y2)
        or in_rect(x, y, KEY_TOOTH2_X1, KEY_TOOTH2_Y1, KEY_TOOTH2_X2, KEY_TOOTH2_Y2)
    )
    # cut the keyhole back to navy
    if is_key and in_circle(x, y, KEY_HEAD_CX, KEY_HEAD_CY, KEY_HOLE_R):
        is_key = False
    return FG if is_key else BG


def alpha(x: int, y: int) -> int:
    return 255 if in_rounded_square(x, y, SIZE, CORNER_R) else 0


def make_png(size: int) -> bytes:
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            r, g, b = pixel(x, y)
            a = alpha(x, y)
            raw.extend((r, g, b, a))
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data)
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def main():
    out_icns = Path(__file__).parent / "keys-keeper.icns"
    sizes_per_image = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ]
    # Build the largest once, downscale via sips for the rest (faster + sharper).
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        iconset = td_path / "keys-keeper.iconset"
        iconset.mkdir()
        master = iconset / "_master_1024.png"
        master.write_bytes(make_png(1024))
        for name, size in sizes_per_image:
            target = iconset / name
            subprocess.run(
                ["sips", "-z", str(size), str(size), str(master), "--out", str(target)],
                check=True, capture_output=True,
            )
        master.unlink()
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(out_icns)],
            check=True,
        )
    print(f"wrote {out_icns} ({out_icns.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
