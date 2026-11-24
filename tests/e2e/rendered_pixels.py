"""Read the pixels a browser actually painted, without an image library.

The hint-contrast cases need the colour *behind* rendered text, and a computed
`background-color` is not that colour: surfaces stack (a card over the page canvas,
a translucent fill over the card) and gradients paint between them. Sampling the
screenshot is the only measurement that answers what a reader's eye receives, so
this module decodes the PNG Playwright returns and reports the dominant colour of a
box. It covers what Chromium emits: 8-bit greyscale/RGB/RGBA, non-interlaced.

No third-party dependency: the e2e job installs only Playwright.
"""

from __future__ import annotations

import struct
import zlib

_BYTES_PER_PIXEL = {0: 1, 2: 3, 4: 2, 6: 4}


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def read_png(data: bytes) -> tuple[int, int, list[bytearray], int]:
    """(width, height, rows, bytes-per-pixel); rows are unfiltered scanlines."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos = 8
    width = height = depth = colour = interlace = 0
    seen_header = False
    idat = bytearray()
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", body)
            seen_header = True
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
    if not seen_header:
        raise ValueError("PNG without an IHDR chunk")
    if depth != 8 or colour not in _BYTES_PER_PIXEL:
        raise ValueError(f"unsupported PNG: depth={depth} colour={colour}")
    if interlace != 0:
        raise ValueError("interlaced PNG unsupported")

    bpp = _BYTES_PER_PIXEL[colour]
    stride = width * bpp
    raw = zlib.decompress(bytes(idat))
    rows: list[bytearray] = []
    previous = bytearray(stride)
    offset = 0
    for _ in range(height):
        filter_type = raw[offset]
        line = bytearray(raw[offset + 1 : offset + 1 + stride])
        offset += 1 + stride
        if filter_type == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                upleft = previous[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(left, previous[i], upleft)) & 0xFF
        elif filter_type != 0:
            raise ValueError(f"unknown PNG filter {filter_type}")
        rows.append(line)
        previous = line
    return width, height, rows, bpp


def _pixel(rows: list[bytearray], bpp: int, x: int, y: int) -> tuple[int, int, int]:
    row = rows[y]
    base = x * bpp
    if bpp >= 3:
        return row[base], row[base + 1], row[base + 2]
    value = row[base]
    return value, value, value


def dominant_colour(
    data: bytes, box: tuple[float, float, float, float], samples: int = 4000
) -> tuple[str, float]:
    """Most common colour inside box (x, y, w, h), as (#rrggbb, share of samples)."""
    width, height, rows, bpp = read_png(data)
    x0, y0, w, h = (int(round(value)) for value in box)
    x0 = max(0, min(x0, width - 1))
    y0 = max(0, min(y0, height - 1))
    x1 = max(x0 + 1, min(x0 + w, width))
    y1 = max(y0 + 1, min(y0 + h, height))
    counts: dict[tuple[int, int, int], int] = {}
    total = 0
    step_x = max(1, (x1 - x0) // 64)
    step_y = max(1, (y1 - y0) // 64)
    for y in range(y0, y1, step_y):
        for x in range(x0, x1, step_x):
            pixel = _pixel(rows, bpp, x, y)
            counts[pixel] = counts.get(pixel, 0) + 1
            total += 1
            if total >= samples:
                break
        if total >= samples:
            break
    best, hits = max(counts.items(), key=lambda item: item[1])
    return "#%02x%02x%02x" % best, hits / total
