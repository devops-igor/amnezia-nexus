"""The rendered-pixel reader the hint-contrast oracle depends on.

A wrong decoder would report a backdrop that was never painted, and every contrast
number derived from it would be fiction, so the five PNG row filters are checked
against hand-computed scanlines rather than against the reader's own output.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from tests.e2e.rendered_pixels import dominant_colour, read_png


def build_png(colour_type: int, width: int, height: int, rows: list[bytes]) -> bytes:
    """A PNG whose IDAT holds the given rows, each `filter byte + filtered bytes`."""
    raw = b"".join(rows)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body))
            + kind
            + body
            + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, colour_type, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def pixels(rows: list[bytearray], bpp: int) -> list[list[tuple[int, ...]]]:
    """Each pixel as (r, g, b); an alpha channel is dropped and grey is expanded."""
    out = []
    for row in rows:
        line = []
        for i in range(0, len(row), bpp):
            pixel = row[i : i + bpp]
            line.append((pixel[0], pixel[0], pixel[0]) if bpp < 3 else tuple(pixel[:3]))
        out.append(line)
    return out


def test_none_filter_scanline_decodes_verbatim() -> None:
    # 3x2 RGB, both rows stored unfiltered.
    data = build_png(
        2,
        3,
        2,
        [
            bytes([0, 10, 20, 30, 40, 50, 60, 70, 80, 90]),
            bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        ],
    )
    width, height, rows, bpp = read_png(data)
    assert (width, height, bpp) == (3, 2, 3)
    assert pixels(rows, bpp) == [
        [(10, 20, 30), (40, 50, 60), (70, 80, 90)],
        [(1, 2, 3), (4, 5, 6), (7, 8, 9)],
    ]


def test_sub_filter_adds_the_byte_to_the_left() -> None:
    # Row 1: 13,23,33 then each following byte is 0x1E = 30 greater than the byte
    # three positions to its left, so the scanline is (13,23,33) (43,53,63) (73,83,93).
    data = build_png(
        2,
        3,
        2,
        [
            bytes([0, 10, 20, 30, 40, 50, 60, 70, 80, 90]),
            bytes([1, 13, 23, 33, 30, 30, 30, 30, 30, 30]),
        ],
    )
    _, _, rows, bpp = read_png(data)
    assert pixels(rows, bpp)[1] == [(13, 23, 33), (43, 53, 63), (73, 83, 93)]


def test_up_filter_adds_the_byte_above() -> None:
    # Row 1 is row 0 plus 5 in every channel.
    data = build_png(
        2,
        1,
        2,
        [bytes([0, 10, 20, 30]), bytes([2, 5, 5, 5])],
    )
    _, _, rows, bpp = read_png(data)
    assert pixels(rows, bpp) == [[(10, 20, 30)], [(15, 25, 35)]]


def test_average_filter_adds_the_floor_of_the_mean() -> None:
    # Row 0 = (10,20,30); row 1 stores 0x05 for each byte, so the decoded pixel is
    # 5 + floor((0 + 10)/2), 5 + floor((0 + 20)/2), 5 + floor((0 + 30)/2).
    data = build_png(
        2,
        1,
        2,
        [bytes([0, 10, 20, 30]), bytes([3, 5, 5, 5])],
    )
    _, _, rows, bpp = read_png(data)
    assert pixels(rows, bpp)[1] == [(10, 15, 20)]


def test_paeth_filter_adds_the_paeth_predictor() -> None:
    # Row 0 is black; row 1 stores 1 for its first byte and 0 for the rest. The first
    # byte's predictor is 0 (no left neighbour, black above), so it decodes to 1.
    # Each later red byte predicts from its left neighbour (paeth(1, 0, 0) == 1) and
    # decodes to 1; a green or blue byte has no left neighbour of its own channel, so
    # its predictor is 0 and it stays 0.
    data = build_png(
        2,
        2,
        2,
        [bytes([0, 0, 0, 0, 0, 0, 0]), bytes([4, 1, 0, 0, 0, 0, 0])],
    )
    _, _, rows, bpp = read_png(data)
    assert pixels(rows, bpp) == [[(0, 0, 0), (0, 0, 0)], [(1, 0, 0), (1, 0, 0)]]


def test_rgba_and_greyscale_are_both_read() -> None:
    rgba = build_png(6, 2, 1, [bytes([0, 0x12, 0x34, 0x56, 0xFF, 0x65, 0x43, 0x21, 0x80])])
    _, _, rows, bpp = read_png(rgba)
    assert bpp == 4
    assert pixels(rows, bpp) == [[(0x12, 0x34, 0x56), (0x65, 0x43, 0x21)]]

    grey = build_png(0, 2, 1, [bytes([0, 0x40, 0x80])])
    _, _, rows, bpp = read_png(grey)
    assert pixels(rows, bpp) == [[(0x40, 0x40, 0x40), (0x80, 0x80, 0x80)]]


def test_dominant_colour_ignores_a_minority_of_glyph_pixels() -> None:
    # 4x1 RGBA: three background pixels and one text pixel, box covering all four.
    data = build_png(
        6,
        4,
        1,
        [
            bytes(
                [0]
                + [0x13, 0x15, 0x1F, 0xFF]
                + [0x13, 0x15, 0x1F, 0xFF]
                + [0x94, 0x96, 0xA8, 0xFF]
                + [0x13, 0x15, 0x1F, 0xFF]
            )
        ],
    )
    colour, share = dominant_colour(data, (0, 0, 4, 1))
    assert colour == "#13151f"
    assert share == pytest.approx(0.75)


def test_a_box_outside_the_image_is_clamped_rather_than_raising() -> None:
    data = build_png(6, 1, 1, [bytes([0, 0x01, 0x02, 0x03, 0xFF])])
    colour, _ = dominant_colour(data, (50, 50, 10, 10))
    assert colour == "#010203"
