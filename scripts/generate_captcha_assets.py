"""Regenerate the small, self-hosted slide CAPTCHA assets (requires Pillow)."""

from pathlib import Path
from PIL import Image, ImageChops, ImageDraw, ImageFilter
import math
import random


ASSETS = Path(__file__).resolve().parent.parent / "internal" / "captcha" / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)


def background(index: int) -> None:
    rng = random.Random(181 + index)
    palettes = [
        ((10, 19, 46), (32, 68, 110), (95, 183, 218)),
        ((17, 14, 43), (64, 39, 104), (178, 130, 213)),
        ((9, 29, 39), (24, 79, 88), (87, 194, 184)),
        ((27, 19, 39), (87, 51, 83), (227, 139, 161)),
        ((17, 27, 49), (44, 66, 119), (151, 172, 244)),
        ((13, 31, 39), (45, 86, 83), (152, 203, 167)),
    ]
    top, bottom, accent = palettes[index]
    im = Image.new("RGB", (300, 160))
    pixels = im.load()
    for y in range(160):
        for x in range(300):
            t = (y / 160 + 0.15 * math.sin(x / 65 + index)) * 0.8
            grain = rng.randrange(-6, 7)
            pixels[x, y] = tuple(max(0, min(255, round(a * (1 - t) + b * t + grain))) for a, b in zip(top, bottom))
    d = ImageDraw.Draw(im, "RGBA")
    for _ in range(18):
        x, y = rng.randrange(300), rng.randrange(160)
        r = rng.randrange(12, 75)
        tint = (*accent, rng.randrange(22, 66))
        if index % 3 == 0:
            d.arc((x - r, y - r, x + r, y + r), rng.randrange(360), rng.randrange(360, 720), fill=tint, width=rng.randrange(1, 3))
        elif index % 3 == 1:
            d.line([(x - r, y + r // 3), (x, y - r // 3), (x + r, y + r // 3)], fill=tint, width=rng.randrange(1, 3))
        else:
            d.rounded_rectangle((x - r // 2, y - r // 2, x + r // 2, y + r // 2), radius=r // 5, outline=tint, width=2)
    for _ in range(100):
        x, y = rng.randrange(300), rng.randrange(160)
        d.point((x, y), fill=(*accent, rng.randrange(40, 125)))
    im.quantize(colors=64).save(ASSETS / f"background-{index + 1}.png", optimize=True)


def tile() -> None:
    scale = 3
    m = Image.new("L", (64 * scale, 64 * scale))
    d = ImageDraw.Draw(m)
    def box(coords, fill):
        d.rectangle(tuple(c * scale for c in coords), fill=fill)
    def circle(coords, fill):
        d.ellipse(tuple(c * scale for c in coords), fill=fill)
    box((8, 7, 55, 56), 255)
    circle((25, 0, 40, 17), 255)
    circle((49, 26, 63, 41), 255)
    circle((1, 25, 16, 40), 0)
    circle((26, 49, 41, 63), 0)
    m = m.resize((64, 64), Image.Resampling.LANCZOS)

    mask = Image.new("RGBA", (64, 64), "white")
    mask.putalpha(m)
    mask.save(ASSETS / "tile-mask.png", optimize=True)

    shadow = Image.new("RGBA", (64, 64), (4, 9, 22, 192))
    shadow.putalpha(m.point(lambda v: round(v * 0.8)))
    shadow.save(ASSETS / "tile-shadow.png", optimize=True)

    outer = m.filter(ImageFilter.MaxFilter(5))
    inner = m.filter(ImageFilter.MinFilter(5))
    border = ImageChops.subtract(outer, inner)
    border = Image.eval(border, lambda v: round(v * 0.85))
    overlay = Image.new("RGBA", (64, 64), (207, 233, 248, 0))
    overlay.putalpha(border)
    overlay.save(ASSETS / "tile-overlay.png", optimize=True)


if __name__ == "__main__":
    for number in range(6):
        background(number)
    tile()
