"""WCAG contrast arithmetic over the design tokens.

Deliberately free of Playwright imports so the offline suite can import it.
Everything here is derived from web/static/css/tokens.css; no colour is pinned
in a test, so a palette change that breaks AA fails the assertion that uses it.
"""

from __future__ import annotations

import re
from pathlib import Path

CSS_DIR = Path(__file__).resolve().parents[2] / "web" / "static" / "css"

AA_TEXT = 4.5  # WCAG 1.4.3, normal text
AA_NON_TEXT = 3.0  # WCAG 1.4.11, focus indicator against its surroundings

_DECL_RE = re.compile(r"--([\w-]+)\s*:\s*([^;]+);")
_HEX_RE = re.compile(r"^#([0-9a-fA-F]{6})$")
_RGBA_RE = re.compile(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$")


def theme_tokens(theme: str, css_dir: Path = CSS_DIR) -> dict[str, str]:
    """Token values in effect for a theme, keyed without the leading --.

    :root first, overridden by [data-theme="light"] for the light theme.
    """
    css = re.sub(r"/\*.*?\*/", "", (css_dir / "tokens.css").read_text(encoding="utf-8"), flags=re.S)
    blocks = {m.group(1).strip(): m.group(2) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css)}
    tokens = dict(_DECL_RE.findall(blocks[":root"]))
    if theme == "light":
        tokens.update(_DECL_RE.findall(blocks['[data-theme="light"]']))
    return {name: value.strip() for name, value in tokens.items()}


def parse_color(value: str) -> tuple[float, float, float, float]:
    """(r, g, b, alpha) from #rrggbb, rgb() or rgba()."""
    value = value.strip()
    hexed = _HEX_RE.match(value)
    if hexed:
        digits = hexed.group(1)
        return (
            float(int(digits[0:2], 16)),
            float(int(digits[2:4], 16)),
            float(int(digits[4:6], 16)),
            1.0,
        )
    rgba = _RGBA_RE.match(value)
    if rgba:
        r, g, b, a = rgba.groups()
        return float(r), float(g), float(b), float(a) if a is not None else 1.0
    raise ValueError(f"not a plain colour: {value!r}")


def _channel(c: float) -> float:
    c /= 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(rgb: tuple[float, float, float, float]) -> float:
    r, g, b, _ = rgb
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def ratio(fg: str, bg: str) -> float:
    """WCAG contrast ratio of two opaque colours."""
    hi, lo = sorted((luminance(parse_color(fg)), luminance(parse_color(bg))), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def resolve(name: str, tokens: dict[str, str]) -> str:
    """Token value, following one level of var(--other) indirection."""
    value = tokens[name]
    ref = re.fullmatch(r"var\(--([\w-]+)\)", value)
    return resolve(ref.group(1), tokens) if ref else value
