"""Computed-style differential oracle for CSS modularization (#504/#505).

Contract specification for Issue #505 to verify zero cascade mutation between
monolithic style.css and the modular bundle across all templates, dynamic class
combinations, viewports, and themes in headless Chromium.
"""
import glob
import os
import re
from pathlib import Path
import pytest
from playwright.sync_api import sync_playwright

ORDER = [
    "tokens.css",
    "base.css",
    "layout.css",
    "components.css",
    "tables.css",
    "server.css",
    "vpn.css",
]

VIEWPORTS = [
    (1280, 800),   # Desktop standard
    (1024, 768),   # Landscape tablet
    (900, 800),    # Desktop narrow / nav breakpoint
    (768, 1024),   # Tablet portrait breakpoint
    (767, 1024),   # Mobile breakpoint upper boundary
    (700, 900),    # Compact tablet
    (480, 854),    # Mobile small
]

THEMES = ["dark", "light"]

@pytest.fixture
def repo_root() -> Path:
    """Resolve repository root relative to tests/e2e."""
    return Path(__file__).resolve().parents[2]

PROBE_SCRIPT = """
() => {
  const out = [];
  const elements = [document.documentElement, document.body, ...document.body.querySelectorAll('*')];
  let i = 0;
  for (const el of elements) {
    const rec = [];
    for (const pe of [null, '::before', '::after']) {
      const s = getComputedStyle(el, pe);
      const o = [];
      for (let k = 0; k < s.length; k++) {
        const n = s[k];
        o.push(n + '=' + s.getPropertyValue(n));
      }
      rec.push(o.join(';'));
    }
    const path = el.tagName.toLowerCase() +
      (el.id ? '#' + el.id : '') +
      (el.className && typeof el.className === 'string'
        ? '.' + el.className.trim().split(/\\s+/).join('.')
        : '');
    out.push([i++, path, rec]);
  }
  return out;
}
"""

def strip_template_syntax(html: str) -> str:
    """Strip Go template actions and scripts to isolate static DOM hierarchy."""
    html = re.sub(r"\{\{.*?\}\}", "", html, flags=re.S)
    html = re.sub(r"<script\b.*?</script>", "", html, flags=re.S | re.I)
    html = re.sub(r"<link[^>]*stylesheet[^>]*>", "", html, flags=re.I)
    html = re.sub(r"</?(html|head|body)\b[^>]*>", "", html, flags=re.I)
    html = re.sub(r"<!DOCTYPE[^>]*>", "", html, flags=re.I)
    return html

def build_test_pages(repo_root: Path) -> dict:
    """Build DOM pages for all templates plus synthetic dynamic class lists."""
    pages = {}
    tpl_dir = os.path.join(repo_root, "web", "templates")
    for p in sorted(glob.glob(os.path.join(tpl_dir, "*.html"))):
        pages[os.path.basename(p)] = strip_template_syntax(Path(p).read_text(encoding="utf-8"))

    # Extract dynamic class lists from templates and client JavaScript
    class_lists = set()
    scan_files = glob.glob(os.path.join(tpl_dir, "*.html")) + [
        p for p in glob.glob(os.path.join(repo_root, "web", "static", "js", "**", "*.js"), recursive=True)
        if not p.endswith(".min.js")
    ]
    for p in scan_files:
        content = Path(p).read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"class(?:Name)?\s*=\s*(?:\\?\"|'|`)([^\"'`\\]*)", content):
            cl = " ".join(re.sub(r"\{\{.*?\}\}|\$\{.*?\}", " ", m.group(1)).split())
            if cl:
                class_lists.add(cl)

    # Dynamic toast variants constructed programmatically in client JS (showToast)
    class_lists.update(f"toast toast-{t}" for t in ("success", "error", "warning", "info"))

    # Table sorting states toggled via classList.add() in client JS (sortable tables)
    class_lists.update(["sort-active sort-asc", "sort-active sort-desc"])

    # Synthetic DOM: each class list standalone and nested inside common containers
    syn = []
    for cl in sorted(class_lists):
        syn.append(f'<div class="{cl}"><span class="icon"></span>content</div>')
        syn.append(f'<input class="{cl}"><button class="{cl}">action</button>')
    pages["__synthetic_classlists__"] = (
        '<div class="app-layout"><main class="app-main"><div class="card">'
        '<table class="data-table interactive-table">'
        '<thead><tr>'
        '<th class="sortable">Column</th>'
        '<th class="sortable sort-active sort-asc">Sorted Asc</th>'
        '<th class="sortable sort-active sort-desc">Sorted Desc</th>'
        '</tr></thead>'
        '<tbody><tr><td>'
        + "\n".join(syn)
        + '</td></tr></tbody></table></div><div id="usersGrid">'
        + "\n".join(syn)
        + "</div></main></div>"
    )
    return pages

def wrap_html(css: str, body: str, theme: str) -> str:
    return (
        f'<!DOCTYPE html><html data-theme="{theme}"><head><meta charset="utf-8">'
        f'<style>{css}</style></head><body>{body}</body></html>'
    )

def test_css_computed_style_differential(repo_root: Path):
    """Assert zero computed style differences between monolith and modular bundle."""
    css_dir = os.path.join(repo_root, "web", "static", "css")
    mono_css = Path(os.path.join(css_dir, "style.css")).read_text(encoding="utf-8")
    modular_css = "\n".join(
        Path(os.path.join(css_dir, f)).read_text(encoding="utf-8") for f in ORDER
    )

    pages = build_test_pages(repo_root)
    diffs = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()

        for page_name, body in pages.items():
            for width, height in VIEWPORTS:
                page.set_viewport_size({"width": width, "height": height})
                for theme in THEMES:
                    page.set_content(wrap_html(mono_css, body, theme))
                    mono_records = page.evaluate(PROBE_SCRIPT)

                    page.set_content(wrap_html(modular_css, body, theme))
                    mod_records = page.evaluate(PROBE_SCRIPT)

                    assert len(mono_records) == len(mod_records)

                    for (idx, path, ra), (_, _, rb) in zip(mono_records, mod_records):
                        for pe_idx, pe_name in enumerate(["", "::before", "::after"]):
                            if ra[pe_idx] != rb[pe_idx]:
                                diffs.append({
                                    "page": page_name,
                                    "viewport": f"{width}x{height}",
                                    "theme": theme,
                                    "element": path + pe_name,
                                })
        browser.close()

    assert len(diffs) == 0, f"Detected {len(diffs)} computed style differences"
