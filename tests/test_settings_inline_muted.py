"""No Settings script may paint informative text in the muted colour inline.

The static stylesheet rules reach only nodes that carry a class. Scripts that
build nodes at runtime and set `style.color` inline bypass them, which is how
Gigahost labels and recovery instructions stayed at 2.95:1 (dark) and 2.56:1
(light) after the stylesheet was fixed. This guard reads every script the
Settings templates load and fails on any inline use of --text-muted that is not
named below with a reason, so a new sibling cannot slip in unseen.

The browser tests in tests/e2e/test_settings.py check what is actually painted;
this one is browser-free and runs in the offline job.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB = REPO_ROOT / "web"

# An inline assignment: element.style.color = '...' or a style="...color:..." string.
_INLINE_MUTED = re.compile(
    r"(?:style\.color\s*=\s*['\"`][^'\"`]*var\(--text-muted|"
    r"style\s*=\s*\\?[\"'][^\"']*color\s*:\s*var\(--text-muted)"
)
_SCRIPT_SRC = re.compile(r'src="/static/js/([\w./-]+\.js)')

# (script, a fragment of the line) -> why muted is correct there. Empty on purpose:
# every inline use on the Settings scripts was informative text. Add an entry only
# for text that is decorative or genuinely inactive, and say why.
DELIBERATE: dict[tuple[str, str], str] = {}


def settings_scripts() -> list[str]:
    """Scripts the Settings page loads: the layout, the page shell and every partial.

    Partials live in two places: templates/settings/ and the settings_*.html files
    beside the page shell (the policy cards). Both load their own scripts.
    """
    templates = WEB / "templates"
    files = [templates / "base.html", templates / "settings.html"]
    files += sorted(templates.glob("settings_*.html"))
    files += sorted((templates / "settings").glob("*.html"))
    found = sorted({m for f in files for m in _SCRIPT_SRC.findall(f.read_text(encoding="utf-8"))})
    assert found, "no script found in the Settings templates"
    return found


def inline_muted_lines(script: str) -> list[tuple[int, str]]:
    source = (WEB / "static" / "js" / script).read_text(encoding="utf-8")
    return [
        (number, line.strip())
        for number, line in enumerate(source.splitlines(), 1)
        if _INLINE_MUTED.search(line) or ("style.color" in line and "var(--text-muted" in line)
    ]


def test_the_scan_sees_every_script_the_page_loads() -> None:
    scripts = settings_scripts()
    for name in (
        "gigahost_order_status.js",
        "gigahost_setup_intents.js",  # templates/settings/ and the shell
        "policy_routing.js",  # a settings_*.html partial
        "policy_upstream.js",
        "policy_client_diag.js",
        "ui.js",  # the layout
    ):
        assert name in scripts, name


def test_no_settings_script_paints_text_in_the_muted_colour_inline() -> None:
    offenders = []
    for script in settings_scripts():
        for number, line in inline_muted_lines(script):
            if any(s == script and fragment in line for (s, fragment) in DELIBERATE):
                continue
            offenders.append(f"{script}:{number}: {line}")
    assert offenders == [], (
        "inline --text-muted on a Settings script (2.95:1 dark, 2.56:1 light on a card); "
        "use --text-secondary or list it in DELIBERATE with a reason:\n" + "\n".join(offenders)
    )
