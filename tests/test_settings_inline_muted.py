"""No Settings script may paint informative text in the muted colour inline.

The static stylesheet rules reach only nodes that carry a class. Scripts that
build nodes at runtime and set `style.color` inline bypass them, which is how
Gigahost labels and recovery instructions stayed at 2.95:1 (dark) and 2.56:1
(light) after the stylesheet was fixed. This guard reads every script the
Settings templates load and fails on any inline use of --text-muted that is not
named below with a reason, so a new sibling cannot slip in unseen.

A template may name a script in more than one form: a bare path (the layout), the
release version in the query, or `asset_url`, which derives the query from the
asset's own bytes. Every form lives in _SCRIPT_FORMS, and a reference that
matches none of them fails the scan naming the tag, so a form a later template
introduces is caught here instead of being read as "no script".

The browser tests in tests/e2e/test_settings.py check what is actually painted;
this one is browser-free and runs in the offline job.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB = REPO_ROOT / "web"

# An inline assignment: element.style.color = '...' or a style="...color:...".
_INLINE_MUTED = re.compile(
    r"(?:style\.color\s*=\s*['\"`][^'\"`]*var\(--text-muted|"
    r"style\s*=\s*\\?[\"'][^\"']*color\s*:\s*var\(--text-muted)"
)


def _script_form(pattern: str) -> re.Pattern[str]:
    """Compile one script reference form; its first group is the script name."""
    return re.compile(pattern)


# Every form a Settings template may use to load a /static/js script. Each pattern
# is matched against a whole <script …> tag, and group 1 is the file below
# web/static/js/. Add a form here when a template starts using one: the scan fails
# on a reference it does not know, so an addition here is what keeps it visible.
_SCRIPT_FORMS = (
    # src="/static/js/x.js" — the layout loads its scripts bare.
    _script_form(r'\ssrc\s*=\s*"(/static/js/[\w./-]+\.js)"'),
    # src="/static/js/x.js?v={{ .app_version }}" — the release version.
    _script_form(r'\ssrc\s*=\s*"(/static/js/[\w./-]+\.js)\?v=\{\{\s*\.app_version\s*\}\}"'),
    # src="{{ asset_url "/static/js/x.js" }}" — the asset's own bytes.
    _script_form(r'\ssrc\s*=\s*"\{\{\s*asset_url\s+"(/static/js/[\w./-]+\.js)"\s*\}\}"'),
)
# A tag that names a source in a form above does not know: inline scripts carry
# none, so their presence means the scan is about to skip a file it cannot read.
_SCRIPT_SRC = re.compile(r"\ssrc\s*=")
_SCRIPT_TAG = re.compile(r"<script\b[^>]*>", re.IGNORECASE)

# Scripts the Settings page must load. The page-load test requires every one of
# them, so a template that stops loading one fails here rather than shrinking the
# set the muted-colour scan reads.
REQUIRED_SCRIPTS = (
    "gigahost_order_status.js",
    "gigahost_setup_intents.js",  # templates/settings/ and the shell
    "policy_routing.js",  # a settings_*.html partial
    "policy_upstream.js",
    "policy_client_diag.js",  # requested through asset_url
    "ui.js",  # the layout
)

# (script, a fragment of the line) -> why muted is correct there. Empty on purpose:
# every inline use on the Settings scripts was informative text. Add an entry only
# for text that is decorative or genuinely inactive, and say why.
DELIBERATE: dict[tuple[str, str], str] = {}


def settings_templates(templates_root: Path | None = None) -> list[Path]:
    """The templates the Settings page is made of: the layout, the shell, the partials.

    Partials live in two places: templates/settings/ and the settings_*.html files
    beside the page shell (the policy cards). Both load their own scripts.
    """
    root = templates_root or WEB / "templates"
    files = [root / "base.html", root / "settings.html"]
    files += sorted(root.glob("settings_*.html"))
    files += sorted((root / "settings").glob("*.html"))
    return files


def script_names(template: Path, source: str) -> list[str]:
    """Scripts one template source loads, by file name under web/static/js/.

    This is the only place a <script> tag is read, so every test below sees the
    same set. A tag whose src matches no form in _SCRIPT_FORMS raises rather than
    being skipped: an unreadable reference is exactly what this scan exists to
    notice.
    """
    found = []
    for tag in _SCRIPT_TAG.findall(source):
        for form in _SCRIPT_FORMS:
            match = form.search(tag)
            if match:
                found.append(match.group(1).removeprefix("/static/js/"))
                break
        else:
            if _SCRIPT_SRC.search(tag):
                raise AssertionError(
                    f"{template} loads a script this scan does not recognise: {tag.strip()} — "
                    "add its reference form to _SCRIPT_FORMS so the muted-colour scan reads it"
                )
            # An inline <script> loads no file, so there is nothing to scan.
    return found


def scripts_in_template(template: Path) -> list[str]:
    """Scripts one template file loads, in the order it names them."""
    return script_names(template, template.read_text(encoding="utf-8"))


def settings_scripts(templates_root: Path | None = None) -> list[str]:
    """Scripts the Settings page loads, across every template it is made of."""
    found = {name for f in settings_templates(templates_root) for name in scripts_in_template(f)}
    assert found, "no script found in the Settings templates"
    return sorted(found)


def assert_required_scripts(scripts: list[str]) -> None:
    """Fail unless every REQUIRED_SCRIPTS entry is in the enumerated set."""
    for name in REQUIRED_SCRIPTS:
        assert name in scripts, f"{name} is not enumerated by the settings scan: {scripts}"


def inline_muted_lines(script: str) -> list[tuple[int, str]]:
    source = (WEB / "static" / "js" / script).read_text(encoding="utf-8")
    return [
        (number, line.strip())
        for number, line in enumerate(source.splitlines(), 1)
        if _INLINE_MUTED.search(line) or ("style.color" in line and "var(--text-muted" in line)
    ]


def test_the_scan_sees_every_script_the_page_loads() -> None:
    assert_required_scripts(settings_scripts())


def test_a_script_dropped_from_a_template_copy_fails_the_page_load_check(tmp_path: Path) -> None:
    """Control: the page-load check fails when a template stops loading one script.

    The copy is temporary and never shipped. Without this control a scan that
    silently enumerated nothing would satisfy the check above.
    """
    templates = tmp_path / "templates"
    shutil.copytree(WEB / "templates", templates)
    assert_required_scripts(settings_scripts(templates))

    target = templates / "settings_policy_client.html"
    source = target.read_text(encoding="utf-8")
    removed = '<script src="{{ asset_url "/static/js/policy_client_diag.js" }}"></script>'
    assert removed in source
    target.write_text(source.replace(removed, "", 1), encoding="utf-8")

    with pytest.raises(AssertionError) as failure:
        assert_required_scripts(settings_scripts(templates))
    assert "policy_client_diag.js is not enumerated" in str(failure.value)


def test_an_unfamiliar_script_reference_fails_instead_of_being_skipped(tmp_path: Path) -> None:
    template = tmp_path / "settings_example.html"
    template.write_text(
        '<script src="{{ some_other_url "/static/js/example.js" }}"></script>', encoding="utf-8"
    )

    with pytest.raises(AssertionError) as failure:
        scripts_in_template(template)

    message = str(failure.value)
    assert "does not recognise" in message, message
    assert "some_other_url" in message, message


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
