"""Share-page navigation oracle, free of Playwright imports.

The share link contains a random hex token. That token is data, so no substring
of the URL can decide whether the page exists: a valid token containing "404"
is still a served page, and a bogus token containing "404" is still a missing
one. This module judges the navigation instead — the HTTP status of the request,
plus an explicit rendered marker for the served branch — so the decision cannot
depend on what random value the token happens to hold.

Deliberately duck-typed and Playwright-free, like ``api.py``: the offline test
harness can hand in fakes, so the oracle is proven without a browser.
"""

from __future__ import annotations

from typing import Any

# The served branch renders either the password prompt or the connection list;
# the not-found branch renders neither.
SERVED_SHARE_SURFACE = "#connectionsList, #authForm"


def assert_share_page_served(response: Any, page: Any) -> None:
    """Assert the navigation landed on a served share page.

    Args:
        response: Response of the navigation to the share link, or None when the
            navigation produced no response at all.
        page: The page the navigation loaded into; only ``locator`` is used.

    Raises:
        AssertionError: The navigation produced no response, was not served with
            200, or rendered the not-found branch instead of the share surface.
    """
    assert response is not None, "the share link navigation produced no response"
    assert response.status == 200, f"the share page must be served; got {response.status}"
    assert (
        page.locator(SERVED_SHARE_SURFACE).count() > 0
    ), "a served share page must render its password or connection surface"
