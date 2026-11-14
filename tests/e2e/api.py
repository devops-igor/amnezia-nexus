"""HTTP helpers shared by the E2E suite and the offline contract tests.

Deliberately free of Playwright imports: modules that only need request and
response handling can then be imported without a browser toolchain. The helpers
duck-type the object they are given (a Playwright Page or APIRequestContext), so
nothing here needs the package at import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple, Union
from urllib.parse import urljoin

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from playwright.sync_api import Page

def api_get(page: Page, url: str, timeout: Optional[float] = None) -> Any:
    """Make a GET request via Playwright's request API (bypasses CSP).

    Uses page.request (APIRequestContext) which shares the browser context's
    cookies and session, but runs outside the page's CSP restrictions.

    Args:
        page: Authenticated Playwright page (used for its request context).
        url: Relative URL path (e.g., '/api/servers').
        timeout: Optional request timeout in milliseconds.

    Returns:
        Parsed JSON response body. Returns a dict with 'error' key for
        non-JSON responses.
    """
    full_url = urljoin(page.url, url)
    get_kwargs: Dict[str, Any] = {}
    if timeout is not None:
        get_kwargs["timeout"] = timeout
    response = page.request.get(full_url, **get_kwargs)
    content_type = response.headers.get("content-type", "")
    text = response.text()

    if "application/json" in content_type or text.startswith(("{", "[")):
        try:
            return response.json()
        except Exception:
            return {"error": text[:200], "status": response.status}

    return {"error": text[:200], "status": response.status}


def api_post(
    page: Page,
    url: str,
    data: Dict[str, Any],
    token: str,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Make a POST request via Playwright's request API (bypasses CSP).

    Uses page.request (APIRequestContext) which shares the browser context's
    cookies and session, but runs outside the page's CSP restrictions.

    Args:
        page: Authenticated Playwright page (used for its request context).
        url: Relative URL path (e.g., '/api/users/add').
        data: JSON-serializable body dict.
        token: CSRF token string.
        timeout: Optional request timeout in milliseconds.

    Returns:
        Dict with 'status' (int) and 'body' (dict). Handles HTML error
        responses gracefully — when the server returns non-JSON (e.g. a
        CSRF rejection page), body contains {error: <first 200 chars>}.
    """
    full_url = urljoin(page.url, url)
    post_kwargs: Dict[str, Any] = {
        "data": data,
        "headers": {
            "X-CSRF-Token": token,
            "Content-Type": "application/json",
        },
    }
    if timeout is not None:
        post_kwargs["timeout"] = timeout
    response = page.request.post(full_url, **post_kwargs)

    content_type = response.headers.get("content-type", "")
    text = response.text()
    status = response.status

    if "application/json" in content_type or text.startswith(("{", "[")):
        try:
            body = response.json()
        except Exception:
            body = {"error": text[:200]}
    else:
        body = {"error": text[:200]}

    return {"status": status, "body": body}


def assert_response_shape(
    data: Any,
    required_keys: Dict[str, Union[type, Tuple[type, ...]]],
    test_name: str = "",
) -> None:
    """Assert that data is a dict containing the required keys with expected types.

    Validates shape only — does not assert exact values. Handles the common
    pattern of api_post returning {"status": int, "body": dict} by checking
    the "body" key before validating its contents.

    Args:
        data: The response body dict to validate (or api_post result dict).
        required_keys: Map of key name -> expected type (e.g. {"id": int, "name": str}).
        test_name: Optional name for error messages.

    Raises:
        AssertionError with details of missing keys or type mismatches.
    """
    prefix = f"{test_name}: " if test_name else ""

    assert isinstance(data, dict), f"{prefix}Expected dict, got {type(data).__name__}"

    for key, expected_type in required_keys.items():
        assert key in data, f"{prefix}Missing required key '{key}' in {sorted(data.keys())}"
        value = data[key]
        if isinstance(expected_type, tuple):
            assert isinstance(value, expected_type), (
                f"{prefix}Key '{key}' expected one of "
                f"{[t.__name__ for t in expected_type]}, got {type(value).__name__}"
            )
        else:
            assert isinstance(value, expected_type), (
                f"{prefix}Key '{key}' expected {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
