"""Activate the E2E console privacy filter for every pytest run in this repo.

The plugin rewrites each test report before pytest renders it, so authentication
material cannot reach the console, the short summary or a machine-readable
report even when a Playwright timeout traceback embeds request headers (#735).
It imports no Playwright and performs no I/O, so ordinary CI runs pay nothing
but the filter itself.
"""

pytest_plugins = ["tests.e2e.log_privacy"]
