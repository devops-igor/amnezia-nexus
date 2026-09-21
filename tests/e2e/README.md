# E2E Playwright Tests: Running Guide

## Prerequisites

```bash
# From repository root
cd .

# Install dependencies
pip install -r tests/e2e/requirements.txt

# Install Chromium browser (one-time, ~100MB)
python3 -m playwright install chromium
```

---

## Running Tests

### Run all E2E tests against dev server

```bash
E2E_BASE_URL=http://127.0.0.1:8443 \
E2E_ADMIN_USER=admin \
E2E_ADMIN_PASS="$ADMIN_PASSWORD" \
python3 -m pytest tests/e2e/ -m e2e -v
```

> **Note:** Set `ADMIN_PASSWORD` in your shell environment before running. Never hardcode credentials in commands or scripts.

### Run a single test file

```bash
E2E_BASE_URL=http://127.0.0.1:8443 \
python3 -m pytest tests/e2e/test_auth.py -m e2e -v
```

### Run a single test by name

```bash
E2E_BASE_URL=http://127.0.0.1:8443 \
python3 -m pytest tests/e2e/test_auth.py::test_login_page_loads -m e2e -v
```

### Run with visible browser (not headless)

```bash
E2E_HEADLESS=0 \
python3 -m pytest tests/e2e/test_auth.py -m e2e -v
```

> Note: `E2E_HEADLESS=0` opens a real Chromium window. Only works on machines with a display (not headless servers).

### Run against localhost (for local development)

```bash
# Default: targets http://localhost:8000
python3 -m pytest tests/e2e/ -m e2e -v
```

### Deterministic 3-Stage Clean-Slate Lifecycle Verification

To run the complete lifecycle suite (Initial Setup -> Server 1 Onboard & AWG 3.1 -> Full Functional Tests) against a clean database:

```bash
E2E_BASE_URL=http://localhost:8000 \
E2E_ADMIN_USER=admin \
E2E_ADMIN_PASS="$ADMIN_PASSWORD" \
E2E_SERVER_HOST=172.17.0.1 \
E2E_SERVER_SSH_KEY=~/.ssh/id_ed25519 \
./scripts/run_e2e_lifecycle.sh
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `E2E_BASE_URL` | `http://localhost:8000` | Target server URL |
| `E2E_HEADLESS` | `1` | Set to `0` for visible browser |
| `E2E_ADMIN_USER` | `admin` | Admin username for login |
| `E2E_ADMIN_PASS` | (empty) | Admin password (**set via env var, never hardcode**) |
| `E2E_SERVER_HOST` | `172.17.0.1` | Remote server hostname or bridge IP for onboarding |
| `E2E_SERVER_SSH_PORT` | `22` | SSH port for server onboarding |
| `E2E_SERVER_SSH_USER` | `ubuntu` | SSH username for server onboarding |
| `E2E_SERVER_SSH_KEY` | (empty) | Path to private SSH key for onboarding |
| `E2E_SERVER_SSH_PASS` | (empty) | SSH password for onboarding (optional fallback) |

---

## Test Files & Suite Overview

| File | Tests | What it covers |
|------|-------|---------------|
| `test_setup.py` | 4 | Initial setup wizard, validation, admin creation, lock |
| `test_onboard.py` | 4 | Server 1 SSH onboarding, fingerprint confirm, AWG 3.1 deploy, health |
| `test_auth.py` | 6 | Login page, success, failure, rate limiting, CSRF, logout |
| `test_servers.py` | 7 | Server list, detail, check, install, stats, add form, reboot |
| `test_connections.py` | 5 | Connection list, add, config/QR, toggle, delete |
| `test_users.py` | 7 | User list, add, edit, toggle, add connection, delete, XSS |
| `test_my_connections.py` | 4 | User login+list, create, view config, role access denied |
| `test_settings.py` | 6 | Page load, change title, captcha toggle, backup download, upstream status API & UI |
| `test_share.py` | 3 | Enable sharing, access share link, download config |

**Total: 46 test scenarios across 9 test suites**

---

## E2E Test Suite & Exact API Coverage Matrix

The following table provides the exhaustive mapping of all 46 test scenarios across all 9 test suites to their target UI pages visited, exact REST API endpoints executed, and corresponding HTTP methods:

| Test File | Test Name | Target UI / Page Visited | Exact APIs Called | HTTP Method |
|-----------|-----------|--------------------------|-------------------|-------------|
| `test_setup.py` | `test_setup_page_redirect_and_form` | `/` (redirects to `/setup`) | None (initial unconfigured redirect) | GET (UI) |
| `test_setup.py` | `test_setup_client_validation_password_mismatch` | `/setup` | None (client-side form validation) | N/A |
| `test_setup.py` | `test_setup_success` | `/setup` | `/api/auth/setup` | POST |
| `test_setup.py` | `test_setup_locked_after_completion` | `/setup` (redirects to `/login`) | `/api/auth/setup` | POST |
| `test_onboard.py` | `test_onboard_server_add` | Server Onboarding Modal | `/api/servers/add`<br>`/api/servers/confirm-fingerprint` | POST<br>POST |
| `test_onboard.py` | `test_onboard_server_reachability` | Server Detail / Server Actions | `/api/servers/1/check` | POST |
| `test_onboard.py` | `test_onboard_install_amneziawg` | Server Detail / Protocol Install | `/api/servers/1/install` | POST |
| `test_onboard.py` | `test_onboard_verify_awg_container_healthy` | Server Detail / Status Polling | `/api/servers/1/check` | POST |
| `test_auth.py` | `test_login_page_loads` | `/login` | None (login page load) | GET (UI) |
| `test_auth.py` | `test_login_success` | `/login` (redirects to `/`) | `/api/auth/login` | POST |
| `test_auth.py` | `test_login_failure` | `/login` | `/api/auth/login` | POST |
| `test_auth.py` | `test_login_rate_limiting` | `/login` | `/api/auth/login` | POST |
| `test_auth.py` | `test_csrf_protection` | `/login` | `/api/auth/login` | POST |
| `test_auth.py` | `test_logout` | `/logout` (redirects to `/login`) | None (session termination) | GET (UI) |
| `test_servers.py` | `test_server_list_loads` | `/` | None (server dashboard view) | GET (UI) |
| `test_servers.py` | `test_server_detail_page` | `/server/{server_id}` | `/api/servers` | GET |
| `test_servers.py` | `test_server_check` | Server Detail / Server Actions | `/api/servers`<br>`/api/servers/{server_id}/check` | GET<br>POST |
| `test_servers.py` | `test_server_install` | Server Detail / Protocol Install | `/api/servers`<br>`/api/servers/{server_id}/install` | GET<br>POST |
| `test_servers.py` | `test_server_stats` | Server Detail / Real-time Metrics | `/api/servers`<br>`/api/servers/{server_id}/stats` | GET<br>POST |
| `test_servers.py` | `test_server_add_form` | `/` (Add Server Modal) | None (form modal rendering) | GET (UI) |
| `test_servers.py` | `test_server_reboot` | Server Detail / Server Actions | `/api/servers`<br>`/api/servers/{server_id}/reboot` | GET<br>POST |
| `test_users.py` | `test_user_list_loads` | `/users` | `/api/users/` | GET |
| `test_users.py` | `test_add_user` | `/users` (Add User Modal) | `/api/users/add`<br>`/api/users/{user_id}/delete` | POST<br>POST |
| `test_users.py` | `test_edit_user` | `/users` (Edit User Modal) | `/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/update`<br>`/api/users/{user_id}/delete` | POST<br>GET<br>POST<br>POST |
| `test_users.py` | `test_toggle_user` | `/users` (User Table Actions) | `/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/toggle`<br>`/api/users/{user_id}/delete` | POST<br>GET<br>POST<br>POST |
| `test_users.py` | `test_add_user_connection` | `/users` (Add Connection Modal) | `/api/servers/`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/delete` | GET<br>POST<br>GET<br>POST<br>POST |
| `test_users.py` | `test_delete_user` | `/users` (User Table Actions) | `/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/delete` | POST<br>GET<br>POST |
| `test_users.py` | `test_xss_prevention` | `/users` (Sanitized Output) | `/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/delete` | POST<br>GET<br>POST |
| `test_connections.py` | `test_connection_list` | `/server/{server_id}` (Connections Tab) | `/api/servers/` | GET |
| `test_connections.py` | `test_add_connection` | Server Detail / Add Connection Modal | `/api/servers/`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/delete` | GET<br>POST<br>GET<br>POST<br>POST |
| `test_connections.py` | `test_connection_config_and_qr` | Server Detail / Config Modal & QR View | `/api/servers/`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/connections/`<br>`/api/servers/{server_id}/connections/config`<br>`/api/users/{user_id}/delete` | GET<br>POST<br>GET<br>POST<br>GET<br>POST<br>POST |
| `test_connections.py` | `test_toggle_connection` | Server Detail / Connection Actions | `/api/servers/`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/connections/`<br>`/api/servers/{server_id}/connections/toggle`<br>`/api/users/{user_id}/delete` | GET<br>POST<br>GET<br>POST<br>GET<br>POST<br>POST |
| `test_connections.py` | `test_delete_connection` | Server Detail / Connection Actions | `/api/users/add`<br>`/api/users/?size=100`<br>`/api/servers/`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/connections/`<br>`/api/servers/{server_id}/connections/remove`<br>`/api/users/{user_id}/delete` | POST<br>GET<br>GET<br>POST<br>GET<br>POST<br>POST |
| `test_my_connections.py` | `test_user_login_and_list` | `/login`, `/logout`, `/my` | `/api/auth/login`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/my/connections` | POST<br>POST<br>GET<br>GET |
| `test_my_connections.py` | `test_create_connection` | `/my` (Self-Service Add Connection) | `/api/servers/`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/delete` | GET<br>POST<br>GET<br>POST<br>POST |
| `test_my_connections.py` | `test_view_connection_config` | `/my` (View Config Modal) | `/api/auth/login`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/servers/`<br>`/api/users/{user_id}/connections/add`<br>`/api/users/{user_id}/connections/`<br>`/api/servers/{server_id}/connections/config`<br>`/api/users/{user_id}/delete` | POST<br>POST<br>GET<br>GET<br>POST<br>GET<br>POST<br>POST |
| `test_my_connections.py` | `test_role_access_denied` | `/login`, `/logout`, `/settings` (Admin Guard) | `/api/auth/login`<br>`/api/users/add`<br>`/api/users/?size=100`<br>`/api/settings` | POST<br>POST<br>GET<br>GET |
| `test_settings.py` | `test_settings_page_loads` | `/settings` | None (settings page load) | GET (UI) |
| `test_settings.py` | `test_change_title` | `/settings` (Appearance Settings), `/` | `/api/settings`<br>`/api/settings/save` | GET<br>POST |
| `test_settings.py` | `test_captcha_toggle` | `/settings` (Security / Captcha Settings) | `/api/settings`<br>`/api/settings/save` | GET<br>POST |
| `test_settings.py` | `test_backup_download` | `/settings` (Backup & Restore) | `/api/settings/backup/download` | GET |
| `test_settings.py` | `test_upstream_status_api` | None (Direct REST API) | `/api/system/upstream-status`<br>`/api/system/upstream-status?refresh=true` | GET<br>GET |
| `test_settings.py` | `test_upstream_status_ui` | `/settings` (Upstream Components Card) | `/api/system/upstream-status`<br>`/api/system/upstream-status?refresh=true` | GET<br>GET |
| `test_share.py` | `test_enable_sharing` | `/users` (Share Setup Modal) | `/api/users/?size=100`<br>`/api/users/add`<br>`/api/users/{user_id}/share/setup` | GET<br>POST<br>POST |
| `test_share.py` | `test_access_share_link` | `/share/{share_token}` | `/api/users/?size=100`<br>`/api/users/add`<br>`/api/users/{user_id}/share/setup`<br>`/api/users/{user_id}/delete` | GET<br>POST<br>POST<br>POST |
| `test_share.py` | `test_download_config_from_share` | `/share/{share_token}` (Config Download) | `/api/servers/`<br>`/api/users/?size=100`<br>`/api/users/add`<br>`/api/users/{user_id}/share/setup`<br>`/api/share/{token}/auth`<br>`/api/users/{user_id}/delete` | GET<br>GET<br>POST<br>POST<br>POST<br>POST |

---

## Categorized Summary of Tested REST API Endpoints

The E2E test suite exercises 26 distinct REST API routes across the platform, including 24 core functional endpoints and 2 automated server onboarding endpoints:

### 1. Authentication & Initial Setup (2 endpoints)
- `POST /api/auth/setup` - Initial administrator account setup (locked after initialization)
- `POST /api/auth/login` - User and administrator authentication session initialization

### 2. Server Management & Diagnostics (7 endpoints)
- `GET /api/servers` (or `/api/servers/`) - Lists registered servers and protocol statuses
- `POST /api/servers/add` - Initiates SSH handshake and captures host key fingerprint
- `POST /api/servers/confirm-fingerprint` - Confirms SSH fingerprint and persists server record
- `POST /api/servers/{server_id}/check` - Probes remote host SSH connectivity and Docker daemon status
- `POST /api/servers/{server_id}/install` - Deploys protocol container (AmneziaWG 3.1) on target server
- `POST /api/servers/{server_id}/stats` - Queries real-time host CPU and RAM telemetry
- `POST /api/servers/{server_id}/reboot` - Dispatches system reboot command to target server host

### 3. Server Connection Peer Management (3 endpoints)
- `POST /api/servers/{server_id}/connections/config` - Fetches WireGuard / AmneziaWG configuration profile and QR text
- `POST /api/servers/{server_id}/connections/toggle` - Enables or disables client peer connection state on server
- `POST /api/servers/{server_id}/connections/remove` - Disconnects client peer and deletes allocated IP routing

### 4. User Directory Management (5 endpoints)
- `GET /api/users/` (with pagination `?size=100`) - Retrieves paginated list of user accounts and roles
- `POST /api/users/add` - Creates a new user account with specified username, password, and role
- `POST /api/users/{user_id}/update` - Updates existing user account metadata and credentials
- `POST /api/users/{user_id}/toggle` - Enables or disables user account login access
- `POST /api/users/{user_id}/delete` - Permanently deletes user account and revokes active sessions

### 5. User Connection Allocation & Sharing (3 endpoints)
- `GET /api/users/{user_id}/connections/` - Retrieves all VPN connection profiles allocated to a specific user
- `POST /api/users/{user_id}/connections/add` - Provisions and allocates a new protocol connection for the user
- `POST /api/users/{user_id}/share/setup` - Enables or disables web share links and configures share password protection

### 6. User Self-Service Portal (1 endpoint)
- `GET /api/my/connections` - Fetches authenticated user's self-service connections and quota limits

### 7. System Settings & Maintenance (3 endpoints)
- `GET /api/settings` - Retrieves global panel configuration (appearance, security, limits)
- `POST /api/settings/save` - Persists updated panel appearance, branding, and security parameters
- `GET /api/system/upstream-status` - Retrieves upstream component release status and update availability (supports `?refresh=true`)

### Additional Utility & Public Endpoints (2 endpoints)
- `GET /api/settings/backup/download` - Downloads complete JSON database backup archive
- `POST /api/share/{token}/auth` - Verifies passphrase and authenticates access to shared client configuration

---

## Seeing What's Happening (Progress & Debugging)

### 1. Verbose output (`-v` flag)

The `-v` flag shows each test name and PASS/FAIL status in real-time:

```
tests/e2e/test_auth.py::test_login_page_loads PASSED
tests/e2e/test_auth.py::test_login_success FAILED
...
```

### 2. Extra verbose (`-vv` flag)

Shows full assertion details:

```bash
python3 -m pytest tests/e2e/test_auth.py -m e2e -vv
```

### 3. Print statements (`-s` flag)

Disables output capture so `print()` statements in tests show in real-time:

```bash
python3 -m pytest tests/e2e/test_auth.py -m e2e -v -s
```

### 4. Detailed traceback (`--tb=long`)

Shows full traceback on failures:

```bash
python3 -m pytest tests/e2e/test_auth.py -m e2e -v --tb=long
```

### 5. Short traceback (`--tb=short`)

More compact, shows just the assertion line:

```bash
python3 -m pytest tests/e2e/test_auth.py -m e2e -v --tb=short
```

### 6. Screenshots on failure

Automatically saved to `tests/e2e/screenshots/` when a test fails. This directory is gitignored: screenshots are runtime artifacts, not committed to the repo.

```bash
ls tests/e2e/screenshots/
# e.g., test_login_success[chromium].png
```

### 7. Slow motion for debugging

Add a delay between Playwright actions to watch what happens:

```python
# In your test (temporary debug):
page.wait_for_timeout(2000)  # 2 second pause
```

### 8. Run with visible browser + slow motion

Best for debugging: you can watch the browser in real time:

```bash
E2E_HEADLESS=0 python3 -m pytest tests/e2e/test_auth.py::test_login_success -m e2e -v -s
```

### 9. Playwright trace viewer

Record a trace and inspect it afterward:

```bash
E2E_BASE_URL=http://127.0.0.1:8443 \
python3 -m pytest tests/e2e/test_auth.py -m e2e --tracing on -v
# Then view:
python3 -m playwright show-trace trace.zip
```

---

## Common Issues

### "ModuleNotFoundError: No module named 'playwright'"

```bash
pip install -r tests/e2e/requirements.txt
python3 -m playwright install chromium
```

### "BrowserType.launch: Executable doesn't exist"

```bash
python3 -m playwright install chromium
```

### Tests timeout / hang

- The dev server may be slow to respond
- Increase wait timeouts in test files or conftest.py (e.g., `timeout=10000` -> `timeout=60000`)
- Or add `--timeout=120` to pytest: `python3 -m pytest tests/e2e/ -m e2e -v --timeout=120`

### Login tests fail with 400/422

- Check `E2E_ADMIN_PASS` is set correctly for the target server
- Check the server is up: `curl -sk http://127.0.0.1:8443/login`
- Check if captcha is enabled (test fixtures try to handle it but may fail)

### Fixture errors / test hangs

Tests use pytest-playwright's built-in sync fixtures. If you see hangs or async errors, make sure conftest.py does NOT define custom async `browser` or `page` fixtures (those conflict with pytest-asyncio).

---

## Quick Reference

```bash
# Full suite, dev server, verbose
E2E_BASE_URL=http://127.0.0.1:8443 E2E_ADMIN_PASS="$ADMIN_PASSWORD" python3 -m pytest tests/e2e/ -m e2e -v

# Single test, detailed output  
E2E_BASE_URL=http://127.0.0.1:8443 E2E_ADMIN_PASS="$ADMIN_PASSWORD" python3 -m pytest tests/e2e/test_auth.py::test_login_page_loads -m e2e -vv -s

# Just collect, don't run
python3 -m pytest tests/e2e/ -m e2e --collect-only -q
```