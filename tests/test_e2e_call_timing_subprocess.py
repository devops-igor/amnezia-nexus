"""End-to-end regression: real Go panel log -> real collector -> artifact.

The unit tests above prove the extractor's behaviour on synthetic lines. This
suite closes the loop the unit tests cannot: it builds and runs the actual Go
provider client against a local server, captures the real stdout the panel emits
through slog, and feeds that captured text to the real collector.

No network call leaves the machine, no container is started, no credentials are
used, and no PROD/DEV endpoint is touched.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.e2e import diagnostics

REPO_ROOT = Path(__file__).resolve().parents[1]

# Harness program: drives the real provider client with timing enabled and prints
# the resulting slog line to stdout, exactly as the panel does in production.
HARNESS = """package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

func main() {
	mode := os.Args[1]

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "stall":
			<-r.Context().Done()
		case "status":
			w.WriteHeader(http.StatusTeapot)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	onCall := func(t gigahost.CallTiming) {
		slog.Info(gigahost.CallTimingMarker, gigahost.TimingRecord(t)...)
	}
	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: srv.URL,
		APIKey:  "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout: 200 * time.Millisecond,
		OnCall:  onCall,
	})
	if err != nil {
		panic(err)
	}

	// A closed port for the network-error case.
	if mode == "refused" {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		_ = l.Close()
		client, err = gigahost.NewClient(gigahost.Config{
			BaseURL: "http://" + addr,
			APIKey:  "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Timeout: 200 * time.Millisecond,
			OnCall:  onCall,
		})
		if err != nil {
			panic(err)
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	_, _ = client.GetServers(context.Background())
}
"""


@pytest.fixture(scope="module")
def harness_binary(tmp_path_factory) -> Iterator[Path]:
    """Build the harness inside the module so the real package resolves."""
    go = os.environ.get("GO_BINARY") or shutil.which("go")
    if not go:
        # The dedicated CI job sets TIMING_COLLECTOR_REQUIRE_GO=1 so a missing
        # toolchain fails the job instead of silently skipping the only proof
        # that the collector works on real panel output.
        if os.environ.get("TIMING_COLLECTOR_REQUIRE_GO") == "1":
            pytest.fail("go toolchain is required for the subprocess collector proof")
        pytest.skip("go toolchain not available (set TIMING_COLLECTOR_REQUIRE_GO=1 to require it)")
    # The harness must live under the module to import internal packages, so it
    # is written into a scratch directory inside the repo and removed afterwards.
    workdir = REPO_ROOT / "test-artifacts" / "call-timing-harness"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "main.go").write_text(HARNESS, encoding="utf-8")
    binary = workdir / "harness"
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOMAXPROCS": "2"})
    try:
        result = subprocess.run(
            [go, "build", "-tags=with_utls", "-o", str(binary), "./test-artifacts/call-timing-harness"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )
    finally:
        (workdir / "main.go").unlink(missing_ok=True)
    if result.returncode != 0:
        pytest.fail(f"harness build failed:\n{result.stdout}\n{result.stderr}")
    yield binary
    binary.unlink(missing_ok=True)
    shutil.rmtree(workdir, ignore_errors=True)


def run_harness(binary: Path, mode: str) -> str:
    sys.path.insert(0, str(REPO_ROOT))
    result = subprocess.run(
        [str(binary), mode], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def collect(binary: Path, mode: str, tmp_path: Path):
    stdout = run_harness(binary, mode)
    payload = diagnostics.parse_call_timing_log(stdout)
    return stdout, payload


def test_real_panel_stdout_round_trips_to_a_valid_artifact(harness_binary, tmp_path):
    """The actual slog line the panel writes must validate as a publishable report."""
    stdout, payload = collect(harness_binary, "ok", tmp_path)
    assert payload is not None, f"collector found no record in real stdout: {stdout!r}"
    assert diagnostics.validate_timing_report(payload) == []
    call = payload["calls"][0]
    assert call["method"] == "GET"
    assert call["op"] == "servers_get"
    assert call["outcome"] == "ok"
    assert call["status"] == 200
    assert call["first_byte_ms"] >= 0

    written = diagnostics.write_timing_artifact(tmp_path, payload)
    assert written is not None
    assert diagnostics.gate(tmp_path) == 0


def test_real_client_timeout_reports_the_stalled_phase(harness_binary, tmp_path):
    """The exact failure mode under investigation, produced by the real client."""
    stdout, payload = collect(harness_binary, "stall", tmp_path)
    assert payload is not None, f"no record in {stdout!r}"
    assert diagnostics.validate_timing_report(payload) == []
    call = payload["calls"][0]
    assert call["outcome"] == "client_timeout"
    assert call["status"] == 0
    assert call["last_phase"] == "request_written"
    assert call["first_byte_ms"] == -1


def test_real_network_error_record_is_still_allowlisted(harness_binary, tmp_path):
    stdout, payload = collect(harness_binary, "refused", tmp_path)
    assert payload is not None, f"no record in {stdout!r}"
    assert diagnostics.validate_timing_report(payload) == []
    call = payload["calls"][0]
    assert call["outcome"] == "network_error"
    assert call["first_byte_ms"] == -1


def test_real_http_status_record_classifies_as_http_status(harness_binary, tmp_path):
    stdout, payload = collect(harness_binary, "status", tmp_path)
    assert payload is not None, f"no record in {stdout!r}"
    assert diagnostics.validate_timing_report(payload) == []
    call = payload["calls"][0]
    assert call["outcome"] == "http_status"
    assert call["status"] == 418


def test_real_stdout_carries_no_secret_or_endpoint(harness_binary, tmp_path):
    """Defence in depth on the REAL bytes, not on a synthetic fixture."""
    stdout = run_harness(harness_binary, "stall")
    lowered = stdout.lower()
    for forbidden in (
        "flux_live_",
        "bearer",
        "authorization",
        "127.0.0.1",
        "http://",
        "://",
        "servers?page",
        "api/v0",
    ):
        assert forbidden not in lowered, f"real stdout leaked {forbidden!r}: {stdout!r}"
    # And the reviewable artifact carries none of it either.
    payload = diagnostics.parse_call_timing_log(stdout)
    assert payload is not None
    assert diagnostics.validate_timing_report(payload) == []
    serialized = json.dumps(payload).lower()
    for forbidden in ("flux_live_", "bearer", "127.0.0.1", "http://"):
        assert forbidden not in serialized
