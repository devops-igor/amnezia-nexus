# Issue #392 Soak Evidence Schema — Enforced by the Qualification Verifier

Normative reference for the evidence a soak report must present to
`scripts/verify_issue392_qualification.sh`. Every constraint below was read out of
the verifier's embedded Python block; the line numbers are that script's lines.
This document describes **implemented behavior only**. The verifier fails closed
(`exit 1`, no summary published) on any violation.

---

## 1. File naming and cardinality

The verifier consumes soak evidence from a single artifact directory
(`--artifacts-dir`, default `test-artifacts/public`).

| Side | Required file glob | Checked by |
|---|---|---|
| reference | `soak_report_reference_*.json` | `require_single_report("reference")` — L346 |
| subject | `soak_report_subject_*.json` | `require_single_report("subject")` — L347 |

- **Exactly one report per side** (L280-287). Zero matches → `Missing <side> soak
  report`. Two or more → `Ambiguous <side> soak evidence: exactly one report is
  required, found N`. There is no last-match selection and no preference for a
  fresher file (L271-278 lists and sorts names only to return the single one).
- Each report is parsed as JSON and must be a **JSON object**; arrays, strings,
  numbers, `null` and unparseable text are rejected (L259-269).
- Diagnostics name only the report file name, never report content (L260).

Note: the verifier does not enforce freshness or emptiness of the artifact
directory. Staleness is handled by output invalidation (§5), not by directory
inspection.

## 2. Declared identity

`require_side_metadata()` (L289-294), applied to both sides at L352-353:

- `server_type` must equal the file's side — `"reference"` for
  `soak_report_reference_*.json`, `"subject"` for `soak_report_subject_*.json`.
- `run_mode` must equal the run mode implied by the requested `--mode`
  (`EXPECTED_RUN_MODE`, L255-256):

  | `--mode` | required `run_mode` |
  |---|---|
  | `bounded` | `bounded_verification` |
  | `full` | `unaccelerated_10_rekey` |

  These are the two literals the Go producer emits
  (`internal/vpn/differential_soak_test.go` L156-158).

## 3. Required soak-report fields

Checked on both reports (L355-367):

| Field | Requirement | Line |
|---|---|---|
| `tcp_continuity_passed` | truthy | L355-358 |
| `idle_phase_passed` | truthy | L359-362 |
| `completed_rekeys` | bounded: `>= 1`; full: `>= 10` (absent → `0`) | L364-380 |
| `sequenced_udp_stats` | present and a JSON object | L323-325 |

## 4. `sequenced_udp_stats`

`verify_udp_evidence()` (L321-344), run for reference then subject (L366-367).

### 4.1 `loss_rate_percent` — `require_finite_rate()` L296-308

1. Key must be **present** (`in` check, L298). Missing is a failure; there is no
   default.
2. Type must be `int` or `float`, **`bool` excluded** (L301-302).
3. `math.isfinite` (L304-305) → `NaN`, `Infinity`, `-Infinity` rejected. These
   arrive only from non-strict JSON parsers, which the verifier's `json.load`
   accepts.
4. Range `0.0 <= value <= 100.0` inclusive (L306-307).

### 4.2 Packet counters — `require_counter()` L310-319

| Field | Minimum | Type |
|---|---|---|
| `packets_sent` | `1` (L328) | `int`, `bool` excluded |
| `packets_received` | `1` (L329) | `int`, `bool` excluded |
| `packets_lost` | `0` (L330) | `int`, `bool` excluded |

Because the type check is `isinstance(value, int)` with a `bool` guard, `10.0`,
`"10"`, `true`, `null`, `[10]` and `{}` are all rejected. Non-integral floats are
rejected rather than coerced.

Additional ordering constraints (L332-335):

- `packets_received <= packets_sent`
- `packets_lost <= packets_sent`

Consequence: **an explicit zero loss with no observed stream fails.** A report
with `packets_sent: 0` or `packets_received: 0` never reaches the budget check.

### 4.3 Percentage consistency (L339-341)

```
math.isclose(loss_rate_percent, 100.0 * packets_lost / packets_sent,
             rel_tol=1e-9, abs_tol=1e-9)
```

A self-declared rate that does not match the counters to within that tolerance
fails, including the case `packets_lost > 0` reported with
`loss_rate_percent: 0`.

### 4.4 Budget (L342-343)

`UDP_LOSS_BUDGET_PERCENT = 0.05` (L257), compared with `>` so the boundary is
inclusive: **`loss_rate_percent <= 0.05` per side**, applied independently to
reference and subject. The check runs *after* the rate is known to be a real,
internally consistent measurement.

### 4.5 `received + lost == sent` is deliberately NOT required

Not imposed by the verifier (comment at L337-338). The producer's late and
duplicate echo accounting does not guarantee that equality, so
`sent=20000, received=19990, lost=10` (sum 20000) and
`sent=20000, received=19990, lost=5` (sum 19995) are both acceptable; only the
two individual `<= sent` bounds and the percentage consistency apply.

## 5. Output lifecycle (stale invalidation and atomic publication)

Bash preconditions, both ahead of any report parsing:

- **Output/input collision check (L128-149).** The resolved output path is
  compared against the verifier's actual consumed inputs — the four fixed report
  names (`evidence_manifest.json`, `qualification_summary.json`,
  `upstream_restart_durability.json`, `non_netstack_qualification.json`, L134-135)
  plus both soak globs (L136-138). A collision exits nonzero. A previously
  published summary is deliberately *not* a candidate input, so a legitimate rerun
  is not blocked by its own earlier output.
- **Stale-output invalidation (L153).** `rm -f -- "$OUTPUT_FILE"` runs after the
  collision check and before any report is read, so a failing rerun can never
  leave a prior `PASS` summary behind.

Publication:

- `is_closure_eligible = (mode == "full")` (L446) — **bounded runs stay
  closure-ineligible**, independently of the evidence.
- `publish_summary()` (L474-488) writes to a `tempfile.mkstemp` sibling
  (`.issue392_summary_*.tmp`) in the target directory and moves it into place with
  `os.replace`, i.e. atomic. An `OSError` unlinks the temp file and fails; the
  call site also converts any other exception to a nonzero exit (L490-494).
- Publication happens only after every gate has passed, so the `PASS` banner
  (L500-513) is unreachable when publication fails.

## 6. Minimal conforming soak report

Per side, with `mode` per §2 and rekeys per §3 (bounded example, threshold case):

```json
{
  "server_type": "subject",
  "run_mode": "bounded_verification",
  "completed_rekeys": 1,
  "tcp_continuity_passed": true,
  "idle_phase_passed": true,
  "sequenced_udp_stats": {
    "packets_sent": 20000,
    "packets_received": 19990,
    "packets_lost": 10,
    "loss_rate_percent": 0.05
  }
}
```

Other producer-emitted fields (`max_interruption_ms`, `avg_rtt_ms`,
`target_rekeys`, `rekey_timestamps`, socket identity, …) are not read by the
verifier and are neither required nor constrained.

## 7. Producer-side counterpart (cross-reference, not enforced here)

`internal/vpn/differential_soak_test.go` applies matching criteria locally in
`validateObservedUDPStream()` (L856-887): positive `PacketsSent`/`PacketsReceived`,
nonnegative `PacketsLost`, neither exceeding `PacketsSent`, finite
`LossRatePercent` in `0..100`, and the same `1e-9` absolute/relative tolerance
against `100*lost/sent`. Field names and JSON types come from `StreamStats`
(L23-29) and `SoakEvidenceReport` (L46-53). The Python side is the normative
consumer; the Go check is defense in depth.

---

## 8. Regression coverage and CI gating

### 8.1 The schema's regression suite

Every constraint in §1-§5 has a permanent regression in
`tests/test_verify_issue392_verifier.py`, which drives the **real** shell script
as a `bash` subprocess — 233 collected cases, one mutated condition per case,
both sides and both modes parametrized. Local result:

```
$ pytest tests/test_verify_issue392_verifier.py -p no:cacheprovider -q
============================= 233 passed in 13.60s =============================
```

### 8.2 The suite is explicitly collected in CI

`.github/workflows/e2e-dev.yml:105`, inside the `Run Playwright E2E Lifecycle
Suite` step (line 100), in the venv built at lines 102-104:

```
105:  python -m pytest tests/test_e2e_assertions.py tests/test_e2e_service_logs.py \
      tests/test_e2e_config_oracle.py tests/test_restart_durability.py \
      tests/test_verify_issue392_verifier.py -p no:cacheprovider
```

Explicit path list, so a new module could never be silently uncollected — the
condition required by resolution-plan §7 item 9. Verified by reading the file;
this session added no workflow lines.

### 8.3 The verifier itself is exercised in CI

`.github/workflows/e2e-dev.yml:260-267`, step `Verify Issue #392 Qualification
Evidence`:

```
260:  - name: Verify Issue #392 Qualification Evidence
261:    if: ${{ steps.qual-mode.outputs.mode != 'standard' }}
262:    run: |
263:      chmod +x ./scripts/verify_issue392_qualification.sh
264:      ./scripts/verify_issue392_qualification.sh \
265:        --artifacts-dir test-artifacts/public \
266:        --mode ${{ steps.qual-mode.outputs.mode }} \
267:        --expected-commit "${{ github.sha }}"
```

End-to-end path on a pull request to `main` (trigger lines 4-7):

| Step | Lines | Role |
|---|---|---|
| `Determine Qualification Mode` (id `qual-mode`) | 46-51 | `qualification` input, defaulting to `bounded` |
| `Run Differential Qualification Suite` | 188-196 | **produces** the soak reports into `test-artifacts/public` |
| `Run Non-Netstack Client Qualification` | 231-238 | produces `non_netstack_qualification.json` |
| `Run Upstream Restart Durability Rehearsal` | 252-257 | produces `upstream_restart_durability.json` |
| `Verify Issue #392 Qualification Evidence` | 260-267 | **consumes** them through this schema; nonzero exit fails the job |
| `Upload Qualification Evidence Artifacts` | 269-275 | `if: always()` — evidence is retained even on failure |

On a `pull_request` event `github.event.inputs.qualification` is empty, so line 49
falls back to `bounded`; the `!= 'standard'` guards at 261 therefore do not skip
the verifier on PRs. Only a `workflow_dispatch` run that explicitly selects
`standard` bypasses it (lines 6-14, 14-18).

### 8.4 Producer-side counterpart gating

`internal/vpn/differential_soak_test.go` (§7 above) is gated by
`.github/workflows/ci.yml:73` — `go test -race -cover -count=1 ./...` — which
includes `TestSoakCriteriaRequireObservedUDPStream` (line 921) and the bounded
soak `TestDifferential_Soak_BoundedVerification` (line 98). The unaccelerated
10-rekey test self-skips unless `NEXUS_SOAK_FULL=true`
(`differential_soak_test.go:124-126`); the full-mode *consumer* path is exercised
instead by the 233-case matrix, which parametrizes both modes.

### 8.5 Observed gate topology (no change made)

Recorded as-is, not as a defect:

- The Python verifier suite runs **only** in `e2e-dev.yml`, never in `ci.yml`
  (which is Go-only: `go vet` line 30, `golangci-lint` line 44, `go test` line
  73). `e2e-dev.yml` does trigger on `pull_request` to `main` (lines 4-7) on a
  self-hosted runner (line 25), so PR coverage exists — it is not a GitHub-hosted
  per-PR required check.
- `differential-soak.yml` (workflow_dispatch + schedule) runs the Go differential
  suite (lines 49-74) and uploads evidence, but does **not** invoke
  `verify_issue392_qualification.sh`. That is not a plan gap: §7 item 9 asks only
  that the verifier's *tests* be explicitly collected, and §7 items 1-8 constrain
  verifier behavior, not which workflow invokes it. Flagged for the record; no
  workflow was edited.