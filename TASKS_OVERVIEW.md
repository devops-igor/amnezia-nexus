# Task Overview — amnezia-nexus
Updated: 2026-09-09 00:45 MSK (pm_bot session wrap-up)

## Closed this session (all: implemented, reviewed, tested, deployed)
- #1 captcha (live-verified) — #2 /vpn template — #5 LB AWG 3+ compatibility (7 commits on PR #10, container acceptance test green, final QA APPROVED, deployed to DEV, live-verified)

## Open issues — state after this session
- #4 Add Backend modal: implemented+QA'd+deployed (in PR #10) — needs live re-verify then close
- #6 AWG detection sync: implemented+QA'd+deployed (in PR #10) — needs live re-verify then close
- #7 Server reachability: implemented+QA'd+deployed (in PR #10) — needs live re-verify then close
- #9 VPN error 400 clarity: implemented+QA'd+deployed (in PR #10) — needs live re-verify then close
- #11 non-admin login redirect: implemented+QA'd+deployed (in PR #10) — needs live re-verify then close
- #13 LB user configs + endpoint UI: implemented+QA'd+deployed (in PR #10) — needs live re-verify then close
- #12 CI/CD: workflows committed (3bbdcc8) — VERIFY GitHub Actions actually run on push; then close
- #8 AWG 3+ full obfuscation (timing params): SPEC READY (tasks/awg3-full-obfuscation/) — includes routed follow-ups from #5: EnableBackend lock-held SSH I/O, 2× 500-handler error echoes, per-field-tier fallback, probe-peer PSK policy ratification

## PR state
- PR #10 @ 3bbdcc8: all session work. READY TO MERGE after the #4/#6/#7/#9/#11/#13 live re-verifications (or merge now and re-verify on main — user decision).

## Infrastructure notes
- DEV = home NAS (igor@192.168.1.100). Panel deploy = thin runtime Dockerfile COPYing precompiled arm64 binary from /home/igor/amnezia-deploy/panel. Binary built via golang:1.26-alpine container from synced tree. Compose: docker-compose-awg-panel.yaml (bunkerweb + panel + docker-proxy).
- Panel live at https://vpn.drochi.games. VPN endpoint listen_port=31458 (container-internal).
- NAS has NO go toolchain — all builds go through the golang container. The amneziawg-go image retag (devopsigor/awg2-arm64 → amneziavpn/amneziawg-go:latest) exists on the NAS for the container integration test; upstream publishes no arm64 manifest.

## Next session starting point
1. Live re-verify #4/#6/#7/#9/#11/#13 on the deployed panel (browser + API), close them
2. Check GitHub Actions on the push (issue #12 completion)
3. Merge PR #10 (after user approval)
4. Issue #8 implementation (spec ready) — includes the #5 follow-ups
