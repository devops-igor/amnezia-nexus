# Task Overview — amnezia-nexus
Updated: 2026-09-09 01:00 MSK (pm_bot session wrap-up — FINAL)

## Session result: PR #10 MERGED to main (aa119d5). All session issues closed.

## CLOSED this session (13 issues)
- #1 captcha, #2 /vpn template (deployed+live-verified earlier)
- #5 LB AWG 3+ compatibility (the arc: 15 review findings -> 4 sub-tasks -> round-2 rework -> container acceptance test green vs real amneziawg v3.1, final QA APPROVED, deployed, live-verified)
- #4 Add Backend modal, #6 AWG detection sync, #7 server reachability, #9 VPN 400 errors, #11 login redirect, #13 LB user configs (all: implemented, QA-approved, in merged PR, deployed, live-verified)
- #12 CI/CD (workflows committed; CI runs on push/PR: tests+cross-compile PASS; lint toolchain-compat fixed 281fc3c; Docker Build & Push runs on main)
- #14 branch protection (verified active — blocked non-admin merge; already closed by parallel session)

## OPEN (2) — next session's work
- #15 Remove invalid CPS I1-I5 from LB client configs: REAL defect (AWGParamsFromVPNConfig injects a 216-byte QUIC Initial blob into every LB client config). Spec at tasks/issue-15-remove-cps-i1-from-lb/TASK.md. NOTE: the spec's root-cause analysis is partially incorrect (upstream sends I1-I5 as SEPARATE datagrams, not a prefix on the initiation — the portal listener drops them harmlessly); the real harm is client-side compat/parsing of the oversized blob + pointless mimicry in LB mode. The FIX (remove I1-I5 from LB configs) is correct regardless. Also includes: no-active-backends handshake UX.
- #8 Fully obfuscated AWG 3+ config generation (timing params etc.): SPEC READY at tasks/awg3-full-obfuscation/. Includes routed follow-ups from #5: EnableBackend lock-held SSH I/O, 2x 500-handler error echoes, per-field-tier fallback semantics, probe-peer PSK policy ratification.

## Repository state
- main @ aa119d5 (merge of PR #10; includes 281fc3c lint fix). Feature branch deleted (local + remote).
- Working tree: clean.
- CI on main: Continuous Integration + Docker Build & Push (first :main image being built — NEW deploy artifact replacing the manual binary-swap flow).
- WORKLOG.md remains gitignored (history lives on disk only — deliberate: contains operational IPs).

## Deploy/infra state (DEV = home NAS, igor@192.168.1.100)
- Panel LIVE at https://vpn.drochi.games: fresh arm64 binary (built from 3bbdcc8 == merged main minus the lint commit), stack healthy (bunkerweb + amnezia-panel + docker-proxy).
- Deploy flow (documented): golang:1.26-alpine container cross-builds panel binary -> /home/igor/amnezia-deploy/panel -> docker compose build (thin runtime Dockerfile) -> compose up. The docker.yml CI workflow now also builds+pushes :main to GHCR — future deploys can pull instead of building on the NAS.
- VPN endpoint: listen_port=31458 (container-internal, UDP).
- amneziawg-go arm64: upstream has NO arm64 manifest; NAS retag devopsigor/awg2-arm64->amneziavpn/amneziawg-go:latest exists for the container test. Container integration test needs AWG_PROBE_HOST=172.17.0.1 inside builder containers.

## Next session starting point
1. CI/Docker-on-main verdict (runs 34282909528/34282909384 were in flight at wrap-up) — if Docker :main image built, verify it exists in GHCR and switch the NAS deploy to pull :main
2. Implement #15 (spec ready; correct the root-cause note first) — small surgical fix + tests
3. Implement #8 (spec ready) — the AWG 3+ full obfuscation batch
4. Re-run full gate; QA; merge to main; deploy :main image to NAS; live-verify
