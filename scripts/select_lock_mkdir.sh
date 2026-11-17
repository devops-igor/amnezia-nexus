#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Select a verified exclusive-create `mkdir` for the lock tests
#
# The remote lock protocol's exclusivity rests on one property of `mkdir`: a plain
# `mkdir DIR` must FAIL when DIR already exists. The generated acquire script takes its
# critical-section branch from that exit status for both the canonical lock directory and
# the acquisition gate, so an implementation that reports success on an existing
# directory turns both into a false success and admits two holders.
#
# This selects an implementation that satisfies that contract for the CI job only, and
# fails closed when there is none. It never installs anything, never changes a host
# alternative and never touches a path outside the job's own temporary directory: the
# selection is a single-entry PATH shim that contains `mkdir` and nothing else, so no
# other command can be shadowed.
#
# Provenance for the implementation the runner actually resolved and for the one selected
# is printed to the log and exported, because the historical CI failure could not be
# attributed without knowing which binary ran.
#
# Scope: this qualifies the CI hosted runner only. It says nothing about any remote host
# the panel operates on; the lock protocol on those hosts is a separate, open concern.
#
# Usage:
#   select_lock_mkdir.sh              # qualify, install the job-local shim, emit provenance
#   select_lock_mkdir.sh --self-test  # offline controls for the qualification gate
#   select_lock_mkdir.sh --check PATH # say whether one implementation passes the gate, and why
# ==============================================================================

readonly GNU_MARKER='GNU coreutils'
readonly SCOPE_NOTE='ci-hosted-runner-only; remote lock-protocol hosts are NOT qualified by this selection'

log() {
    printf 'select-lock-mkdir: %s\n' "$*"
}

# version_line prints the first line of an implementation's version banner.
version_line() {
    local bin="$1" out
    out="$("$bin" --version 2>&1 | head -n 1 || true)"
    printf '%s' "${out%$'\r'}"
}

# package_of prints the owning package when the platform can say, else a placeholder.
package_of() {
    local bin="$1" real
    real="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$real" 2>/dev/null | head -n 1 | cut -d: -f1 || true
    fi
}

is_gnu() {
    case "$(version_line "$1")" in
    *"$GNU_MARKER"*) return 0 ;;
    *) return 1 ;;
    esac
}

# package_label names the owning package, or says plainly that the platform could not say.
package_label() {
    local pkg
    pkg="$(package_of "$1")"
    printf '%s' "${pkg:-package-unknown}"
}

# exclusive_create_ok is the decisive capability, and it proves its two halves separately:
# the first plain mkdir must report success and leave a directory behind, and the second must
# be refused. Proving them apart matters, because an implementation that never creates
# anything also fails the second call and must not be mistaken for a correct one.
exclusive_create_ok() {
    local bin="$1" probe status=0
    probe="$(mktemp -d)"
    if ! "$bin" "$probe/once" >/dev/null 2>&1; then
        status=1
    elif [ ! -d "$probe/once" ]; then
        status=1
    elif "$bin" "$probe/once" >/dev/null 2>&1; then
        status=1
    fi
    rm -rf "$probe"
    return "$status"
}

# contention_create_ok is the capability the lock actually exercises: contenders call
# mkdir on the same path at the same time, and exactly one of them may report success.
# A sequential probe cannot see an implementation that only false-succeeds when it loses
# the creation race, and that is precisely the observed defect, so this races a bounded
# number of rounds. A correct mkdir is atomic here, so it cannot fail this probe.
contention_create_ok() {
    local bin="$1" rounds="${2:-24}" contenders=3 probe round success=0 pid i status=0
    local -a pids=()
    probe="$(mktemp -d)"
    for ((round = 1; round <= rounds; round++)); do
        pids=()
        for ((i = 0; i < contenders; i++)); do
            "$bin" "$probe/round-$round" >/dev/null 2>&1 &
            pids+=("$!")
        done
        success=0
        for pid in "${pids[@]}"; do
            if wait "$pid"; then
                success=$((success + 1))
            fi
        done
        if [ "$success" -ne 1 ] || [ ! -d "$probe/round-$round" ]; then
            status=1
            break
        fi
    done
    rm -rf "$probe"
    return "$status"
}

# reject_reason prints why a candidate is unusable, or nothing when it is acceptable.
reject_reason() {
    local bin="$1"
    if [ -z "$bin" ]; then
        printf 'empty candidate'
        return 0
    fi
    if [ ! -e "$bin" ]; then
        printf 'not present'
        return 0
    fi
    if [ ! -x "$bin" ]; then
        printf 'not executable'
        return 0
    fi
    if ! is_gnu "$bin"; then
        printf 'version banner is not %s (%s)' "$GNU_MARKER" "$(version_line "$bin")"
        return 0
    fi
    if ! exclusive_create_ok "$bin"; then
        printf 'reports success when the directory already exists'
        return 0
    fi
    if ! contention_create_ok "$bin"; then
        printf 'admits more than one creator when contenders race for the same directory'
        return 0
    fi
    printf ''
}

# select_from prints the first acceptable candidate and returns 0, else returns 1.
select_from() {
    local candidate reason
    for candidate in "$@"; do
        [ -n "$candidate" ] || continue
        reason="$(reject_reason "$candidate")"
        if [ -n "$reason" ]; then
            log "rejected ${candidate}: ${reason}" >&2
            continue
        fi
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
}

# candidates lists implementations to consider, most specific first. The two GNU-prefixed
# names are what distributions provide when a differently named implementation owns the
# plain `mkdir` name.
candidates() {
    if [ -n "${LOCK_MKDIR_GNU:-}" ]; then
        printf '%s\n' "$LOCK_MKDIR_GNU"
    fi
    command -v gnumkdir 2>/dev/null || true
    command -v gmkdir 2>/dev/null || true
    command -v mkdir 2>/dev/null || true
    printf '%s\n' /usr/bin/mkdir /bin/mkdir
}

# install_shim creates a fresh directory holding exactly one entry, a `mkdir` symlink to the
# selected implementation, and prints that directory. The directory is unique per invocation:
# a predictable path that is deleted and re-created would let one run remove another run's
# shim, and would delete a path it does not own.
install_shim() {
    local bin="$1" base="${2:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}" shim count
    if [ ! -d "$base" ]; then
        echo "::error::cannot create the mkdir shim: ${base} is not a directory"
        return 1
    fi
    if ! shim="$(mktemp -d "${base%/}/lock-mkdir-shim.XXXXXXXX")"; then
        echo "::error::could not create a unique mkdir shim directory under ${base}"
        return 1
    fi
    ln -s "$bin" "$shim/mkdir"
    count="$(find "$shim" -mindepth 1 -maxdepth 1 | wc -l)"
    if [ "$count" -ne 1 ]; then
        echo "::error::the mkdir shim must contain exactly one entry, found ${count}"
        return 1
    fi
    printf '%s\n' "$shim"
}

# assert_wiring proves the selection reaches a real subprocess. The Go lock tests invoke the
# generated shell as `bash -c <script>`, so a bash subprocess is the same lookup they perform.
#
# The two halves are asserted separately, and that separation is the point: testing only that
# the second call does not succeed accepts an implementation that cannot create anything,
# because its first call fails, the compound short-circuits, and the check reads that as
# exclusivity.
assert_wiring() {
    local shim="$1" resolved probe
    if ! resolved="$(PATH="$shim:$PATH" bash -c 'command -v mkdir')"; then
        echo "::error::a subprocess could not resolve mkdir at all"
        return 1
    fi
    if [ "$resolved" != "$shim/mkdir" ]; then
        echo "::error::a subprocess resolves mkdir to ${resolved}, not ${shim}/mkdir"
        return 1
    fi

    probe="$(mktemp -d)"
    if ! PATH="$shim:$PATH" bash -c "mkdir '$probe/once'"; then
        rm -rf "$probe"
        echo "::error::the selected mkdir could not create a directory in a subprocess"
        return 1
    fi
    if [ ! -d "$probe/once" ]; then
        rm -rf "$probe"
        echo "::error::the selected mkdir reported success in a subprocess but created nothing"
        return 1
    fi
    if PATH="$shim:$PATH" bash -c "mkdir '$probe/once' 2>/dev/null"; then
        rm -rf "$probe"
        echo "::error::the selected mkdir reports success for a directory that already exists"
        return 1
    fi
    rm -rf "$probe"
    log "subprocess wiring: bash -c resolves mkdir=${resolved}, creates on the first call and refuses the second"
}

emit_provenance() {
    local original="$1" selected="$2" shim="$3" line
    local original_version='none' original_package='none'
    if [ -n "$original" ]; then
        original_version="$(version_line "$original")"
        original_package="$(package_label "$original")"
    fi
    local -a entries=(
        "LOCK_MKDIR_ORIGINAL_PATH=${original:-none}"
        "LOCK_MKDIR_ORIGINAL_VERSION=${original_version}"
        "LOCK_MKDIR_ORIGINAL_PACKAGE=${original_package}"
        "LOCK_MKDIR_SELECTED_PATH=${selected}"
        "LOCK_MKDIR_SELECTED_VERSION=$(version_line "$selected")"
        "LOCK_MKDIR_SELECTED_PACKAGE=$(package_label "$selected")"
        "LOCK_MKDIR_SHIM_DIR=${shim}"
    )
    for line in "${entries[@]}"; do
        log "$line"
        if [ -n "${GITHUB_ENV:-}" ]; then
            printf '%s\n' "$line" >>"$GITHUB_ENV"
        fi
    done
    log "scope: ${SCOPE_NOTE}"
    if [ -n "${GITHUB_ENV:-}" ]; then
        printf 'LOCK_MKDIR_SCOPE=%s\n' "$SCOPE_NOTE" >>"$GITHUB_ENV"
    fi
}

fail_closed() {
    local probed="$1"
    echo "::error::no verified exclusive-create mkdir is available for the lock tests"
    log "unsupported environment: none of the probed implementations satisfies the lock contract"
    log "probed: ${probed}"
    log "required: a ${GNU_MARKER} mkdir whose plain 'mkdir DIR' fails when DIR already exists"
    log "the lock tests are not skipped and are not run against an unverified mkdir"
    log "installing a coreutils package is a separate, authorised change; this step installs nothing"
    exit 1
}

# self_test exercises the qualification gate offline with synthetic implementations only.
self_test() {
    local rc=0 shim accepted fake_dir
    fake_dir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$fake_dir'" EXIT

    log "self-test: offline controls for the mkdir qualification gate"

    # Control 1: the gate accepts a real GNU mkdir. This positive control must actually run:
    # a self-test that reports success while its positive is unavailable would claim coverage
    # it does not have.
    local -a cands
    mapfile -t cands < <(candidates)
    if accepted="$(select_from "${cands[@]}" 2>/dev/null)"; then
        log "control accepted-real: PASS (${accepted}, $(version_line "$accepted"))"
    else
        echo "::error::the self-test positive control could not run: no qualified mkdir is available on this host"
        rc=1
    fi

    # Control 2: a candidate that is not present must be refused.
    if select_from "${fake_dir}/absent/mkdir" >/dev/null 2>&1; then
        echo "::error::the gate accepted an absent binary"
        rc=1
    else
        log "control refused-absent: PASS"
    fi

    # Control 3: an implementation whose banner is not GNU must be refused.
    cat >"${fake_dir}/acme-mkdir" <<'FAKE'
#!/bin/sh
case "${1:-}" in
--version) echo 'mkdir (acme) 1.0' ;;
*) exit 1 ;;
esac
FAKE
    chmod +x "${fake_dir}/acme-mkdir"
    if select_from "${fake_dir}/acme-mkdir" >/dev/null 2>&1; then
        echo "::error::the gate accepted a non-GNU implementation"
        rc=1
    else
        log "control refused-non-gnu: PASS"
    fi

    # Control 4: an implementation that claims GNU but reports success for an existing
    # directory must be refused. This is the capability the lock protocol depends on.
    cat >"${fake_dir}/false-success-mkdir" <<FAKE
#!/bin/sh
case "\${1:-}" in
--version) echo 'mkdir (${GNU_MARKER}) 9.9' ;;
*)
    target=''
    for arg in "\$@"; do
        case "\$arg" in -*) ;; *) target="\$arg" ;; esac
    done
    /usr/bin/mkdir "\$@" 2>/dev/null || { [ -d "\$target" ] && exit 0; exit 1; }
    ;;
esac
FAKE
    chmod +x "${fake_dir}/false-success-mkdir"
    if select_from "${fake_dir}/false-success-mkdir" >/dev/null 2>&1; then
        echo "::error::the gate accepted a mkdir that reports success for an existing directory"
        rc=1
    else
        log "control refused-false-success: PASS"
    fi

    # Control 5: the subprocess wiring check must fail when the shim points at that
    # false-success implementation, so a green wiring check means something.
    shim="$(install_shim "${fake_dir}/false-success-mkdir" "$fake_dir")"
    if assert_wiring "$shim" >/dev/null 2>&1; then
        echo "::error::the wiring check passed for a mkdir that reports false success"
        rc=1
    else
        log "control wiring-catches-false-success: PASS"
    fi

    # Control 6: the wiring check must pass for the accepted implementation.
    if [ -n "${accepted:-}" ]; then
        shim="$(install_shim "$accepted" "$fake_dir")"
        if assert_wiring "$shim"; then
            log "control wiring-positive: PASS"
        else
            echo "::error::the wiring check failed for the accepted implementation"
            rc=1
        fi
    fi

    # Control 8: the contention probe must reject the false-success implementation on its
    # own. That probe is what detects an implementation that only false-succeeds when it
    # loses the creation race, which a sequential probe cannot see.
    if contention_create_ok "${fake_dir}/false-success-mkdir"; then
        echo "::error::the contention probe accepted a mkdir that reports false success"
        rc=1
    else
        log "control contention-probe-catches-false-success: PASS"
    fi

    # Control 7: the fail-closed report must exit non-zero and say the environment is
    # unsupported, rather than letting the lock tests be skipped.
    fail_log="${fake_dir}/fail-closed.log"
    if ( fail_closed "synthetic-candidate" ) >"$fail_log" 2>&1; then
        echo "::error::fail_closed returned success"
        rc=1
    elif ! grep -q 'unsupported environment' "$fail_log"; then
        echo "::error::fail_closed did not report an unsupported environment"
        rc=1
    elif ! grep -q 'not skipped' "$fail_log"; then
        echo "::error::fail_closed did not state that the lock tests are not skipped"
        rc=1
    else
        log "control fail-closed-report: PASS"
    fi

    # Control 9: an implementation that never creates anything must be refused by the
    # capability gate. It fails the second call too, so "the second call was refused" on its
    # own would have accepted it.
    cat >"${fake_dir}/never-mkdir" <<FAKE
#!/bin/sh
case "\${1:-}" in
--version) echo 'mkdir (${GNU_MARKER}) 9.9' ;;
*) exit 1 ;;
esac
FAKE
    chmod +x "${fake_dir}/never-mkdir"
    if select_from "${fake_dir}/never-mkdir" >/dev/null 2>&1; then
        echo "::error::the gate accepted an implementation that never creates a directory"
        rc=1
    else
        log "control refused-never-creates: PASS"
    fi

    # Control 10: the wiring check must refuse it as well. A shim can be pointed at any
    # binary, so this is the case a "second call failed" test cannot see.
    shim="$(install_shim "${fake_dir}/never-mkdir" "$fake_dir")"
    if assert_wiring "$shim" >/dev/null 2>&1; then
        echo "::error::the wiring check passed for an implementation that never creates a directory"
        rc=1
    else
        log "control wiring-catches-never-creates: PASS"
    fi

    if [ "$rc" -ne 0 ]; then
        echo "::error::the mkdir qualification gate did not behave as required"
        exit 1
    fi
    log "self-test: all applicable controls passed"
}

main() {
    local original selected shim probed
    local -a cands

    original="$(command -v mkdir 2>/dev/null || true)"
    mapfile -t cands < <(candidates)
    probed="${cands[*]:-none}"

    # stderr keeps the per-candidate rejection reasons in the log; only the selected
    # path is captured, so a failure report says why each candidate was refused.
    if ! selected="$(select_from "${cands[@]}")"; then
        fail_closed "$probed"
    fi

    shim="$(install_shim "$selected")"
    assert_wiring "$shim"
    emit_provenance "$original" "$selected" "$shim"

    if [ -n "${GITHUB_PATH:-}" ]; then
        printf '%s\n' "$shim" >>"$GITHUB_PATH"
    fi
    log "selected ${selected} for this job only (original resolved: ${original:-none})"
}

case "${1:-}" in
--self-test) self_test ;;
--check)
    candidate="${2:?usage: $(basename "$0") --check <path>}"
    reason="$(reject_reason "$candidate")"
    if [ -z "$reason" ]; then
        printf 'accepted %s (%s)\n' "$candidate" "$(version_line "$candidate")"
        exit 0
    fi
    printf 'refused %s: %s\n' "$candidate" "$reason"
    exit 1
    ;;
"") main ;;
*)
    echo "usage: $(basename "$0") [--self-test|--check <path>]" >&2
    exit 2
    ;;
esac
