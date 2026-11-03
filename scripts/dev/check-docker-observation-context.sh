#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
fixture_dir="${script_dir}/fixtures"
cd "${repo_root}"

observation_context="${TOLO_OBSERVATION_CONTEXT:-../tolo-observation}"

is_missing_observation_context_failure() {
    local log_file="$1"
    local terminal_error

    terminal_error="$(
        awk '
            /^#[0-9]+ .*ERROR:/ { block = NR }
            /^ERROR: (failed to build|failed to solve):/ { final = NR }
            { line[NR] = $0 }
            END {
                if (final == 0) {
                    exit 1
                }
                start = (block > 0 ? block : final)
                for (i = start; i <= final; i++) {
                    print line[i]
                }
            }
        ' "${log_file}"
    )" || return 1

    printf '%s\n' "${terminal_error}" | grep -q 'failed to solve' || return 1
    printf '%s\n' "${terminal_error}" \
        | grep -Eq 'docker[.]io/library/observation|library/observation|COPY --from=observation|build context.*observation|observation.*build context' \
        || return 1
}

run_matcher_self_test() {
    local failed=0

    if is_missing_observation_context_failure "${fixture_dir}/missing-observation-context.log"; then
        printf 'ok: self-test accepts a missing-observation-context log\n'
    else
        printf 'ERROR: self-test rejected a missing-observation-context log\n' >&2
        failed=1
    fi

    if is_missing_observation_context_failure "${fixture_dir}/unrelated-error-after-copy.log"; then
        printf 'ERROR: self-test accepted a log whose final error is unrelated\n' >&2
        failed=1
    else
        printf 'ok: self-test rejects an unrelated final error after COPY --from=observation\n'
    fi

    if [ "${failed}" -ne 0 ]; then
        exit 1
    fi
}

run_matcher_self_test

skip_or_fail() {
    if [ "${CI:-}" = "true" ] || [ "${CI:-}" = "1" ]; then
        printf 'ERROR: %s (CI must not skip this check)\n' "$1" >&2
        exit 1
    fi
    printf 'skip: %s\n' "$1"
    exit 0
}

command -v docker >/dev/null 2>&1 || skip_or_fail "docker is not installed"
docker info >/dev/null 2>&1 || skip_or_fail "the Docker daemon is not reachable"

case "${observation_context}" in
    *://*|git@*) ;;
    *)
        if [ ! -d "${observation_context}" ]; then
            printf "ERROR: observation build context not found: %s\n" "${observation_context}" >&2
            printf 'clone tolo-observation next to this repository or set TOLO_OBSERVATION_CONTEXT\n' >&2
            exit 1
        fi
        ;;
esac

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/tolo-gateway-observation-context.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

missing_log="${tmp_dir}/without-context.log"
with_log="${tmp_dir}/with-context.log"

if docker build --target server --output type=cacheonly --progress=plain . >"${missing_log}" 2>&1; then
    cat "${missing_log}" >&2
    printf 'ERROR: the server build succeeded without the observation build context\n' >&2
    printf 'the Dockerfile no longer requires --build-context observation=...\n' >&2
    exit 1
fi

if ! is_missing_observation_context_failure "${missing_log}"; then
    cat "${missing_log}" >&2
    printf 'ERROR: the build without the observation context failed for an unrelated reason\n' >&2
    exit 1
fi
printf 'ok: build without the observation context fails for the missing context\n'

if ! docker build --target server --build-context "observation=${observation_context}" --output type=cacheonly . >"${with_log}" 2>&1; then
    cat "${with_log}" >&2
    printf 'ERROR: the server build failed with the observation build context\n' >&2
    exit 1
fi
printf 'ok: build with the observation context succeeds\n'
