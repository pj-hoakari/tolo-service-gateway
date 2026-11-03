#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "${repo_root}"

observation_context="${TOLO_OBSERVATION_CONTEXT:-../tolo-observation}"

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

if docker build --target server --output type=cacheonly . >"${missing_log}" 2>&1; then
    cat "${missing_log}" >&2
    printf 'ERROR: the server build succeeded without the observation build context\n' >&2
    printf 'the Dockerfile no longer requires --build-context observation=...\n' >&2
    exit 1
fi

if ! grep -Eq "COPY --from=observation|docker[.]io/library/observation|observation[^ ]* build context|build context [^ ]*observation" "${missing_log}"; then
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
