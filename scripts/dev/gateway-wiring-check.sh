#!/usr/bin/env bash
set -euo pipefail

GATEWAY_BASE_URL="${GATEWAY_BASE_URL:-http://localhost:8080}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
token_script="${script_dir}/fakeidp-token.sh"

for cmd in curl jq; do
    command -v "${cmd}" >/dev/null 2>&1 || { printf '%s is required\n' "${cmd}" >&2; exit 1; }
done

failures=0

expect() {
    local want="$1" label="$2" procedure="$3" payload="$4" token="${5:-}"
    local args=(-s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "${payload}")
    [ -n "${token}" ] && args+=(-H "Authorization: Bearer ${token}")

    local got
    got="$(curl "${args[@]}" "${GATEWAY_BASE_URL}/${procedure}")"
    if [ "${got}" = "${want}" ]; then
        printf 'ok: %s -> %s\n' "${label}" "${got}"
    else
        printf 'NG: %s -> %s (want %s)\n' "${label}" "${got}" "${want}" >&2
        failures=$((failures + 1))
    fi
}

greeting="$("${token_script}" -k tenant_access -t 0123456789abcdef -s greeting.read)"
no_scope="$("${token_script}" -k tenant_access -t 0123456789abcdef -s tenant.read)"
event_read="$("${token_script}" -k event_access -t 0123456789abcdef -e fedcba9876543210 -s events.read)"

expect 200 'anonymous Ping reaches testbackend' greet.v1.GreetService/Ping '{}'
expect 401 'Greet without a token' greet.v1.GreetService/Greet '{"name":"tolo"}'
expect 200 'Greet with greeting.read reaches testbackend' greet.v1.GreetService/Greet '{"name":"tolo"}' "${greeting}"
expect 403 'Greet without greeting.read' greet.v1.GreetService/Greet '{"name":"tolo"}' "${no_scope}"
expect 503 'GetGraph to an absent destination' tolo.graph.v1.GraphAuthoringService/GetGraph '{"eventId":"fedcba9876543210"}' "${event_read}"
expect 503 'anonymous StartTenantRegistration is forwarded' tolo.tenant.v1.TenantService/StartTenantRegistration '{"name":"tolo","contractPlan":"standard"}'
expect 503 'anonymous ResolveTenantSubdomain is forwarded' tolo.tenant.v1.TenantService/ResolveTenantSubdomain '{"subdomain":"test"}'
expect 401 'GetEvent without a token' tolo.tenant.v1.TenantService/GetEvent '{"eventId":"fedcba9876543210"}'

if [ "${failures}" -ne 0 ]; then
    printf '%d wiring check(s) failed\n' "${failures}" >&2
    exit 1
fi
printf 'all wiring checks passed\n'
