#!/usr/bin/env bash
set -euo pipefail

GATEWAY_BASE_URL="${GATEWAY_BASE_URL:-http://localhost:8080}"
FAKEIDP_BASE_URL="${FAKEIDP_BASE_URL:-http://localhost:8082}"
OWNER_SUB="${OWNER_SUB:-user-owner}"
TENANT_NAME="${TENANT_NAME:-integration-$$-${RANDOM}}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
token_script="${script_dir}/fakeidp-token.sh"

for cmd in curl jq; do
    command -v "${cmd}" >/dev/null 2>&1 || { printf '%s is required\n' "${cmd}" >&2; exit 1; }
done

body=''
status=''

call() {
    local procedure="$1" payload="$2" token="${3:-}"
    local args=(-sS -X POST -H 'Content-Type: application/json' -d "${payload}" -w '\n%{http_code}')
    [ -n "${token}" ] && args+=(-H "Authorization: Bearer ${token}")

    local response
    response="$(curl "${args[@]}" "${GATEWAY_BASE_URL}/${procedure}")"
    status="${response##*$'\n'}"
    body="${response%$'\n'*}"

    printf '\n=== %s -> HTTP %s\n' "${procedure}" "${status}" >&2
    printf '%s\n' "${body}" | jq . >&2 2>/dev/null || printf '%s\n' "${body}" >&2
}

expect() {
    [ "${status}" = "$1" ] || { printf 'expected HTTP %s, got %s\n' "$1" "${status}" >&2; exit 1; }
}

token() {
    FAKEIDP_BASE_URL="${FAKEIDP_BASE_URL}" "${token_script}" "$@"
}

call tolo.tenant.v1.TenantService/StartTenantRegistration \
    "$(jq -nc --arg n "${TENANT_NAME}" '{name: $n, contractPlan: "standard"}')"
expect 200
tenant_id="$(printf '%s' "${body}" | jq -r '.tenant.tenantId')"
claim_token="$(printf '%s' "${body}" | jq -r '.ownershipClaimToken')"

registration_token="$(token -k registration -b "${OWNER_SUB}" -s 'tenant.claim')"
call tolo.tenant.v1.TenantService/ClaimTenantOwnership \
    "$(jq -nc --arg t "${tenant_id}" --arg c "${claim_token}" '{tenantId: $t, ownershipClaimToken: $c}')" \
    "${registration_token}"
expect 200

owner_token="$(token -k tenant_access -b "${OWNER_SUB}" -t "${tenant_id}" -s 'tenant.read tenant.write events.read events.manage')"
call tolo.tenant.v1.TenantService/CreateEvent \
    "$(jq -nc --arg t "${tenant_id}" '{tenantId: $t, name: "integration-expo", type: "EVENT_TYPE_SHORT_TERM"}')" \
    "${owner_token}"
expect 200
event_id="$(printf '%s' "${body}" | jq -r '.event.eventId')"

manage_token="$(token -k event_access -b "${OWNER_SUB}" -t "${tenant_id}" -e "${event_id}" -s 'events.manage')"
call tolo.graph.v1.GraphAuthoringService/SaveGraph "$(jq -nc --arg e "${event_id}" '{
    eventId: $e,
    document: {
        nodes: [
            {nodeId: "gate", nodeType: "NODE_TYPE_BOUNDARY", labels: {ja: "入場ゲート"}, layout: {x: 0, y: 0}},
            {nodeId: "hall", nodeType: "NODE_TYPE_GOAL", labels: {ja: "ホール"}, layout: {x: 120, y: 0}}
        ],
        edges: [{edgeId: "gate-hall", sourceNodeId: "gate", targetNodeId: "hall", direction: "EDGE_DIRECTION_ONE_WAY"}]
    }
}')" "${manage_token}"
expect 200

call tolo.graph.v1.GraphAuthoringService/PublishRevision "$(jq -nc --arg e "${event_id}" '{eventId: $e}')" "${manage_token}"
expect 200

call tolo.observation.v1.EdgeDeviceService/RegisterEdgeDevice \
    "$(jq -nc --arg e "${event_id}" '{eventId: $e, name: "gate-counter", observationPointNames: ["gate"]}')" \
    "${manage_token}"
expect 200
device_id="$(printf '%s' "${body}" | jq -r '.device.edgeDeviceId')"
point_id="$(printf '%s' "${body}" | jq -r '.device.observationPoints[0].observationPointId')"

call tolo.graph.v1.GraphAuthoringService/MapObservationPoint \
    "$(jq -nc --arg e "${event_id}" --arg p "${point_id}" '{eventId: $e, mapping: {observationPointId: $p, anchor: {pointId: "gate"}}}')" \
    "${manage_token}"
expect 200

printf 'TENANT_ID=%s\nEVENT_ID=%s\nEDGE_DEVICE_ID=%s\nOBSERVATION_POINT_ID=%s\n' \
    "${tenant_id}" "${event_id}" "${device_id}" "${point_id}"
