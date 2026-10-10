# 提案機構の結合環境

`compose.flow.yml` は、`compose.yml`・`compose.tm.yml`・`compose.ga.yml`・`compose.obs.yml` の上に [tolo-flow-control](https://github.com/pj-hoakari/tolo-flow-control) を加えるオーバーライドになる  
これを重ねると、エッジ端末の計測値が Gateway を通って Observation に届き、Observation が Graph Authoring と Flow Control を呼んで、結果を `optimization_results` に保存するまでを手元で通せる

## 構成

```bash
export COMPOSE_PROJECT_NAME=tolointegration
export COMPOSE_FILE=compose.yml:compose.tm.yml:compose.ga.yml:compose.obs.yml:compose.flow.yml
docker compose up -d --build
```

追加されるサービスは `flow-control` だけになる  
`flow-control` は、tolo-flow-control の既定ブランチ `develop` の固定したコミットを git のビルドコンテキストとしてビルドする  
Flow Control は Gateway を通らない（ADR-0048）。Observation は `compose.obs.yml` の `FLOW_CONTROL_URL`（`http://flow-control:8080`）で直接呼ぶ

| サービス | ホスト | コンテナ内 |
| --- | --- | --- |
| `server`（公開用） | `http://localhost:8080` | `http://server:8080` |
| `fakeidp` | `http://localhost:8082` | `http://fakeidp:8080` |
| `flow-control` | （公開しない） | `http://flow-control:8080` |

tolo-web はこの構成に含めない。観測ページは tolo-web 側で起動し、公開用の `http://localhost:8080` へ送る

片付けは、同じ環境変数のまま `docker compose down -v` を実行する

## 事前データの投入

`scripts/dev/integration-seed.sh` は、公開用 listener 越しに次の順で事前データを作る

1. テナントの作成と所有権の取得
2. イベントの作成
3. `SaveGraph` と `PublishRevision`
4. `RegisterEdgeDevice`
5. `MapObservationPoint`（登録した観測点をノード `gate` に紐づける）

各 RPC の応答は標準エラーに出し、標準出力には作った ID だけを `KEY=value` の形で出す

```bash
./scripts/dev/integration-seed.sh > /tmp/tolo-seed.env
cat /tmp/tolo-seed.env
```

```text
TENANT_ID=c625f67fe594a701
EVENT_ID=c2f08ff259b035ed
EDGE_DEVICE_ID=d5a9986f573b92c7
OBSERVATION_POINT_ID=cb1c56c735d52bc5
```

`RegisterEdgeDevice` の応答にある `observationPageUrl`（`http://localhost:3000/observe/<edge_device_id>`）が、その端末の観測ページになる

## 計測値の送信と結果の確認

エッジ端末として送るときは、fakeidp から `events.report` の `event_access` トークンを取る

```bash
source /tmp/tolo-seed.env
token="$(./scripts/dev/fakeidp-token.sh -k event_access -t "${TENANT_ID}" -e "${EVENT_ID}" -s events.report)"
post() {
    curl -sS -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer ${token}" \
        -d "$2" "http://localhost:8080/$1"
}

post tolo.observation.v1.EdgeDeviceService/Heartbeat "$(jq -nc \
    --arg e "${EVENT_ID}" --arg d "${EDGE_DEVICE_ID}" --arg p "${OBSERVATION_POINT_ID}" \
    '{eventId: $e, edgeDeviceId: $d, activeObservationPointIds: [$p]}')"

post tolo.observation.v1.MeasurementIngestService/ReportMeasurements "$(jq -nc \
    --arg e "${EVENT_ID}" --arg d "${EDGE_DEVICE_ID}" --arg p "${OBSERVATION_POINT_ID}" \
    --arg s "$(date -u -v-30S +%Y-%m-%dT%H:%M:%SZ)" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{eventId: $e, edgeDeviceId: $d, measurements: [{observationPointId: $p, windowStart: $s, windowEnd: $t, countIn: 3, countOut: 1, source: "MEASUREMENT_SOURCE_EDGE"}]}')"

docker compose exec -T observation-db psql -U observation -d observation \
    -c 'select id, verdict, optimization_result is not null as has_result from optimization_results order by id'
```

`date -v-30S` は macOS の書き方で、GNU date では `date -u -d '-30 seconds' ...` になる  
`Heartbeat` を送っていない端末の計測値はサイクルで除外される

| 段階 | 結果 |
| --- | --- |
| `Heartbeat` | `200` |
| `ReportMeasurements` | `200`。`acceptedCount` が `1` |
| 監査ログの `GetCurrentRevision`・`GetObservationPointMappings` | `caller_service=tolo-observation` の記録が `http_status=200` |
| `optimization_results` | `ReportMeasurements` 1 回につき 1 行 |

現状の Observation が Flow Control へ送る要求では、`optimization_results` の `verdict` は `VERDICT_SKIPPED_NO_TRIGGER` になり、`optimization_result` は空のままになる  
Observation は履歴（`HistoryDigest`）を空で送り、観測種別を `VECTOR` に固定し、`CapacityHint` も埋めない。そのため Flow Control の急増・停滞・パンクのどのトリガーも発火しない
