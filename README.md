# tolo-service-gateway

## 開発

### セットアップ
miseを使用して開発環境をセットアップ

```bash
mise trust
mise install
task proto
```

### Docker Compose での起動

Docker Compose で開発サーバーを起動できる

```bash
docker compose up --build
```

もしくは
```bash
task up:build
```

この構成は `keygen`・`server`・`testbackend` の 3 つのサービスからなる

`keygen` は開発用の署名鍵を名前付きボリューム `internal-jwt-keys` へ 1 度だけ生成する init サービスで、`server` はその鍵を読み込み専用でマウントして使う  
鍵はコンテナの外に出ず、リポジトリにもイメージにも含まれない  
鍵がすでにボリュームにあれば `keygen` は何もしないため、起動を繰り返しても鍵は変わらない  
鍵を作り直すには `docker compose down -v` でボリュームごと削除してから起動し直す

サーバーは `http://localhost:8080` で待ち受ける（停止は `task down`）  
現段階の `server` が公開するのは `/healthz`（liveness）・`/readyz`（readiness）・公開 JWKS と、匿名で呼べる業務 RPC になる  
`/healthz` はプロセスが応答できる限り 200 を返す  
`/readyz` は登録された準備チェックがすべて成功したときだけ 200 を返し、1 つでも失敗すれば 503 を返す（失敗の内容は応答本文には出さず、サーバー側のログにだけ記録する）  
`/.well-known/jwks.json` は内部 JWT の署名検証用公開鍵を JWKS として返す  
この経路は認証不要で、`Authorization`・`workload-authorization`・`X-Serverless-Authorization`・`DPoP` のどの認証ヘッダが付いていても内容は変わらず、identity も作らない  
返すのは署名鍵と `INTERNAL_JWT_PUBLISHED_KEY_FILES` の公開鍵で、秘密鍵成分（`d`）は含まない  
応答には `Cache-Control: public, max-age=300` と本文から導いた ETag が付き、同じ ETag を `If-None-Match` で送れば 304 を返す

`server` は起動時に RPC 登録表（公開 proto の認可ポリシーと宛先の束縛）を導出し、宛先設定と突き合わせ、登録済み service ごとに型付き委譲のハンドラーを立てる  
現段階で実際に転送するのは、資格情報を伴わない匿名 RPC だけになる  
`Authorization`・`DPoP`・`workload-authorization`・`X-Serverless-Authorization` のいずれかが付いた要求は、匿名で呼べる RPC であっても `unauthenticated` を返す（外部トークン検証とワークロード認証が未実装のため、匿名へフォールバックしない）  
認証必須の RPC とサービス専用の RPC も、資格情報なしでは `unauthenticated` を返す  
登録表に無い RPC は `unimplemented` を返す  
Connect・gRPC・gRPC-Web のいずれかとして解釈できる POST には、その形式に合わせたエラーを返し、それ以外の要求（GET を含む）には 404 を返す  
後段へは受信ヘッダを 1 つも渡さず、後段の応答ヘッダとトレーラーも外へ返さない  
受信した deadline と cancel は後段へ伝え、残存時間は増やさない（deadline が無いときだけ 30 秒の既定値を使う）  
後段へ到達できない場合は `unavailable` を返し、宛先のホスト名などの詳細は応答に出さずサーバー側のログにだけ記録する

RPC 1 件につき監査ログを 1 行出力する（メッセージは `audit`、項目は `audit` グループにまとめる）  
項目は `method`・`result`・`source_ip`・`http_status`・`trace_id`・`span_id` と、値があるときだけ出る `client_id`・`sub`・`token_use`・`txn`・`jti`・`src_jti`・`origin_sub`・`failure_reason` になる  
外部トークンを受理した場合は `client_id`・`sub`・`token_use`・`txn`・`jti`・`src_jti` が入る（外部トークンの検証器はまだ配線しておらず、資格情報つきの要求は `unauthenticated` になるため、現段階で入るのは `method`・`result`・`source_ip`・`http_status`・`trace_id`・`span_id`・`failure_reason` だけ）  
監査ログは `LOG_LEVEL` に依らず必ず出力する  
登録表に無い RPC・RPC として解釈できない要求（GET を含む）は監査の対象にせず、ログも出さない

ログと監査の相関には W3C Trace Context の trace-id を使う  
Gateway は外部に面しているため、受信した `traceparent` を引き継がず、要求ごとに新しいトレースを始める  
trace-id は OTLP のエクスポート設定が無くても採番され、後段へは `traceparent` として伝わる（後段の span は Gateway の span の子になる）  
相関 ID を応答ヘッダで返すことはしない

`source_ip` は `TOLO_GATEWAY_TRUSTED_PROXY_HOPS` が 0（既定）なら接続元アドレスのホスト部になる  
n が 1 以上なら、すべての `X-Forwarded-For` の値を出現順に並べた列の右から n 番目を採り、要素が足りない場合や IP アドレスでない場合は接続元アドレスへ戻す  
`Forwarded`・`X-Real-Ip` などほかの転送ヘッダは読まない

`testbackend`（`http://localhost:8081`）は `server` の JWKS を取得して内部 JWT を検証するテスト用の後段サービスで、`jwtgen` で作った JWKS を配る手順の代わりになる  
`greet.v1.GreetService/Greet` は内部 JWT を要求するが、`greet.v1.GreetService/Ping` は匿名で呼べる  
`Ping` は Gateway 経由で通り、`Greet` は内部 JWT の発行経路がまだ無いため Gateway で `unauthenticated` になる  
Tenant Management は compose にコンテナが無いため、匿名で呼べる `StartTenantRegistration` も宛先不達の `unavailable` になる

```bash
curl http://localhost:8080/.well-known/jwks.json

curl -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8080/greet.v1.GreetService/Ping

curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer x' -d '{}' http://localhost:8080/greet.v1.GreetService/Ping

curl -X POST -H 'Content-Type: application/json' -d '{"name":"tolo"}' http://localhost:8080/greet.v1.GreetService/Greet

curl -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8080/tolo.tenant.v1.TenantService/StartTenantRegistration
```

上から順に、kid `dev-key-1` を含む JWKS、`{"message":"pong"}`、`{"code":"unauthenticated"}`、`{"code":"unauthenticated"}`、`{"code":"unavailable"}` を返す

#### 環境変数

| 変数 | 必須 | 既定値 | 内容 |
| --- | --- | --- | --- |
| `SERVER_ADDR` | 任意 | `:8080` | HTTP サーバーの待受アドレス |
| `INTERNAL_JWT_ISSUER` | 必須 | なし | 内部 JWT の issuer ID |
| `INTERNAL_JWT_SIGNING_KEY_FILE` | 必須 | なし | 内部 JWT の署名鍵ファイル（P-256 の EC 秘密鍵の PEM。SEC1 または PKCS#8）のパス。起動時に読み込み、読めない・PEM でない・P-256 でない場合は起動に失敗する |
| `INTERNAL_JWT_SIGNING_KEY_ID` | 必須 | なし | 署名鍵の kid。発行する内部 JWT のヘッダと公開 JWKS に載る |
| `INTERNAL_JWT_PUBLISHED_KEY_FILES` | 任意 | なし | 署名鍵に加えて JWKS へ載せる公開鍵。`kid=パス` をカンマ区切りで並べる（例 `next-key=/etc/tolo/keys/next.pub.pem,old-key=/etc/tolo/keys/old.pub.pem`）。kid は署名鍵のものを含めて重複させられない |
| `IDP_ISSUER` | 任意 | なし | 外部 IdP の issuer。`INTERNAL_JWT_ISSUER` と同じ値は設定エラーになる。外部トークン経路を実装する段階で必須にする |
| `TOLO_GATEWAY_DESTINATIONS_FILE` | 必須 | なし | 宛先設定ファイル（JSON）のパス。起動時に読み込み、読めない・形式が不正・RPC 登録表と噛み合わない場合は起動に失敗する |
| `TOLO_GATEWAY_TRUSTED_PROXY_HOPS` | 任意 | `0` | 信頼する前段プロキシの段数（0〜16 の整数）。監査ログの `source_ip` を `X-Forwarded-For` の右から何番目で採るかを決める。範囲外の値と整数でない値は設定エラーになる |

必須の変数が欠けている場合は設定エラーとして起動に失敗する  
compose を使わずに起動する場合、開発用の署名鍵は `openssl ecparam -name prime256v1 -genkey -noout -out <path>` で生成できる（鍵ファイルはリポジトリに置かない）

#### 宛先設定ファイル

`TOLO_GATEWAY_DESTINATIONS_FILE` が指す JSON は、論理サービスID（内部 JWT の aud と同じ名前体系）から後段の接続 URL への対応を持つ

```json
{
  "destinations": {
    "tolo-testbackend": { "url": "http://testbackend:8080" },
    "tolo-tenant-management": { "url": "http://tenant-management:8080" }
  }
}
```

未知のフィールドと、最上位オブジェクトより後ろにある余分なデータは受け付けない  
`destinations` が無い・空、論理サービスIDが空文字、`url` が空はいずれもエラーになる  
`url` の scheme は `http` か `https`、host は必須で、userinfo・query・fragment は持てず、path は空か `/` だけ許す  
RPC 登録表が参照する宛先が設定に無い場合も、設定にあるが登録表から参照されない宛先がある場合もエラーになる  
compose では `config/compose/destinations.json` を `/etc/tolo/gateway/destinations.json` へ読み込み専用でマウントしている

登録表には `greet.v1.GreetService` に加えて Tenant Management の `tolo.tenant.v1.TenantService` と `tolo.relation.v1.RelationAdminService` が入っており、後者2つの宛先は `tolo-tenant-management` になる  
ただし compose にはまだ Tenant Management のコンテナが無いため、これらの RPC は宛先へ到達できず `unavailable` になる

#### 配備についての注意

ワークロード認証（`docs/workload_auth.md` の環境変数契約）はまだ実装されていない  
これを実装するまで、本番相当の環境へこのビルドを配備してはならない  
同じ警告は起動時の構造化ログにも出力される

### トレースの確認（Jaeger）

監視スタックはオーバーライドファイル `compose.o11y.yml` を重ねたときだけ有効になる  
Jaeger が起動し、`server` に OTLP エクスポート用の環境変数（`OTEL_EXPORTER_OTLP_ENDPOINT` など）がセットされる

```bash
docker compose -f compose.yml -f compose.o11y.yml up --build
```

もしくは
```bash
task up:build:o11y
```

Jaeger UI は `http://localhost:16686`（停止は `task down:o11y`）

---

## proto アーティファクトの利用

`.proto` は [ORAS](https://oras.land) で OCI アーティファクト化され、GitHub Container Registry に公開される  
アーティファクト名: `ghcr.io/<owner>/<repo>/proto`

### 取得（pull）

[ORAS CLI](https://oras.land/docs/installation) が必要

```bash
# 出力先ディレクトリに proto を展開（ディレクトリ構造が復元される）
oras pull ghcr.io/pj-hoakari/tolo-service-gateway-proto:latest -o proto

# 例: proto/greet/v1/greet.proto として展開される
```

取得した `.proto` は `buf` や `protoc` の入力としてそのまま利用できる
