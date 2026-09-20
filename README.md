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

この構成は `keygen`・`server`・`testbackend`・`fakeidp` の 4 つのサービスからなる

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
転送するのは、資格情報を伴わない匿名 RPC と、外部トークンの検証を通った RPC になる  
`DPoP`・`workload-authorization`・`X-Serverless-Authorization` のいずれかが付いた要求は、匿名で呼べる RPC であっても `unauthenticated` を返す（送信者拘束とワークロード認証が未実装のため、匿名へフォールバックしない）  
`Authorization` が付いた要求は外部トークンとして検証し、検証できない場合と `IDP_ISSUER` が未設定の場合は `unauthenticated` を返す（匿名で呼べる RPC でも同じ）  
認証必須の RPC とサービス専用の RPC も、資格情報なしでは `unauthenticated` を返す  
登録表に無い RPC は `unimplemented` を返す  
Connect・gRPC・gRPC-Web のいずれかとして解釈できる POST には、その形式に合わせたエラーを返し、それ以外の要求（GET を含む）には 404 を返す  
後段へは受信ヘッダを 1 つも渡さず、後段の応答ヘッダとトレーラーも外へ返さない  
受信した deadline と cancel は後段へ伝え、残存時間は増やさない（deadline が無いときだけ 30 秒の既定値を使う）  
後段へ到達できない場合は `unavailable` を返し、宛先のホスト名などの詳細は応答に出さずサーバー側のログにだけ記録する

RPC 1 件につき監査ログを 1 行出力する（メッセージは `audit`、項目は `audit` グループにまとめる）  
項目は `method`・`result`・`source_ip`・`http_status`・`trace_id`・`span_id` と、値があるときだけ出る `client_id`・`sub`・`token_use`・`txn`・`jti`・`src_jti`・`origin_sub`・`failure_reason` になる  
外部トークンを受理した場合は `client_id`・`sub`・`token_use`・`txn`・`jti`・`src_jti` が入る（`IDP_ISSUER` が未設定なら資格情報つきの要求はすべて `unauthenticated` になるため、入るのは `method`・`result`・`source_ip`・`http_status`・`trace_id`・`span_id`・`failure_reason` だけになる）  
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
`Ping` は Gateway 経由で通り、`Greet` は外部トークンを付けたときだけ通る（後述「外部トークンの検証」）  
Tenant Management は compose にコンテナが無いため、匿名で呼べる `StartTenantRegistration` も宛先不達の `unavailable` になる

```bash
curl http://localhost:8080/.well-known/jwks.json

curl -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8080/greet.v1.GreetService/Ping

curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer x' -d '{}' http://localhost:8080/greet.v1.GreetService/Ping

curl -X POST -H 'Content-Type: application/json' -d '{"name":"tolo"}' http://localhost:8080/greet.v1.GreetService/Greet

curl -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8080/tolo.tenant.v1.TenantService/StartTenantRegistration
```

上から順に、kid `dev-key-1` を含む JWKS、`{"message":"pong"}`、`{"code":"unauthenticated"}`、`{"code":"unauthenticated"}`、`{"code":"unavailable"}` を返す

#### 外部トークンの検証

`IDP_ISSUER` と `IDP_AUDIENCE` を設定すると外部トークンの検証が有効になる  
未設定なら検証器を持たず、資格情報つきの要求はすべて `unauthenticated` になる  
`server` は起動時に Discovery（`/.well-known/openid-configuration` と `/.well-known/oauth-authorization-server`）をバックグラウンドで解決し、解決できるまで `/readyz` は 503 を返す（この間、匿名 RPC は通り、トークンつきの要求は `unavailable` になる）  
IdP へ届かない・5xx が返るといった一時的な失敗は 5 秒ごとに再試行し続けるが、metadata が設定と食い違う場合や issuer が URL として使えない場合は設定の誤りとしてプロセスが終了する  
受理する claim は Gateway の仕様（`docs/service_gateway_spec.md`）どおりで、IdP の現状に合わせた読み替えは `IDP_LEGACY_EVENTS_WRITE_SCOPE` を除いてしない  
現時点の tolo-idp が発行するトークンは `tenant_id` の形式などが仕様に追随していないため拒否される  
管理系書き込み 6 RPC（ArchiveTenant、ChangeTenantContract、AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole）は、検証と認可を通ったあとに IdP へ失効照会（introspection）を行い、`active` なトークンだけを受理する  
照会の結果は jti 単位で 60 秒キャッシュするため、失効はその範囲で遅れて反映される  
IdP へ照会できないときは当該 6 RPC だけを `unauthenticated`（理由 `introspection_unavailable`）で拒否し、他の RPC は通す  
失効済みと報告されたトークンは `unauthenticated`（理由 `token_revoked`）になる  
`IDP_INTROSPECTION_CLIENT_ID` と `IDP_INTROSPECTION_CLIENT_SECRET_FILE` が未設定なら照会できないため、6 RPC は `introspection_unavailable` で拒否され続ける（起動時に警告を 1 回記録する）  
introspection を設定したのに IdP の metadata に `introspection_endpoint` が無い場合は、設定の誤りとしてプロセスが終了する

`IDP_LEGACY_EVENTS_WRITE_SCOPE=enabled` を設定すると、外部トークンの `events.write` を `events.manage`・`events.operate`・`events.report` の3つとして扱う（既定は無効で、有効なときは起動時に警告を 1 回記録する）  
tolo-idp が ADR-0063 の新しい語彙をまだ発行できないあいだの一時的な措置であり、外部トークンの scope を転記して拡大しないという仕様からの意図的な逸脱にあたる  
有効にすると `events.write` を持つトークンは設計・構成（`events.manage`）・現場運用（`events.operate`）・計測報告（`events.report`）の3つの権限をまとめて得るため、権限を分けた ADR-0063 の狙いはその範囲で失われる  
読み替えは Gateway の認可と後段へ渡す内部 JWT の `scope` の両方に反映され、IdP が新しい scope を発行するようになったら（Issue #20）この設定ごと削除する

compose の `fakeidp`（`http://localhost:8082`）は開発専用の偽 IdP で、`POST /token` の本文をそのまま claim にしたトークンを検証なしで発行する  
`POST /oauth2/introspect` は自分が発行した期限内のトークンを `active` と答え、開発専用の `POST /revoke`（`{"jti":"..."}` または `{"token":"..."}`）で失効させられる  
introspection の client 認証に使う secret は compose の `keygen` が名前付きボリュームへ生成し、`server` と `fakeidp` の両方が読み込み専用で読む  
本番相当の環境へ配備してはならない

```bash
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"token_use":"tenant_access","sub":"user-1","client_id":"admin-ui","scope":"greeting.read","tenant_id":"0123456789abcdef","ttl_seconds":300}' \
  http://localhost:8082/token | jq -r .access_token)

curl -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"tolo"}' http://localhost:8080/greet.v1.GreetService/Greet
```

このトークンでは `Greet` が挨拶を返す  
`scope` を `other.read` にしたトークンでは `permission_denied`、`tenant_id` を `tenant-a` にしたトークンでは `unauthenticated` になる

失効照会は次のように確かめられる

```bash
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"token_use":"tenant_access","sub":"user-1","client_id":"admin-ui","scope":"tenant.write","tenant_id":"0123456789abcdef","ttl_seconds":300}' \
  http://localhost:8082/token | jq -r .access_token)

curl -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id":"0123456789abcdef"}' http://localhost:8080/tolo.tenant.v1.TenantService/ArchiveTenant

curl -X POST -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}" http://localhost:8082/revoke
```

`ArchiveTenant` は認証・認可・失効照会を通り、宛先の Tenant Management が居ないため `unavailable`（`upstream unavailable`）になる  
`/revoke` の後に新しく発行したトークンで同じ RPC を呼ぶと `unauthenticated` になる（同じトークンは 60 秒のキャッシュが切れるまで結果が変わらない）

#### 環境変数

| 変数 | 必須 | 既定値 | 内容 |
| --- | --- | --- | --- |
| `SERVER_ADDR` | 任意 | `:8080` | HTTP サーバーの待受アドレス |
| `INTERNAL_JWT_ISSUER` | 必須 | なし | 内部 JWT の issuer ID |
| `INTERNAL_JWT_SIGNING_KEY_FILE` | 必須 | なし | 内部 JWT の署名鍵ファイル（P-256 の EC 秘密鍵の PEM。SEC1 または PKCS#8）のパス。起動時に読み込み、読めない・PEM でない・P-256 でない場合は起動に失敗する |
| `INTERNAL_JWT_SIGNING_KEY_ID` | 必須 | なし | 署名鍵の kid。発行する内部 JWT のヘッダと公開 JWKS に載る |
| `INTERNAL_JWT_PUBLISHED_KEY_FILES` | 任意 | なし | 署名鍵に加えて JWKS へ載せる公開鍵。`kid=パス` をカンマ区切りで並べる（例 `next-key=/etc/tolo/keys/next.pub.pem,old-key=/etc/tolo/keys/old.pub.pem`）。kid は署名鍵のものを含めて重複させられない |
| `IDP_ISSUER` | 任意 | なし | 外部 IdP の issuer（絶対 HTTP URL。userinfo・query・fragment は持てない）。設定すると外部トークンの検証が有効になる。`INTERNAL_JWT_ISSUER` と同じ値は設定エラーになる |
| `IDP_AUDIENCE` | `IDP_ISSUER` があるとき必須 | なし | 外部トークンに要求する `aud`（バックエンド API 全体の論理 audience。例 `backend-api`）。`IDP_ISSUER` 無しで指定すると設定エラーになる |
| `IDP_ALGORITHMS` | 任意 | `RS256` | 受理する署名アルゴリズムのカンマ区切り。`RS256` と `ES256` だけを指定でき、それ以外の値・空要素・重複と、`IDP_ISSUER` 無しの指定は設定エラーになる |
| `IDP_INTROSPECTION_CLIENT_ID` | 任意 | なし | 失効照会（introspection）を呼ぶための client ID。`IDP_INTROSPECTION_CLIENT_SECRET_FILE` と対で設定する |
| `IDP_INTROSPECTION_CLIENT_SECRET_FILE` | `IDP_INTROSPECTION_CLIENT_ID` があるとき必須 | なし | client secret を 1 行で収めたファイルのパス（末尾の改行は除く）。起動時に 1 回読み込み、読めない・空の場合は起動に失敗する。片方だけの指定と、`IDP_ISSUER` 無しの指定は設定エラーになる |
| `IDP_LEGACY_EVENTS_WRITE_SCOPE` | 任意 | なし | `enabled` を指定したときだけ、外部トークンの `events.write` を `events.manage`・`events.operate`・`events.report` として扱う移行用の読み替えを有効にする。`enabled` 以外の値（`true`・`Enabled`・前後に空白がある `enabled` など）と、`IDP_ISSUER` 無しの指定は設定エラーになる |
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
