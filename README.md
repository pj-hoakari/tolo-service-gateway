# go-service-template

Connect (connect-go) ベースの Go マイクロサービス開発用テンプレートリポジトリ

- HTTP サーバ（ヘルスチェック `GET /healthz` + graceful shutdown）
- Service Gateway 発行の内部 JWT の検証と RPC ごとの認可（`internal-jwt-handling` による JWKS 取得 + ES256 検証。`INTERNAL_JWKS_URL` / `INTERNAL_JWT_ISSUER` / `INTERNAL_JWT_AUDIENCE` で設定）
- 開発・テスト用の JWT / JWKS 生成 CLI（`internal-jwt-handling` 同梱の `go tool jwtgen`）とモック生成用の mockgen（`go.mod` の `tool`）
- OpenTelemetry によるトレーシング（Connect interceptor + OTLP/HTTP exporter。`OTEL_EXPORTER_OTLP_ENDPOINT` 設定時のみ有効）と Jaeger を含む Compose オーバーライド（`compose.o11y.yml`）
- `log/slog` による構造化ログ（Cloud Logging 互換の JSON。`internal/logging`。トレース有効時はトレース ID / スパン ID をレコードに付与）
- マルチステージ Dockerfile（distroless）とコンテナイメージ公開ワークフロー、Docker Compose（`compose.yml` + `task up:*`）
- `buf` による proto の lint / コード生成（connect-go・connect-es）
- `.proto` を ORAS で OCI アーティファクト化し GitHub Container Registry へ公開するワークフロー
- connect-es クライアントの npm publish ワークフロー
- 生成物の drift-check（connect-go）ワークフロー
- `mise` による開発ツール（buf / go / task）のバージョン固定

---

## テンプレート利用時の初期設定

開発を始める前にプロジェクト向けに変更する必要がある  
大部分は `task bootstrap` で自動化できる

### 自動セットアップ（task bootstrap）

テンプレートから作成した新しいリポジトリのクローンで実行する  
`WITH_OPTION=db` を使う場合は、リポジトリ作成時に「Include all branches」を選び、`with-db` ブランチを含めておく必要がある

```bash
mise trust
mise install
```

DB なし
```bash
task bootstrap SERVICE_NAME=<service-name> WITH_OPTION=none
```

DB あり（origin/with-db をマージ）
```bash
task bootstrap SERVICE_NAME=<service-name> WITH_OPTION=db
```

bootstrap は次を行う

- `WITH_OPTION=db` のとき `origin/with-db` を `--no-commit` でマージする
- origin の URL から新しいモジュールパスを求め、`github.com/pj-hoakari/go-service-template` を一括置換する（`gen/` は除外し、再生成で追従させる）
- `go-service-template` を `SERVICE_NAME` に一括置換する（telemetry の `service.name`、内部 JWT の audience、connect-es のパッケージ名の `<repo>` 部分などが追従する）
- `go mod tidy`、`clients/connect-es` の `npm install`、`task proto` で生成物とロックファイルを同期する
- `renovate.json` を `renovate.example.json` の内容で置き換える（example は削除）
- `sync-with-*.yml` とローカルの `with-*` ブランチを削除する
- 完了時に Taskfile.yml から bootstrap タスク自身を削除する

変更はコミットされないので、内容を確認して自分でコミットする  
途中で失敗した場合はタスクが残るので、原因を直して再実行できる

次の項目は bootstrap の対象外なので手動で行う

- npm スコープ `@pj-hoakari`（`clients/connect-es/package.json` の `name` と `publish-client-es.yml` の `scope`）
- リモートの `with-db` ブランチの削除（bootstrap が削除するのはローカルブランチと同期用 workflow のみ）
- README の書き換え

### 1. Go モジュールパス

テンプレートの `github.com/pj-hoakari/go-service-template` を新しいモジュールパスへ置換

| ファイル | 箇所 | 内容 |
| --- | --- | --- |
| `go.mod` | `module` 行 | モジュールパス |
| `cmd/server/main.go` | import | `.../internal/*` の参照 |
| `internal/**`（`internal/infra/connect` / `internal/tenantctx` など） | import | 内部パッケージ間の参照 |
| `buf.gen.go.yaml` | `go_package_prefix` | 生成コードのパッケージ接頭辞 |

生成物（`gen/`）を除いて一括置換

```bash
OLD=github.com/pj-hoakari/go-service-template
NEW=github.com/<owner>/<repo>

# gen/ は再生成で追従
git grep -lz "$OLD" -- ':!gen' | xargs -0 sed -i "s#$OLD#$NEW#g"

go mod tidy
task proto:gen:go
```

### 2. connect-es クライアント（npm パッケージ）

`clients/connect-es` は GitHub Packages に publish される npm クライアント向け実装

| ファイル | 箇所 | 内容 |
| --- | --- | --- |
| `clients/connect-es/package.json` | `name` | `@<scope>/<repo>-client-es` |
| `clients/connect-es/package.json` | `description` | パッケージ説明 |
| `clients/connect-es/package.json` | `repository.url` | 新しいリポジトリ URL |
| `.github/workflows/publish-client-es.yml` | `scope` | `@<owner>` へ（GitHub Packages のスコープと一致） |

`package.json` の `name` を変更し、ロックファイルを同期

```bash
cd clients/connect-es && npm install
```

### 3. Renovate 設定

```bash
mv renovate.example.json renovate.json
```

### 4. その他

- `internal/telemetry/telemetry.go` の `DefaultServiceName` と `compose.o11y.yml` の `OTEL_SERVICE_NAME`（トレースの `service.name` になる）
- `mise.toml` の Go / buf バージョン
    buf の版を変える場合は `.github/workflows/proto-gen-check.yml` の `version:` も揃える
- with-db ブランチと同期用 workflow（`.github/workflows/sync-with-db.yml`）を削除する

---

## 初期設定チェックリスト

`task bootstrap` を使った場合、`bootstrap: `と記した項目は済んでいる

- [ ] bootstrap: Go モジュールパスを `github.com/<owner>/<repo>` に置換（`go.mod` / `cmd/**` / `internal/**` / `buf.gen.go.yaml`）
- [ ] bootstrap: `go mod tidy` を実行
- [ ] bootstrap: `task proto:gen:go` で connect-go を再生成
- [ ] bootstrap: `telemetry.DefaultServiceName` と `compose.o11y.yml` の `OTEL_SERVICE_NAME` を更新

- [ ] bootstrap: connect-es の `package.json`（`name` / `description` / `repository.url`）を更新
- [ ] bootstrap: `clients/connect-es` で `npm install` を実行し `package-lock.json` を同期

- [ ] bootstrap: `renovate.json` を `renovate.example.json` の内容で置き換え（example は削除）
- [ ] bootstrap: `sync-with-*.yml` とローカルの with-* ブランチを削除

下記は手動対応/確認が必要
- [ ] `clients/connect-es/package.json` の `name` のスコープを `@<owner>` に変更
- [ ] `publish-client-es.yml` の `scope` を `@<owner>` に変更
- [ ] リモートリポジトリの with-* ブランチを削除

- [ ] README のテンプレート説明を書き換え

リモートリポジトリのテンプレートブランチ削除は下記
```bash
git push origin --delete with-db
```

---

## ディレクトリ構成

レイヤードアーキテクチャを採用している

```
cmd/server/           エントリポイント（依存の組み立て・DI）
internal/
  domain/             ドメインモデル（エンティティ + 検証。他レイヤに依存しない）
  application/        ユースケース（`GreetUseCases` インターフェース + 実装。domain を使う）
  infra/
    connect/          Connect transport（ハンドラ・認証/認可 interceptor の配線。application に依存）
  logging/            Cloud Logging 互換の slog ハンドラ（severity / message / time + トレース相関フィールド）
  telemetry/          OpenTelemetry トレーシングの配線（OTLP/HTTP exporter + W3C propagator）
  tenantctx/          検証済み内部 JWT からの主体（`sub`）とテナント公開 ID の参照・検証
gen/                  buf による生成コード（手動編集しない）
```

---

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

サーバーは `http://localhost:8080` で待ち受ける（停止は `task down`）  
RPC を呼び出すには Service Gateway 発行の内部 JWT が必要なので、`go tool jwtgen` で生成した JWKS を配信する URL を `INTERNAL_JWKS_URL` で `server` に渡す（後述）

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

トレーシングの配線は `internal/telemetry` にあり、`cmd/server/main.go` の起動時に `telemetry.Setup` で global tracer provider と W3C Trace Context / Baggage propagator を設定する

- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` または `OTEL_EXPORTER_OTLP_ENDPOINT` が設定されているときだけ OTLP/HTTP で span を export する。未設定なら no-op provider で動作し、エラーにはならない（トレーシングはデプロイ環境の opt-in）
- `service.name` は `OTEL_SERVICE_NAME`（デフォルト: `telemetry.DefaultServiceName` = `go-service-template`）
- ヘッダ・TLS・タイムアウトなどその他の `OTEL_EXPORTER_OTLP_*` は exporter がそのまま解釈する
- Connect の RPC は `otelconnect` interceptor（`internal/infra/connect/server.go`）で span になる。Service Gateway の背後で動く前提で `WithTrustRemote()` を指定しており、受信した `traceparent` を span link に落とさず親として継続する
- interceptor は認証の前段に入るため、認証で拒否されたリクエスト（`CodeUnauthenticated` など）も span として記録される
- 終了時は `shutdownTimeout` 内でバッファ済み span を flush する

### ログ

ログは標準出力へ 1 行 1 件の JSON で書き出し、Cloud Logging がそのまま解釈する構造化フォーマット（`severity`、`message`、`time`）に合わせている  
トレースが有効なリクエストでは、その文脈からトレース ID とスパン ID を自動で読み取り、`logging.googleapis.com/trace` などのフィールドとして各レコードに付与する  
このハンドラは `internal/logging` が提供し、`cmd/server/main.go` の起動時に `slog.SetDefault` で既定のロガーとして設定する  
`message` や `severity` のような予約キーと同じ名前の属性は、値が上書きされないように `attr_` 接頭辞付きで出力する  
`net/http` と OpenTelemetry が内部で出すログも同じハンドラに流すので、サーバーのログはこの 1 系統にまとまる

- `LOG_LEVEL`（デフォルト: `info`）: ログに出力する最小レベル。`debug`／`info`／`warn`（`warning` も同義）／`error`／`critical` を取り、未知の値ならサーバーは起動しない
- `GOOGLE_CLOUD_PROJECT`（デフォルト: なし）: 設定するとログの `logging.googleapis.com/trace` を `projects/<project>/traces/<trace_id>` 形式にし、Cloud Logging でトレースと相関させる。未設定なら素のトレース ID を出力する

### connect-es の生成
connect-es の生成（`task proto:gen:es`）はリリース時に CI で行う  
ローカルで実行する場合は `clients/connect-es` の依存（`npm i`）を導入する必要がある

### 内部 JWT の検証と RPC ごとの認可

認証・認可は外部モジュール `github.com/pj-hoakari/internal-jwt-handling` に委ねる  
proto の policy annotation から `protoc-gen-authz-go` が生成するのは procedure ごとの policy 表（`gen/greet/v1/greetv1connect/greet.authz.connect.go` の `GreetServicePolicies`）で、`internal-jwt-handling/interceptor` がこれを読んで Service Gateway 発行の内部 JWT を検証し、`token_use` と宣言された scope を突合する  
検証済みのクレームは request context に載り、ハンドラ以降から参照できる（「テナント ID の参照」を参照）

- 主な検証項目は ES256 の署名、`kid`、`iss`、`aud`、`exp`／`nbf`、`token_use`、`tenant_id` の束縛である。JWKS の取得・キャッシュ・リトライ・レート制限は `jwks.Cache` が持つ
- 既定の `token_use` は `AUTH_LEVEL_AUTHENTICATED` が `tenant_access`、`AUTH_LEVEL_INTERNAL` が `service` で、これと異なる RPC は proto の `token_uses` で宣言する
- `service` トークンは scope の検査を行わない
- proto の annotation（`authz.v1.service_auth_policy` / `authz.v1.auth_policy` の `level`・`required_scopes`・`token_uses`）は宣言のみで、強制は interceptor が行う
- 未認証と `token_use` の不一致は `CodeUnauthenticated`、scope 不足は `CodePermissionDenied` を返す。拒否理由はクライアントには返さず、`internal JWT rejected` として `slog.Warn` でサーバー側にのみ記録する
- `Greet` は `AUTH_LEVEL_AUTHENTICATED` と `greeting.read` スコープを要求する。`token_uses` は宣言しておらず、既定の `tenant_access` に従う

期待値は `cmd/server/main.go` が読む環境変数で設定する

| 環境変数 | デフォルト | 内容 |
| --- | --- | --- |
| `INTERNAL_JWKS_URL` | `http://gateway:8080/.well-known/jwks.json` | JWKS の取得先 |
| `INTERNAL_JWT_ISSUER` | `service-gateway` | 期待する `iss` |
| `INTERNAL_JWT_AUDIENCE` | `go-service-template` | 期待する `aud` |

ハンドラは `NewHandlerWithJWTSettings(greetService, settings)` → `NewHandlerWithVerifier(greetService, tokenVerifier)` の段階的コンストラクタで構成される（`greetService` は `application.GreetUseCases`）  
前者は `JWTSettings{JWKSURL, Issuer, Audience}`（既定値は `DefaultJWTSettings()`、`cmd/server` はこれを環境変数で上書きする）の JWKS URL から `jwks.Cache` と `verifier.Verifier` を組み立てる本番向けの入口で、テストでは後者に verifier を差し替えて渡す  
既定値の定数は `internal/infra/connect/server.go` の `DefaultInternalJWKSURL` / `DefaultInternalJWTIssuer` / `DefaultInternalJWTAudience` である

ローカルでの動作確認には `internal-jwt-handling` 同梱の jwtgen CLI でトークンと JWKS を生成する  
`go.mod` の `tool` に登録してあるので `go tool jwtgen` で実行できる

```bash
# ES256 の内部 JWT と対応する JWKS ドキュメントを JSON で出力
go tool jwtgen -audience go-service-template -tenant-public-id 0123456789abcdef -scope greeting.read -ttl 10m
```

- `-token-use` は `tenant_access`（既定）、`event_access`、`registration`、`service` を取る
- `tenant_access` では `-tenant-public-id`（ランダムな 16 文字 hex）と `-scope` が必須である
- `-issuer` の既定は `service-gateway`、`-audience` に既定はないので `go-service-template` を明示する
- そのほかのフラグは `-event-public-id`、`-origin-sub`、`-subject`、`-txn`、`-kid`（既定 `test-key`）、`-ttl`（既定 2 分）である

出力は `token` / `claims` / `jwks` を持つ JSON である  
`jwks` を任意の HTTP エンドポイント（例: ローカルのファイルサーバ）で配信し、`INTERNAL_JWKS_URL` にその URL を設定すると、`Authorization: Bearer <token>` で呼び出せる  
サービスのテストも同じ生成ロジック（`internal-jwt-handling/jwtgen`）を使用する

### 認証済み主体の参照（tenantctx）

内部 JWT のクレーム（主体の `sub`、テナントの 16 文字 hex 公開 ID である `tenant_id`）は、`internal-jwt-handling` の interceptor が検証済みクレームとして request context に載せる  
`internal/tenantctx` はそのクレーム（`internaljwt.ClaimsFromContext`）から認可判断に使う値だけを読み取る読み取り専用パッケージで、context への注入は行わない

- ハンドラ / ユースケースは `tenantctx.TenantPublicIDFromContext(ctx)` で参照する。値は前後の空白を除いて返し、空なら `ok=false` になる
- 認証済み主体（内部 JWT の `sub`）は `tenantctx.SubjectFromContext(ctx)` で参照する。テナントと同じく前後の空白を除いて返し、空なら `ok=false` になる
- テナント対象操作の認可には `tenantctx.Ensure`（fail-closed）、永続化から復元したモデルの防衛的チェックには `tenantctx.VerifyOwnership`（fail-open）を使う
- テナントが必ず存在することは、`tenant_access` トークンは `tenant_id` を必ず持つというモジュール側の束縛検証と、RPC ごとのポリシー（既定の `token_use` が `tenant_access`）から来る
- テナント非依存の RPC（セルフサインアップ、サービス間呼び出し、公開エンドポイント等）は、proto の `token_uses`（`service` や `registration`）や `AUTH_LEVEL_PUBLIC` で宣言する
- 参照は `internal/tenantctx` を直接 import する。

### エラー

内部エラーは `internal` と固定メッセージ `internal error` だけを返し、原因はサーバー側のログにのみ記録する  
そのログは `message` が `internal error`、`error` 属性が原因という構造化レコードで、トレースが有効なときはトレースのフィールドも付く（「ログ」を参照）  
クライアント都合の中断・締め切り超過は `canceled`／`deadline_exceeded` として返し、サーバー側のログには記録しない  
ハンドラの内部エラーは `InternalError(ctx, err)`（`internal/infra/connect/service.go`）で組み立てる（他の transport からも同じ関数を使う）  
エラーメッセージには内部主キー・テナント名・ユーザー ID などの内部識別子を含めない  
`connectrpc.CodeInternal` の直接使用は golangci-lint の `forbidigo` で禁止しており、許可するのは `InternalError` の中だけである

---

## proto アーティファクトの利用

`.proto` は [ORAS](https://oras.land) で OCI アーティファクト化され、GitHub Container Registry に公開される  
アーティファクト名: `ghcr.io/<owner>/<repo>/proto`

### 取得（pull）

[ORAS CLI](https://oras.land/docs/installation) が必要

```bash
# 出力先ディレクトリに proto を展開（ディレクトリ構造が復元される）
oras pull ghcr.io/pj-hoakari/go-service-template-proto:latest -o proto

# 例: proto/greet/v1/greet.proto として展開される
```

取得した `.proto` は `buf` や `protoc` の入力としてそのまま利用できる
