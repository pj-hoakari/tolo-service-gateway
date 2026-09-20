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
現段階の `server` が公開するのは `/healthz`（liveness）・`/readyz`（readiness）と公開 JWKS だけで、業務 RPC はまだ受け付けない  
`/healthz` はプロセスが応答できる限り 200 を返す  
`/readyz` は登録された準備チェックがすべて成功したときだけ 200 を返し、1 つでも失敗すれば 503 を返す（失敗の内容は応答本文には出さず、サーバー側のログにだけ記録する）  
`/.well-known/jwks.json` は内部 JWT の署名検証用公開鍵を JWKS として返す  
この経路は認証不要で、`Authorization`・`workload-authorization`・`X-Serverless-Authorization`・`DPoP` のどの認証ヘッダが付いていても内容は変わらず、identity も作らない  
返すのは署名鍵と `INTERNAL_JWT_PUBLISHED_KEY_FILES` の公開鍵で、秘密鍵成分（`d`）は含まない  
応答には `Cache-Control: public, max-age=300` と本文から導いた ETag が付き、同じ ETag を `If-None-Match` で送れば 304 を返す

`testbackend`（`http://localhost:8081`）は `server` の JWKS を取得して内部 JWT を検証するテスト用の後段サービスで、`jwtgen` で作った JWKS を配る手順の代わりになる  
現段階の `server` にはまだ業務 RPC の入口が無く、内部 JWT を発行させる経路が無いため、手元で確認できるのはトークンなしの呼び出しが `unauthenticated` になることまでになる

```bash
curl http://localhost:8080/.well-known/jwks.json

curl -X POST -H 'Content-Type: application/json' -d '{"name":"tolo"}' http://localhost:8081/greet.v1.GreetService/Greet
```

前者は kid `dev-key-1` を含む JWKS を返し、後者は `{"code":"unauthenticated"}` を返す

#### 環境変数

| 変数 | 必須 | 既定値 | 内容 |
| --- | --- | --- | --- |
| `SERVER_ADDR` | 任意 | `:8080` | HTTP サーバーの待受アドレス |
| `INTERNAL_JWT_ISSUER` | 必須 | なし | 内部 JWT の issuer ID |
| `INTERNAL_JWT_SIGNING_KEY_FILE` | 必須 | なし | 内部 JWT の署名鍵ファイル（P-256 の EC 秘密鍵の PEM。SEC1 または PKCS#8）のパス。起動時に読み込み、読めない・PEM でない・P-256 でない場合は起動に失敗する |
| `INTERNAL_JWT_SIGNING_KEY_ID` | 必須 | なし | 署名鍵の kid。発行する内部 JWT のヘッダと公開 JWKS に載る |
| `INTERNAL_JWT_PUBLISHED_KEY_FILES` | 任意 | なし | 署名鍵に加えて JWKS へ載せる公開鍵。`kid=パス` をカンマ区切りで並べる（例 `next-key=/etc/tolo/keys/next.pub.pem,old-key=/etc/tolo/keys/old.pub.pem`）。kid は署名鍵のものを含めて重複させられない |
| `IDP_ISSUER` | 任意 | なし | 外部 IdP の issuer。`INTERNAL_JWT_ISSUER` と同じ値は設定エラーになる。外部トークン経路を実装する段階で必須にする |

必須の変数が欠けている場合は設定エラーとして起動に失敗する  
compose を使わずに起動する場合、開発用の署名鍵は `openssl ecparam -name prime256v1 -genkey -noout -out <path>` で生成できる（鍵ファイルはリポジトリに置かない）

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
