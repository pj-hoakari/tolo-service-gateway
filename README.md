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

`server` は起動時に RPC 登録表（公開 proto の認可ポリシーと宛先の束縛）を導出し、宛先設定と突き合わせるが、転送はまだ行わない  
そのため現段階では、未知の RPC も登録済みの RPC も `unimplemented` を返す  
Connect・gRPC・gRPC-Web のいずれかとして解釈できる POST には、その形式に合わせたエラーを返し、それ以外の要求（GET を含む）には 404 を返す

`testbackend`（`http://localhost:8081`）は `server` の JWKS を取得して内部 JWT を検証するテスト用の後段サービスで、`jwtgen` で作った JWKS を配る手順の代わりになる  
`greet.v1.GreetService/Greet` は内部 JWT を要求するが、`greet.v1.GreetService/Ping` は匿名で呼べる  
現段階の `server` にはまだ業務 RPC の入口が無く、内部 JWT を発行させる経路が無いため、手元で確認できるのはトークンなしの呼び出しが `unauthenticated` になることまでになる

```bash
curl http://localhost:8080/.well-known/jwks.json

curl -X POST -H 'Content-Type: application/json' -d '{"name":"tolo"}' http://localhost:8081/greet.v1.GreetService/Greet

curl -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8081/greet.v1.GreetService/Ping
```

上から順に、kid `dev-key-1` を含む JWKS、`{"code":"unauthenticated"}`、`{"message":"pong"}` を返す

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
ただし compose にはまだ Tenant Management のコンテナが無いため、宛先は宣言だけで接続はしない

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
