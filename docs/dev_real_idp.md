# 実物の IdP での開発

`compose.idp.yml` は、開発用の偽 IdP（`fakeidp`）の代わりに実物の IdP（[tolo-idp](https://github.com/pj-hoakari/tolo-idp)）へ `server` を向けるオーバーライドになる  
tolo-idp 側には何も変更を加えず、`server` の `IDP_ISSUER` と relation のデータだけで噛み合わせている

## 構成

```bash
docker compose -p toloidpcheck -f compose.yml -f compose.idp.yml up -d --build
```

追加されるサービスは `idp`・`idp-db`（PostgreSQL 17）・`idp-redis`（Redis 7。IdP のレート制限に必須）・`idp-relation-stub`（所属の参照先）になる  
base の `fakeidp` は profile `fakeidp` へ退避されるため既定では起動せず、`server` の `depends_on` も `idp` に差し替わる

公開ポートは base（8080〜8082）と重ならないようにずらしてある

| サービス | ホスト | コンテナ内 |
| --- | --- | --- |
| `server` | `http://localhost:18090` | `http://server:8080` |
| `testbackend` | `http://localhost:18091` | `http://testbackend:8080` |
| `idp` | `http://localhost:18080` | `http://idp:8080` |
| `idp-relation-stub` | `http://localhost:18081` | `http://idp-relation-stub:8080` |

issuer はコンテナ内の名前 `http://idp:8080` で統一してある  
`server` の `IDP_ISSUER`、IdP の `TOLO_IDP_ISSUER`、発行されるトークンの `iss` がこの 1 つの文字列で一致し、Discovery の検証が通る  
IdP は Discovery 文書にも `iss` にも設定値をそのまま使い、リクエストの Host を見ないため、ホストから `http://localhost:18080` で叩いてもトークンは取得できる

片付けは `docker compose -p toloidpcheck -f compose.yml -f compose.idp.yml down -v` になる

### イメージ

既定では `ghcr.io/pj-hoakari/tolo-idp:latest` を使う  
このイメージは linux/amd64 の GraalVM native image で AVX2 などを要求するため、arm64 のマシン（Apple Silicon）では Rosetta 上でも起動しない  
その場合は tolo-idp を JVM イメージとして自前でビルドし、`TOLO_IDP_IMAGE` で差し替える

```bash
./gradlew bootJar
printf 'FROM eclipse-temurin:24-jre\nCOPY build/libs/tolo-idp-0.0.1-SNAPSHOT.jar /app/app.jar\nENTRYPOINT ["java","-jar","/app/app.jar"]\n' | docker build -t tolo-idp-local:jvm -f - .
TOLO_IDP_IMAGE=tolo-idp-local:jvm docker compose -p toloidpcheck -f compose.yml -f compose.idp.yml up -d --build
```

### relation のデータ

IdP はログイン時に選んだ tenant の ID をそのまま `tenant_id` claim に載せる（IdP 側の形式は `^[A-Za-z0-9_-]{1,64}$`）  
Gateway は `tenant_id`・`event_id` が 16 桁の小文字 hex であることを要求するため、`config/compose/idp/relation.json` では ID を hex にしてある

`config/compose/idp/relation-nonhex.json` は形式が合わない場合を試すためのデータで、`TOLO_RELATION_DATA` で切り替える

```bash
TOLO_RELATION_DATA=/data/relation-nonhex.json docker compose -p toloidpcheck -f compose.yml -f compose.idp.yml up -d idp-relation-stub idp
```

relation-stub は 1 人のユーザーが所属できる tenant を 1 つに限るため、hex と非 hex を 1 つのファイルには入れられない  
IdP は所属を Redis と DB にキャッシュするので、データを差し替えたら `idp` も作り直す

## トークンの取得

`scripts/dev/idp-token.sh` がログイン・authorize・token の 3 段階を curl で行い、アクセストークンだけを標準出力へ出す

```bash
TOKEN=$(./scripts/dev/idp-token.sh -s "openid tenant.read events.read")
```

| 引数 | 環境変数 | 既定 |
| --- | --- | --- |
| `-u` | `IDP_BASE_URL` | `http://localhost:18080` |
| `-t` | `IDP_TENANT_ID` | `0123456789abcdef` |
| `-s` | `IDP_SCOPE` | `openid tenant.read events.read` |
| `-e` | `IDP_EVENT_ID` | （空。指定すると Token Exchange で `event_access` にする） |

PKCE の verifier と challenge はスクリプト内で `openssl` を使って生成する  
ユーザー・client・redirect_uri は tolo-idp の seed（`TOLO_IDP_SEED_ENABLED=true`）の値を既定にしていて、`IDP_USERNAME`・`IDP_PASSWORD`・`IDP_CLIENT_ID`・`IDP_CLIENT_SECRET`・`IDP_REDIRECT_URI` で変えられる

## 通る RPC と通らない RPC

`tolo-tenant-management` のコンテナは compose に無いため、認証と認可を通った要求は `unavailable`（`upstream unavailable`）で終わる  
これが「実物のトークンが検証・認可・入口変換まで通った」ことの印になる

| RPC | 必要な scope | 結果 | 理由 |
| --- | --- | --- | --- |
| `TenantService/ListEvents` | `events.read` | `unavailable` | 宛先が居ないところまで到達する |
| `RelationAdminService/ListMemberships` | `tenant.read` | `unavailable` | 同上 |
| `TenantService/CreateEvent` | `events.manage` | `permission_denied`（`missing_scope`） | IdP は `events.manage` を発行できない |
| `TenantService/ArchiveTenant` | `tenant.write` | `unauthenticated`（`introspection_unavailable`） | 失効照会が未実装 |
| `TenantService/GetEvent` | — | `permission_denied`（`internal_only`） | 内部オンリーの RPC |

IdP が発行できる scope は `openid`・`tenant.read`・`tenant.write`・`events.read`・`events.write` だけで、登録表が要求する `events.manage`・`tenant.claim`・`greeting.read` は出せない  
これらを必要とする RPC は実物の IdP では試せない

`-e` で得た `event_access` トークンは形式としては Gateway の要求を満たすが、登録表に `external=event_access` の RPC が 1 つも無いため、どの RPC でも `token_use_mismatch` になる

## 既知の制約

Token Exchange には `openid` scope を渡せない（`invalid_scope` になる）ため、スクリプトは交換時に `openid` を落とす  
IdP が発行するトークンには Gateway の仕様に無い `resource` claim（`https://api.example.com/tenants/<tenant_id>` 形式）が入るが、Gateway は無視する  
JWT ヘッダに `typ` は入らず、`alg` は RS256、`kid` は IdP が起動ごとに作る ephemeral な鍵の UUID になる（`TOLO_IDP_JWK_ALLOW_EPHEMERAL=true`）  
アクセストークンの有効期限は 15 分（`event_access` は 10 分）で、`idp` を作り直すと署名鍵が変わるため古いトークンは使えなくなる
