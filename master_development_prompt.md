# MASTER DEVELOPMENT PROMPT: 次世代エンタープライズAIセキュリティプラットフォーム（PktSecurity Platform Next）構築指示書

> **【開発エージェントへの実行指示】**
> 本ドキュメントは、ファイル操作・ターミナル実行・ビルド・テスト実行能力を持つ自律型開発エージェント（Antigravity等）が、ゼロから企業向けAIセキュリティプラットフォーム **「PktSecurity Platform Next」** を設計・実装・検証するための完全版マスタープロンプトである。推測やモックで済ませず、以下の全20章の仕様・制約・マイルストーンに従って段階的に実装と実測検証を完遂せよ。

## 第1章：製品の目的と成功条件

### 1.1 ミッション
あなたは、世界トップクラスのソフトウェアアーキテクト、サイバーセキュリティ研究者、パフォーマンスエンジニア、およびフルスタック実装エンジニアを兼ね備えた開発エージェントである。
目標は、単に複数のセキュリティスキャナーの出力を画面に並べるだけのツールではなく、**「ソフトウェアのセキュリティリスクを検出し、関連する証拠（Evidence）を統合・重複排除し、客観的根拠に基づいて重大なリスクを優先順位付けし、AIによる原因調査と検証済み修正パッチ（Unified Diff）の提示・人間による承認を通じて安全な修正へつなげる企業向け統合プラットフォーム」** をゼロから構築することである。

### 1.2 対象ユーザーと成功条件
開発者（Developer）、セキュリティエンジニア（Security Engineer / PSIRT）、セキュリティ管理者（Tenant Admin）、および監査担当者（Auditor）が日常業務で利用できる以下の品質目標を達成することを成功条件とする。
1. **セキュリティとテナント分離（最優先 P0）**：API層およびPostgreSQLの[Row-Level Security (RLS)](https://www.google.com/search?q=https%3A%2F%2Fwww.postgresql.org%2Fdocs%2Fcurrent%2Fddl-rowsecurity.html)による二重のマルチテナント分離と、信頼できない入力リポジトリを安全に処理するサンドボックス隔離が100%自動テストで実証されていること。
2. **検出結果の信頼性と重複排除（P1）**：[OASIS SARIF 2.1.0](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fsarif%2Fsarif%2Fv2.1.0%2Fsarif-v2.1.0.html)および[OWASP CycloneDX 1.6](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2Fspecification%2Foverview%2F)への正規化と、コード編集による行番号ズレに耐性のある2段階フィンガープリント重複排除により、再スキャン時にトリアージ状態（誤検知判定やリスク受容履歴）が失われないこと。
3. **根拠に基づくリスク評価（P1）**：[CVSS v4.0](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fcvss%2Fv4.0%2Fspecification-document)/v3.1、[FIRST EPSS](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fepss%2F)、[CISA KEV](https://www.google.com/search?q=https%3A%2F%2Fwww.cisa.gov%2Fknown-exploited-vulnerabilities-catalog)、到達可能性（Reachability）、資産重要度（Asset Context）を統合した説明可能なスコアを算出し、欠損データを推測で埋めないこと。
4. **高い検索・API性能と同時実行性（P1）**：100万件規模のFindingデータに対してフィルタ・ソート検索のp95 < 100ms、10,000件のSARIF取り込み・重複排除が3.0秒未満で完了することを実測ベンチマークで実証すること。
5. **AIによる調査・修正支援の安全性と有用性（P2）**：事実（Verified Facts）とAIの推論（AI Hypothesis）を厳格に分離し、Unified Diff形式の修正案を隔離サンドボックスで再スキャン検証した上で、人間が承認（Human-in-the-Loop）するワークフローが動作すること。
6. **日本市場への適合（P2）**：経済産業省「[ソフトウェア管理に向けたSBOMの導入に関する手引 Ver2.0](https://www.google.com/search?q=https%3A%2F%2Fwww.meti.go.jp%2Fpress%2F2024%2F08%2F20240829001%2F20240829001.html)」および[IPAの脆弱性対策情報](https://www.google.com/search?q=https%3A%2F%2Fwww.ipa.go.jp%2Fsecurity%2Fvuln%2Findex.html)に準拠した日本語UI・日本語監査レポート出力、およびオンプレミス/セルフホスト動作が可能であること。

### 1.3 作業ディレクトリと環境前提
- 想定作業ディレクトリ：`./pkt-security-platform-next`（または実行環境のワークスペースルート）。
- 既存プロジェクトのコードには一切依存せず、独立した新規リポジトリとして構築すること。ローカルの無関係なディレクトリやシステム設定を破壊してはならない。

## 第2章：技術選定とその根拠

性能上の明確なメリットがない多言語化（Polyglotの乱用）や、初期段階での過剰なマイクロサービス分割・外部ミドルウェア乱立を禁止し、以下の技術スタックを採用する。

| 領域 | 採用技術 | 選定根拠と役割分担 |
| :--- | :--- | :--- |
| **メインバックエンド & 非同期ワーカー** | **C# (.NET 8 LTS または環境内の最新 .NET 8/9/10)** + **[ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0) (Kestrel)** | Kestrelによる最高水準の非同期I/Oスループット、`Utf8JsonReader` / `Span<T>` / `System.Text.Json` Source Generatorによる巨大SARIF・SBOM JSONの省メモリ高速解析、`BackgroundService` によるワーカー制御、および強い静的型付けによる高い保守性を単一言語で実現するため。 |
| **データアクセス層** | **EF Core (`Npgsql.EntityFrameworkCore.PostgreSQL`) + Dapper + `NpgsqlBinaryImporter`** | スキーマ管理・通常CRUD・Global Query Filterによるテナント保護にはEF Core、100万件規模の高速検索クエリにはDapper（または最適化SQL）、1万件単位のFinding一括挿入にはPostgreSQL `COPY` プロトコル（`NpgsqlBinaryImporter`）を併用する。 |
| **データベース & ジョブキュー** | **PostgreSQL 16 / 17** | `ENABLE / FORCE ROW LEVEL SECURITY` によるDB層テナント分離、複合B-Tree / GIN (`pg_trgm`) インデックスによるミリ秒検索、`FOR UPDATE SKIP LOCKED` + `LISTEN/NOTIFY` によるACID保証付きジョブリース管理を単一DBで完結させ、初期の運用複雑性を最小化する。 |
| **フロントエンド** | **TypeScript + React + Next.js (App Router) + Tailwind CSS** | OpenAPIスキーマと同期した型安全なAPI通信、仮想スクロールによる大量Findingの軽快な表示、Unified Diffビューア、日本語/英語UIの構築。 |
| **スキャナー実行・統合** | **[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)**, **[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)**, **[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)**, **[OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner)**, **[Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft)**, **[Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype)** + ネイティブSARIF/CycloneDX解析エンジン | 実績あるOSSスキャナーを `IScannerAdapter` 経由でプロセス隔離実行する。環境に一部CLIバイナリが存在しない場合でも、Dockerコンテナ経由の実行および組み込みの決定論的ルール/ロックファイル検査器＋SARIF/CycloneDXインポーターによりE2Eが100%実動する構成とする。 |

## 第3章：アーキテクチャ

初期から不要なマイクロサービスを乱立させず、**「モジュラーモノリスAPI（`PktSecurity.Api`）＋独立スケール可能なWorkerプロセス（`PktSecurity.Worker`）＋隔離スキャン実行サンドボックス＋Next.js UI（`PktSecurity.Web`）」** の構成を採る。

1. **Web APIプロセスとスキャン実行プロセスの完全分離**
   - `PktSecurity.Api` プロセス内では、外部スキャナープロセスの起動、Gitリポジトリのクローン、アーカイブの展開、巨大SARIFファイルのパースを**一切実行してはならない**。これらはすべてジョブとしてPostgreSQLキューへ登録し、`PktSecurity.Worker` が非同期に処理する。
2. **将来の技術変更を容易にする5つの抽象化境界（Clean Interfaces）**
   - `IJobQueueProvider`：初期実装はPostgreSQL `FOR UPDATE SKIP LOCKED`。将来Redis StreamsやKafkaへ差し替え可能にする。
   - `ISandboxExecutionProvider`：初期実装は制限付きDocker/Podmanコンテナ（本番Linuxでは[gVisor runsc](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fgvisor)指定可能）およびOSレベル制限付きプロセス実行。
   - `IScannerAdapter`：各スキャナーの起動引数構築・出力検証・正規化をカプセル化。
   - `IFindingSearchService`：初期実装はPostgreSQL複合インデックス＋Keysetページネーション。将来OpenSearch等へ差し替え可能にする。
   - `IAiRemediationProvider`：OpenAI互換API / Anthropic / ローカルLLM（Ollama / vLLM）およびオフライン時の決定論的修正テンプレート生成器を切り替え可能にする。

## 第4章：モジュール構成とディレクトリ構造

リポジトリは以下の構成で構築し、レイヤー間の依存方向（`Domain` ← `Application` ← `Infrastructure` ← `Api` / `Worker`）を厳守せよ。`Domain` は外部NuGetパッケージへの依存を持たない純粋なC#モデルとする。

```text
pkt-security-platform-next/
├── README.md
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── docker-compose.yml
├── Directory.Build.props
├── PktSecurityPlatform.sln
├── docs/
│   ├── architecture.md
│   ├── api-spec.md
│   ├── security-verification.md
│   └── benchmark-report.md
├── src/
│   ├── PktSecurity.Domain/           # エンティティ、値オブジェクト、リスク評価純粋関数、重複排除ハッシュ計算
│   ├── PktSecurity.Application/      # ユースケース、DTO、FluentValidation、5つの抽象化インターフェース
│   ├── PktSecurity.Infrastructure/   # EF Core/Dapper、RLS Interceptor、PostgresJobQueue、SARIF/CycloneDXパーサー、Sandbox/AI実装
│   ├── PktSecurity.Api/              # ASP.NET Core Minimal APIs/Controllers、JWT/API Key認証、RBAC、RateLimiter、RFC9457、SSE
│   ├── PktSecurity.Worker/           # BackgroundService、ジョブリース・ハートビート、隔離スキャン実行、バルクDB保存
│   └── PktSecurity.Web/              # Next.js (TypeScript + Tailwind CSS) フロントエンド
├── tests/
│   ├── PktSecurity.UnitTests/        # ドメインロジック、重複排除、リスク算出、パーサー、セキュリティ境界の単体テスト
│   ├── PktSecurity.IntegrationTests/ # E2E APIフロー、PostgreSQL RLS分離、ジョブ再試行・冪等性、攻撃耐性の統合テスト
│   └── PktSecurity.Benchmarks/       # 10万〜100万件検索性能、1万件SARIF取り込み性能の実測ベンチマークハーネス
└── samples/
    ├── sample-vulnerable-repo/       # E2E検証用サンプル（脆弱コード、package-lock.json/requirements.txt、ダミー秘密鍵）
    ├── sample-sarif/                 # Trivy / Semgrep / Gitleaks 実形式SARIFテストデータ
    └── sample-sbom/                  # CycloneDX 1.6 実形式SBOMテストデータ
```

## 第5章：データモデル設計

以下のエンティティ群をPostgreSQL上に実装せよ。グローバルマスタ（`vulnerabilities`, `packages`）と `organizations`, `tenants` 自身を除くすべてのテーブルに `tenant_id UUID NOT NULL` を持たせ、外部キー整合性とインデックスを定義すること。

1. **IAM・マルチテナント**：`organizations`, `tenants`, `users`, `roles`, `permissions`, `user_tenant_roles`, `api_keys`
2. **資産・プロジェクト**：`projects`（`business_criticality`, `is_internet_facing`, `data_sensitivity` を保持）, `repositories`（認証情報は暗号化カラム `encrypted_credential` に保存）
3. **スキャン・ジョブ管理**：`scanners`, `scans`, `scan_jobs`（`status`, `priority`, `idempotency_key`, `lease_owner`, `leased_until`, `heartbeat_at`, `attempt_count`, `max_attempts`, `cancel_requested`, `execution_duration_ms`）
4. **Finding（検出結果）・証拠・履歴**：
   - `findings`：高速一覧検索のため、`severity`, `risk_score`, `confidence`, `status`, `category`, `scanner_name`, `cwe_id`, `cve_id`, `package_purl`, `installed_version`, `fixed_version`, `file_path`, `start_line`, `enclosing_symbol`, `is_kev`, `epss_score`, `reachability`, `primary_fingerprint`, `secondary_fingerprint`, `correlation_group_id`, `occurrence_count`, `first_seen_scan_id`, `last_seen_scan_id` をテーブル直下のカラムとして保持する。
   - `finding_evidences`：サイズが大きい `code_snippet_redacted`, `code_flow_json`, `raw_sarif_result_json` を別テーブルに分離し、`findings` テーブルのページキャッシュ効率を最大化する。
   - `finding_status_history`：トリアージ状態変更の履歴（変更者、変更前後ステータス、理由、承認者、有効期限）を記録する。
5. **脆弱性・SBOM・サプライチェーン**：`vulnerabilities`, `sbom_documents`, `packages`, `project_dependencies`（`is_direct`, `depth`, `dependency_path_json`）, `vex_statements`（[OpenVEX](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fopenvex%2Fspec)準拠）
6. **リスク評価・AI修正・監査・通知**：`risk_assessments`（スコア内訳と算出式バージョンを保存）, `remediations`（`verified_facts_json`, `ai_hypothesis_analysis`, `proposed_unified_diff`, `verification_status`, `approval_status`）, `audit_events`（`prev_event_hash`, `event_hash` によるハッシュチェーン）, `integrations`, `notifications`

### 必須インデックス設計
- `CREATE INDEX ix_findings_tenant_status_risk ON findings (tenant_id, status, risk_score DESC, id DESC);`
- `CREATE INDEX ix_findings_tenant_project_sev ON findings (tenant_id, project_id, severity, risk_score DESC, id DESC);`
- `CREATE UNIQUE INDEX ux_findings_tenant_project_fp1 ON findings (tenant_id, project_id, primary_fingerprint);`
- `CREATE INDEX ix_findings_tenant_project_fp2 ON findings (tenant_id, project_id, secondary_fingerprint) WHERE status != 'Closed';`
- `pg_trgm` を用いた `title`, `file_path`, `package_purl`, `cve_id` のGINインデックス。

## 第6章：API設計方針

1. **OpenAPI 3.1とバージョニング**：全エンドポイントを `/api/v1/...` 配下に設計し、OpenAPI定義を自動生成せよ。
2. **Keyset（Cursor）ページネーションの強制**：`/api/v1/findings` 等の大量データ一覧では、遅い `OFFSET` を禁止し、`cursor`（`(risk_score, id)` のエンコード文字列）と `limit`（最大200、デフォルト50）によるKeysetページネーションを実装せよ。
3. **エラー形式の統一**：すべてのエラー応答を[RFC 9457 Problem Details](https://www.google.com/search?q=https%3A%2F%2Fwww.rfc-editor.org%2Frfc%2Frfc9457.html)（`application/problem+json`）に統一し、`type`, `title`, `status`, `detail`, `instance`, `traceId`, `errors` を返却せよ。内部例外のスタックトレースや生SQLエラーは絶対に外部へ返してはならない。
4. **レート制限と冪等性**：ASP.NET Core `RateLimiter` によるテナント/IP単位のレート制限と、`POST /api/v1/projects/{id}/scans` における `Idempotency-Key` ヘッダによる重複実行防止を実装せよ。
5. **リアルタイム進捗配信**：`GET /api/v1/scans/{id}/events` にてServer-Sent Events（SSE）を提供し、ジョブの状態変化と進捗率をリアルタイムにクライアントへストリーム配信せよ。

## 第7章：セキュリティ要件（検証可能な実装仕様）

製品自身の安全性を担保するため、以下の要件をすべてコードとして実装し、統合テストで検証せよ。
1. **マルチテナントのDB層強制分離（RLS）**：
   - API層のクレーム検証とEF Core Global Query Filterに加え、Npgsqlの `DbConnectionInterceptor` で接続確立時に `SELECT set_config('app.current_tenant_id', @tenantId, true);` を実行せよ。
   - 全テナントテーブルに対し以下のDDLを実行せよ。
     ```sql
     ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
     ALTER TABLE findings FORCE ROW LEVEL SECURITY;
     CREATE POLICY tenant_isolation_policy ON findings
         USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
         WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
     ```
2. **RBAC（5ロールの厳格な権限境界）**：`SystemAdmin`, `TenantAdmin`, `SecurityEngineer`, `Developer`, `Auditor` を実装せよ。`Auditor` は全変更系APIが `403` となり、`Developer` はリスク受容（`RiskAccepted`）の最終承認を行えない（申請のみ可能、`SecurityEngineer` または `TenantAdmin` が承認）ワークフローを強制せよ。
3. **パストラバーサル（Zip Slip）およびSymlink攻撃対策**：アーカイブ展開時およびファイル参照時、`Path.GetFullPath` 解決後のパスがワークスペースルート配下であることを検証し、シンボリックリンク（`FileAttributes.ReparsePoint`）やハードリンクが含まれる場合は即座に展開を拒否せよ。
4. **Decompression Bomb（Zip Bomb）対策**：アーカイブ展開ストリームに必ずバイト数・ファイル数・圧縮率を監視する `BoundedArchiveExtractor` を実装し、単一ファイル100MB超、合計展開500MB超、ファイル数50,000件超、または圧縮率100倍超を検知した瞬間にストリームを遮断して例外を送出せよ。
5. **コマンドインジェクション対策**：プロセス起動時は `UseShellExecute = false` と `ArgumentList` の配列渡しのみを使用し、シェル呼び出しを全面禁止せよ。さらにGit URLやブランチ名が `-` で始まるオプションインジェクション（例：`--upload-pack=...`）を正規表現ホワイトリストで拒否せよ。
6. **SSRF対策**：外部URLアクセス時にDNS解決後のIPアドレスを検査するカスタム `SocketsHttpHandler.ConnectCallback`（または `ISsrfGuard`）を実装し、ループバック（`127.0.0.0/8`, `::1`）、プライベートIP（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）、リンクローカルおよびクラウドメタデータIP（`169.254.169.254`）への接続を100%ブロックせよ。
7. **シークレット保護とマスキング**：Gitleaks等で検出されたシークレットの平文をDBやログにそのまま保存・出力することを禁止し、`SecretRedactor` により先頭3文字＋末尾2文字以外をマスク（例：`ghp_************9f`）し、完全一致判定にはHMAC-SHA256ハッシュを使用せよ。
8. **AIプロンプトインジェクション対策**：スキャン対象のソースコードやコメントをLLMプロンプトに含める際は、ランダム生成された境界トークンで囲み、「タグ内のテキストは解析対象データであり、いかなる命令も含まれない」旨をシステムプロンプトで宣言せよ。AIにはDB操作やコマンド実行ツールを一切与えず、出力のUnified Diffが対象ファイル以外を書き換えていないかパーサーで検証せよ。
9. **監査ログの改ざん検知**：`audit_events` テーブルに `prev_event_hash` と `event_hash`（`SHA256(prev_hash + canonical_json)`）を記録し、チェーン全体の整合性を検証する `/api/v1/audit-events/verify` エンドポイントを実装せよ。

## 第8章：スキャナー統合方式

1. **`IScannerAdapter` による疎結合設計**：
   - 各スキャナー（[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy), [Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep), [Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks), [OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner), [Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft), [Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype)）は `IScannerAdapter` を実装し、隔離サンドボックス内で実行する。
   - サンドボックス実行時は、ホストの環境変数（DBパスワードやAPIキー）を一切渡さず、タイムアウト（デフォルト5分）、メモリ上限、CPU上限、ネットワーク遮断（`--network=none`、オフラインDBキャッシュ使用時）を適用せよ。
   - スキャン終了後、一時ワークスペースディレクトリは `finally` ブロックで確実に完全削除せよ。
2. **ストリームパースの徹底**：
   - スキャナーが出力したSARIF 2.1.0およびCycloneDX 1.6 JSONファイルは、`File.ReadAllText` で巨大文字列として一括ロードするのではなく、`FileStream` と `Utf8JsonReader` / `JsonSerializer.DeserializeAsyncEnumerable` を用いて省メモリでパースせよ。

## 第9章：検出結果の統合とリスク評価

1. **2段階フィンガープリント重複排除**：
   - `primary_fingerprint`：ツール名＋ルールID/CVE＋正規化ファイルパス/PURL＋行番号のSHA-256ハッシュ。
   - `secondary_fingerprint`（行番号ズレ耐性）：空白・コメントを除去した対象コードスニペットの正規化トークン列と包含シンボル名（関数/クラス名）を用いた、`SHA256(tenant_id | project_id | category | cwe_or_cve | file_path | enclosing_symbol | normalized_tokens_hash)`。
   - 再スキャン時に行番号が変わっていても、`secondary_fingerprint` が一致する同一ファイル内の未解決Findingがあれば、新規作成せず既存Findingの行番号・最終検出スキャンID・出現回数を更新し、トリアージ状態を維持せよ。
2. **異種スキャナー間のクロス相関（`correlation_group_id`）**：
   - 複数スキャナーが同一パッケージ＋同一CVE、または同一ファイル・近接行＋同一CWEを報告した場合、同一の `correlation_group_id` を付与して証拠を統合し、確信度（`confidence`）を引き上げよ。
3. **根拠に基づく決定論的リスク評価**：
   - CVSS（v4.0/v3.1）またはCWE基本重要度（最大40点）＋ 脅威情報（CISA KEV該当で+20点、EPSSスコア×10で最大10点）＋ 到達可能性（Reachable=+20点、PotentiallyReachable=+10点、NoPathFound=+2点）に、プロジェクトの資産重要度・外部公開係数を掛け合わせて `0.0〜100.0` のスコアを算出せよ。
   - **厳守事項**：EPSSやKEVが存在しないデータに対して推測値を埋めてはならない。存在しない項目は `missing_inputs_json` に明記せよ。

## 第10章：AIによる調査・修正支援

1. **事実と推論の分離スキーマ**：
   - AI修正支援の出力は必ず以下の構造を持たせよ。
     - `verified_facts`：スキャナー証拠・CVE/CWE・コード位置から直接得られた客観的事実のリスト。
     - `ai_hypothesis_analysis`：脆弱性の原因・影響範囲・攻撃シナリオに関する解説。
     - `proposed_unified_diff`：修正パッチのUnified Diff文字列。
     - `side_effects_warning`：修正による破壊的変更リスクや確認すべきテスト観点。
2. **サンドボックス再スキャンによるパッチ自動検証**：
   - 生成されたUnified Diffを一時ワークスペース上の対象ファイルコピーへ適用し、該当スキャナーを再実行して「対象Findingが消滅し、新たなFindingが発生していないか」を検証し、`verification_status` を `VerifiedFixed` / `PatchAppliesButFindingRemains` / `PatchInvalid` として記録せよ。
3. **Human-in-the-Loop承認**：
   - パッチの初期状態は必ず `PendingReview` とし、権限を持つユーザーが承認API（`POST /api/v1/remediations/{id}/approve`）を呼び出した場合のみ `Approved` へ遷移させよ。

## 第11章：UI・UX要件

`src/PktSecurity.Web` に、バックエンドAPIと完全に連動する日本語ネイティブUIを構築せよ。
1. **統合セキュリティダッシュボード**：リスクスコア上位のFinding、CISA KEV該当アラート、重要度別サマリー、スキャン実行状況。
2. **プロジェクト＆リアルタイムスキャン画面**：プロジェクト作成（ビジネス重要度・外部公開設定）、スキャン起動、SSEによるリアルタイム進捗表示とキャンセル操作。
3. **高速Finding検索・トリアージ画面**：複合フィルタ（重要度、ステータス、KEV、到達可能性、キーワード）とKeysetページネーションによる高速一覧表示。
4. **Finding詳細・証拠・AI修正Diffレビュー画面**：
   - ソースコードハイライトとデータフロー表示、複数スキャナー相関証拠の表示。
   - リスクスコア算出根拠の視覚的ブレークダウン（なぜこの点数なのかの内訳表示）。
   - AI解説（事実と推論の明確な区別表示）、Unified Diff比較ビューア、「サンドボックス再検証」ボタン、「承認 / 却下」ボタン。
5. **SBOM・VEX・レポート出力画面**：依存パッケージ一覧、ファイル再走査なしのSBOM高速再スキャン、OpenVEX登録、およびSARIF / CycloneDX / 経産省SBOM手引書対応の日本語監査レポート出力。

## 第12章：性能測定と最適化

以下の計測項目を測定するベンチマークハーネスを `tests/PktSecurity.Benchmarks` に実装し、実際に実行して結果を `docs/benchmark-report.md` に記録せよ。
1. **必須計測項目と合格基準（Target SLO）**：
   - **Finding検索API（10万〜100万件データ下、複合フィルタ＋リスク順ソート＋Keysetページネーション50件）**：**p50 < 25ms, p95 < 100ms, p99 < 200ms**。
   - **ダッシュボード集計API**：**p50 < 30ms, p95 < 120ms, p99 < 250ms**。
   - **10,000件のFindingを含むSARIF一括取り込み＋2段階重複排除＋リスク算出＋DB保存**：初回 **< 3.0秒**、再スキャン重複排除更新 **< 2.5秒**、ピークメモリ増加量 **< 300MB**。
   - **PostgreSQL実行計画**：`EXPLAIN (ANALYZE, BUFFERS)` により、RLS有効化状態でインデックススキャンが使用され、不要な `Seq Scan` が発生していないこと。
2. **未達時のルール**：
   - 性能目標を達成できなかった場合、目標値を緩めて合格扱いにすることは厳禁とする。必ずボトルネック（N+1クエリ、インデックス不足、過剰アロケーション）を分析・改善し、改善前後の数値を両方記録せよ。

## 第13章：テストと品質保証

テストを後回しにせず、各マイルストーンで以下の自動テストを作成・実行せよ。
1. **単体テスト（`PktSecurity.UnitTests`）**：
   - 2段階フィンガープリント計算（空白・コメント挿入や行番号ズレに対する不変性テスト）。
   - 決定論的リスク評価計算（KEV、EPSS、到達可能性、資産重要度の全組み合わせと、`null` 入力時の非推測テスト）。
   - SARIF 2.1.0 / CycloneDX 1.6 ストリーミングパーサーの正常系・境界値テスト。
2. **統合・セキュリティテスト（`PktSecurity.IntegrationTests`）**：
   - エンドツーエンドフロー（プロジェクト作成→スキャン→ジョブ実行→結果保存→検索→AI修正生成→パッチ検証→承認→エクスポート）。
   - マルチテナント分離テスト（テナントAの認証でテナントBの全リソースにアクセスし100%遮断されること、およびDB RLS単体での遮断確認）。
   - 異常系・攻撃耐性テスト（Zip Slipパストラバーサル、Zip Bomb展開阻止、コマンドインジェクション引数拒否、SSRFプライベートIP遮断、プロンプトインジェクション無力化、監査ログ改ざん検知、ジョブ二重取り込み防止）。

## 第14章：CI/CDパイプライン

リポジトリ内の `.github/workflows/ci.yml` に以下の自動検証パイプラインを定義せよ。
1. **Build & Architecture Check**：`dotnet build --configuration Release -warnaserror` およびレイヤー依存方向テストの実行。
2. **Unit & Integration Tests**：PostgreSQLサービスコンテナを用いた全単体テスト・統合テスト・セキュリティテストの自動実行。
3. **Frontend Typecheck & Build**：`PktSecurity.Web` の `tsc --noEmit` および本番ビルド検証。
4. **Self-Dogfooding Security Scan**：プラットフォーム自身のコードと依存関係に対するシークレット検査・脆弱性検査・SBOM生成。

## 第15章：運用・監視・障害復旧

1. **OpenTelemetry計装とヘルスチェック**：
   - ASP.NET CoreおよびWorkerにOpenTelemetry（Tracing / Metrics / Structured Logging）を組み込み、スキャン実行時間、キュー滞留数、エラー率、APIレイテンシを計測可能にせよ。
   - `/health/live`（Liveness）および `/health/ready`（DB接続・キュー稼働確認を含むReadiness）エンドポイントを実装せよ。
2. **障害復旧（Lease Recovery & Dead Letter）**：
   - Workerがスキャン途中でクラッシュした場合、`leased_until` 期限切れにより別Workerが自動的にジョブを再取得（最大3回、指数バックオフ）し、3回失敗したジョブは `Failed (DeadLetter)` としてエラー詳細を記録し、キュー全体が詰まらないことを保証せよ。

## 第16章：ドキュメントとライセンス管理

1. **OSSライセンス遵守と `THIRD_PARTY_NOTICES.md` の作成**：
   - 統合する外部スキャナー（[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy): Apache-2.0、[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep): LGPL-2.1、[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks): MIT、[OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner): Apache-2.0、[Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft) / [Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype): Apache-2.0）および使用する全NuGet / npmパッケージのライセンス、著作権表示、利用条件を `THIRD_PARTY_NOTICES.md` に明記せよ。
   - 特にSemgrep（LGPL-2.1）については、コードの静的リンクやプロプライエタリルール（Semgrep Rules License）の無断同梱を行わず、独立した外部CLIプロセスとして呼び出す設計理由と商用利用時の留意事項を明記せよ。
2. **運用・アーキテクチャドキュメント**：
   - `README.md`、`docs/architecture.md`、`docs/api-spec.md`、`docs/security-verification.md`、`docs/benchmark-report.md` を作成し、第三者がクローン直後にビルド・起動・テスト・ベンチマークを再実行できるようにせよ。

## 第17章：マイルストーン定義（M0〜M6）

実装は以下の7段階のマイルストーンに分割し、順番に完遂せよ。

- **M0：環境調査・ソリューション骨格・PostgreSQL RLS基盤の構築**
- **M1：最小エンドツーエンド（Vertical Slice：プロジェクト作成→スキャン実行→結果保存→一覧・詳細・エクスポート）の完成**
- **M2：2段階重複排除・クロススキャナー相関・根拠ベースリスク評価・SBOM/OpenVEX機能の実装**
- **M3：AI調査・Unified Diff修正パッチ生成・サンドボックス再検証・セキュリティ16要件ハードニングの完成**
- **M4：Next.js（TypeScript）フロントエンド全画面の実装とAPI/SSE結合**
- **M5：性能ベンチマークハーネス実装・10万〜100万件規模での実測とボトルネック最適化**
- **M6：CI/CD定義・ライセンス一覧（`THIRD_PARTY_NOTICES.md`）・ドキュメント整備・最終全体検証**

## 第18章：各マイルストーンの完了条件（Definition of Done）

各マイルストーンは以下のすべてを満たした時点でのみ「完了」と判定できる。
1. **M0完了条件**：環境調査ログの記録、全プロジェクトの `dotnet build` 成功、マイグレーション適用、およびPostgreSQL RLSによるテナント間データ遮断テストの実行・合格。
2. **M1完了条件**：`samples/sample-vulnerable-repo` に対するスキャン登録からジョブ実行・SARIF/SBOM取り込み・Finding一覧取得・詳細確認・JSON/CSV/SARIFエクスポートまでがモックなしで一気通貫動作し、E2E統合テストが合格していること。
3. **M2完了条件**：コード行番号を意図的にずらした再スキャンでFindingが増殖せず既存レコードが更新されること、CVSS/EPSS/KEV/Reachability/AssetContextによるリスク評価内訳が保存されること、SBOM高速再照合とOpenVEX除外が単体・統合テストで合格していること。
4. **M3完了条件**：AI修正パッチ（Unified Diff）生成→サンドボックス適用・再スキャン検証→人間による承認フローが動作し、かつZip Slip、Zip Bomb、コマンドインジェクション、SSRF、プロンプトインジェクション、監査ログ改ざん検知の全セキュリティテストが実行・合格していること。
5. **M4完了条件**：`PktSecurity.Web` のTypeScript型チェック・本番ビルドが成功し、ダッシュボード・検索・詳細Diffレビュー・SSE進捗表示・日本語レポート出力がバックエンドと連動して動作すること。
6. **M5完了条件**：ベンチマークハーネスを実際に実行し、検索p50/p95/p99、1万件取り込み時間、メモリ使用量、`EXPLAIN ANALYZE` 結果が `docs/benchmark-report.md` に実測値として記録され、SLOを満たしていること。
7. **M6完了条件**：全テストスイートが0件の失敗で完走し、ライセンス文書・README・最終検証レポートが揃っていること。

## 第19章：最終成果物と検証レポートの形式

全マイルストーン完了時に、以下の構成で最終検証レポートを提出せよ。
1. **環境調査・構築サマリー**：確認したOS/ランタイム/ツール環境と生成されたディレクトリ構造。
2. **機能実装・検証ステータスマトリクス**：各機能について「実装済み」「単体テスト合格」「統合テスト合格」「性能実測済み」の4段階の状態を正確に区別した表。
3. **テスト実行結果の証跡**：実際にターミナルで実行した `dotnet test` およびフロントエンドビルドの実行結果サマリー（成功数・失敗数・実行時間）。
4. **セキュリティ検証レポート**：RLS分離、Zip Bomb/Slip、コマンドインジェクション、SSRF、AIプロンプトインジェクション、監査ログハッシュチェーンの各テストケースと検証結果。
5. **性能ベンチマーク実測レポート**：測定環境（CPU/RAM/OS/DB）、データ件数、p50/p95/p99実測値、1万件取り込み実測時間、ボトルネック改善前後の比較。
6. **残存課題と本番運用に向けた推奨事項**：ローカル環境と本番クラスタ（gVisor / 専用HSM / 商用LLM等）の差異および法務・ライセンス確認事項。

## 第20章：禁止事項と安全上の制約

1. **未実行テスト・未計測ベンチマークの虚偽報告の絶対禁止**：実行していないテストを「合格」と書いたり、推測の性能数値を「実測値」として記載したりすることは重大な規約違反である。環境制約で実行できない項目がある場合は、必ず「未実行（理由：〇〇）」と正直に明記せよ。
2. **ダミー実装・TODO放置での完了宣言の禁止**：空の配列やハードコードされた固定JSONを返すだけのスタブを残して「実装完了」と主張してはならない。
3. **テスト基準やアサーションの改ざん禁止**：テストが失敗した際、テストコード側のアサーションをコメントアウトしたり性能基準を引き下げたりしてパスさせる行為を固く禁じる。
4. **無関係なファイルの変更・危険なコマンドの禁止**：作業ディレクトリ外のファイルを変更・削除したり、ホストOSのセキュリティ設定を弱体化させたりするコマンドを実行してはならない。
