# 技術選定の結論とアーキテクチャ意思決定記録（ADR）

## 1. 技術選定の基本方針：必要な複雑さと不要な複雑さの峻別

企業向けAIセキュリティプラットフォームの技術選定において最も避けるべき失敗は、「言語やマイクロサービスを増やすこと自体が高度である」という錯覚に陥ることである。複数言語（Polyglot）や分散メッセージブローカーを無秩序に導入すれば、ビルドパイプライン、型定義の同期、認証コンテキストの伝播、デバッグ、障害切り分けのコストが指数関数的に増大し、少人数または開発エージェントによる段階的構築が破綻する。

したがって本設計では、以下の3原則に基づき技術選定を決定した。
1. **単一メインバックエンド言語による凝集性の最大化**：Web API、認証・認可、マルチテナント分離、大量JSON（SARIF/CycloneDX）のストリーム解析、リスクスコアリング、非同期ジョブワーカー、AIオーケストレーションまでを、高性能かつ型安全な単一ランタイム（**C# / [ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0)**）で統一する。
2. **実績ある専門OSSスキャナーのプロセス隔離統合**：SAST、SCA、シークレット検出、SBOM生成は自前で再発明せず、[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)、[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)、[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)、[OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner)、[Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft)、[Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype)を隔離サンドボックス内のアダプター経由で実行する。
3. **インフラ依存の最小化と段階的拡張（PostgreSQL中心設計）**：初期段階からKafka、Elasticsearch、Redis、複数DBを必須とせず、**PostgreSQL 16/17**単体でリレーショナルデータ、Row-Level Security（RLS）、パーティショニング、全文/トライグラム検索（`pg_trgm` / GIN）、およびトランザクショナルなジョブキュー（`FOR UPDATE SKIP LOCKED`）を完結させ、インターフェース抽象化によってのみ将来の外部基盤差し替えを担保する。

## 2. 採用を推奨する技術スタックと選定根拠

| レイヤー / コンポーネント | 採用技術 | 選定の具体的根拠（性能・安全性・保守性） |
| :--- | :--- | :--- |
| **メインバックエンドAPI & ワーカー基盤** | **C# (.NET 8 LTS または .NET 9/10)** / **[ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0) (Kestrel)** | 1) [TechEmpowerベンチマーク](https://www.google.com/search?q=https%3A%2F%2Fwww.techempower.com%2Fbenchmarks%2F)でも実証されているKestrelの圧倒的な非同期HTTPスループットと低レイテンシ。<br>2) `Utf8JsonReader`、`System.Text.Json` Source Generator、`Span<T>`、`ArrayPool<T>` による巨大SARIF/CycloneDXファイル（数十MB〜数百MB）の省メモリ・高速ストリーミング解析。<br>3) `System.Threading.Channels` と `BackgroundService` による堅牢なインプロセス/マルチプロセス非同期ワーカー実装。<br>4) 強い静的型付け、null許容参照型、PolicyベースRBAC、OpenTelemetry標準統合による高いエンタープライズ保守性。 |
| **データアクセス層（ORM / クエリ）** | **Entity Framework Core + Dapper + Npgsql** | 1) 通常の一貫性重視CRUDおよびマイグレーション管理にはEF Coreを使用し、`Global Query Filters` と `DbConnectionInterceptor` でテナント分離を自動化。<br>2) 100万件規模のFinding検索・複雑集計にはDapperまたはコンパイル済みクエリを併用し、ORMオーバーヘッドを排除。<br>3) 大量Findingの一括登録には `NpgsqlBinaryImporter`（PostgreSQL `COPY` プロトコル）を使用し、1万件の挿入を数百ミリ秒で完了させる。 |
| **プライマリデータベース & ジョブキュー** | **PostgreSQL 16 / 17** | 1) `ENABLE ROW LEVEL SECURITY` および `FORCE ROW LEVEL SECURITY` によるデータベースエンジンレベルでの厳格なテナント分離。<br>2) `HASH` または `LIST` パーティショニングと複合B-Tree / GIN（`pg_trgm`、JSONB）インデックスによる高速検索。<br>3) `SELECT ... FOR UPDATE SKIP LOCKED` を用いたACID保証付きのジョブリース管理により、初期構成で外部メッセージブローカーの運用負荷と障害点を排除。 |
| **フロントエンドUI** | **TypeScript / React 19 / Next.js (App Router)** + **Tailwind CSS** + **TanStack Table / Virtual** | 1) 型安全なAPIクライアント生成（OpenAPI → TypeScript自動生成）によりフロント・バック間の型不整合を防止。<br>2) 大量のFinding一覧やSBOM依存ツリーをブラウザフリーズなしに描画するため、仮想スクロール（TanStack Virtual）とサーバーサイドKeysetページネーションを組み合わせる。<br>3) Monaco Editor（または軽量Diffビューア）によるソースコード根拠表示とUnified Diffパッチの視覚的比較・承認UI。 |
| **スキャン実行・隔離サンドボックス** | **Rootless Docker / Podman + [gVisor (runsc)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fgvisor)**（ローカル開発時は制限付きプロセス/コンテナ実行へフォールバック可能） | 1) スキャン対象リポジトリは信頼できない入力であるため、`--network=none`、`--read-only`、`--cap-drop=ALL`、`--security-opt=no-new-privileges`、`--pids-limit`、`--memory`、`--cpus` を強制した使い捨てコンテナ内でスキャナーを実行。<br>2) Linux本番環境ではgVisor（`runsc`）ランタイムを指定することでホストカーネルへのシステムコール直接到達を遮断。 |
| **統合セキュリティスキャナー群** | **[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)**, **[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)**, **[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)**, **[OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner)**, **[Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft)**, **[Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype)** | 1) 業界標準のOSSスキャナーを `IScannerAdapter` インターフェース経由で統合。<br>2) 出力は標準[SARIF 2.1.0](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fsarif%2Fsarif%2Fv2.1.0%2Fsarif-v2.1.0.html)および[CycloneDX 1.6](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2Fspecification%2Foverview%2F)へ正規化し、ツール固有情報は `FindingEvidence` にロスレス保存。 |
| **AI連携・修正支援層** | **C# `Microsoft.Extensions.AI` Abstractions** + **OpenAI / Anthropic Claude / ローカルLLM (Ollama / vLLM)** | 1) 特定の商用LLMへのロックインを避け、クラウドAPIと社内閉域網LLM（Ollama/vLLM）を設定一つで切り替え可能なプロバイダ抽象化を採用。<br>2) Structured Outputs（JSON Schema強制）により、事実・推論・Unified Diffパッチ・注意点を分離取得。 |
| **観測性（Observability）** | **OpenTelemetry (.NET SDK)** + **Prometheus / Grafana / OpenTelemetry Collector** | トレース（API〜キュー〜スキャナー実行〜DB〜AI呼び出し）、メトリクス（p50/p95/p99レイテンシ、キュー滞留数、スキャン時間）、構造化監査ログを一元収集。 |

## 3. 採用しない候補（または初期フェーズで見送る候補）とその理由

| 候補技術 | 判定 | 不採用・見送りの具体的理由 |
| :--- | :--- | :--- |
| **Python / FastAPI（メインバックエンドとして）** | **不採用** | 1) 非同期I/O自体は扱えるものの、50MB〜200MBの巨大SARIF/SBOM JSONのパース、数万件のFindingに対する正規化トークンハッシュ計算、インメモリ重複排除などのCPU負荷が混在すると、GIL（Global Interpreter Lock）またはフリースレッド移行期のシングルスレッド性能制約によりイベントループがブロックされ、p99レイテンシが急격に悪化する。<br>2) 商用LLM APIやローカルLLMサーバーをHTTP経由で呼び出すだけであればPythonの機械学習ライブラリ群（PyTorch等）は一切不要であり、Pythonをメインにする理由が存在しない。 |
| **C++（バックエンドまたはパーサーとして）** | **不採用** | 1) 信頼できない外部リポジトリ、不正に細工されたZIP/TARアーカイブ、巨大JSON文字列を直接パースするセキュリティ製品において、メモリ非安全なC++を使用することはバッファオーバーフローやUse-After-FreeによるRCE（リモートコード実行）脆弱性の重大なリスク要因となる。<br>2) C#の `Span<T>` やRustで同等のネイティブ級性能がメモリ安全に得られるため、C++を採用する合理性はない。 |
| **Rust（メインWebバックエンドとして）** | **メインAPIとしては不採用（将来の専用CLI/高速解析器の拡張枠としてのみ留保）** | 1) Rust（Axum / SQLx）は最高峰の性能とメモリ安全性を持つが、エンタープライズ向けの複雑なRBAC/ABAC、OIDC/SAML連携、動的検索クエリ構築、監査ログ、業務ワークフローを実装する際の開発速度とボイラープレート量がC# / ASP.NET Coreに比べて重い。<br>2) C#（.NET 8/9/10）で目標性能（検索p95 < 150ms、1万件一括処理 < 2秒）は十分に達成可能であり、初期からC#とRustの2言語を混在させることはビルドと保守の複雑さを不必要に増やすため、**初期フェーズはC#単一バックエンドに統一する**。 |
| **Go（メインWebバックエンドまたは別ワーカー言語として）** | **初期フェーズでは不採用（将来の配布用軽量CI CLIとしてのみ留保）** | 1) Goはスキャナー制御やCLI開発に極めて優れているが、メインAPIをC#で書き、WorkerだけをGoで書くと、「データモデル定義」「テナント分離ロジック」「SARIF/CycloneDX正規化ロジック」「DBマイグレーション」がC#とGoに二重化（またはgRPC通信の追加が発生）する。<br>2) C#の `BackgroundService` と `Process` 制御はGoに劣らない堅牢性を持つため、サーバーサイド（API + Worker）はC#に統一する方が圧倒的に合理的である。将来、顧客のCIランナーに配布するゼロ依存の軽量CLIが必要になった段階でのみGo（またはC# Native AOT）を使用する。 |
| **初期からのマイクロサービス分割 + Kafka / RabbitMQ / Elasticsearch** | **初期フェーズでは不採用（不要な複雑さの排除）** | 1) 初期から「Authサービス」「Scanサービス」「Findingサービス」「AIサービス」「Notificationサービス」のように分割し、KafkaとElasticsearchを必須にすると、ローカル開発やオンプレミス導入（エアギャップ環境）のハードルが跳ね上がり、分散トランザクションの不整合バグが多発する。<br>2) **モジュラーモノリス（APIプロセス）＋独立スケール可能なWorkerプロセス（同一C#ソリューション・共通ドメイン共有）＋PostgreSQL** の構成で、数千万Finding規模まで十分に対応可能である。 |

## 4. 各コンポーネントの責務・通信方式・データ交換・運用設計

### 4.1 コンポーネントの責務とプロセス境界
システム全体は単一のC#ソリューション（`PktSecurityPlatform.sln`）内で厳格にモジュール分割された以下の3つの実行単位で構成する。
1. **`PktSecurity.Api`（API Server & SSE Streamer）**
   - 責務：認証・認可（JWT / OIDC / API Key）、テナントコンテキスト検証、プロジェクト・リポジトリ管理、スキャン要求の受付（ジョブ登録）、Findingの高速検索・トリアージ状態更新、AI修正案の生成要求・承認管理、SSE（Server-Sent Events）によるリアルタイム進捗配信、監査ログ記録。
   - **絶対原則**：APIプロセス内では、外部スキャナーの実行やリポジトリの展開・解析を**一切行わない**。
2. **`PktSecurity.Worker`（Scan Orchestrator & Ingestion Worker）**
   - 責務：PostgreSQLの `scan_jobs` テーブルからリース方式（`FOR UPDATE SKIP LOCKED`）でジョブを取得し、ハートビートを更新しながら、隔離サンドボックス（Docker/Podman/gVisor）を起動してスキャナーを実行。出力されたSARIF / CycloneDXファイルをストリーミング解析し、2段階重複排除ハッシュ計算、リスクスコア算出、および `NpgsqlBinaryImporter` 等による高速一括DB保存を実行。
3. **`PktSecurity.Web`（Next.js Frontend）**
   - 責務：ダッシュボード、Finding高度検索・フィルタテーブル、コードフロー・根拠（Evidence）ビューア、SBOMサプライチェーングラフ、AI修正パッチのDiff確認・承認ワークフロー、日本語監査レポート出力。

### 4.2 コンポーネント間通信方式とデータ交換形式
- **Frontend ↔ API Server**：HTTPS上のREST JSON API（OpenAPI 3.1準拠、エラー応答は[RFC 9457 Problem Details for HTTP APIs](https://www.google.com/search?q=https%3A%2F%2Fwww.rfc-editor.org%2Frfc%2Frfc9457.html)に完全統一）および進捗通知用のServer-Sent Events（SSE: `text/event-stream`）。
- **API Server ↔ Worker**：共有PostgreSQLの `scan_jobs` テーブル（トランザクショナルキュー）および `LISTEN / NOTIFY` による即時ウェイクアップ通知とSSE進捗ブリッジ。これによりRedisなしでもミリ秒単位のジョブ着火とリアルタイム進捗配信が成立する。
- **Worker ↔ 隔離スキャナーコンテナ**：プロセス引数（シェルを経由しない配列渡し）と、読み取り専用マウントされた入力ワークスペース、およびサイズ上限付き出力専用一時ディレクトリ上の[SARIF 2.1.0](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fsarif%2Fsarif%2Fv2.1.0%2Fsarif-v2.1.0.html) / [CycloneDX 1.6](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2Fspecification%2Foverview%2F) JSONファイルによるファイル交換。

### 4.3 ビルド・配布・デバッグ・テスト方法
- **ビルドと配布**：`dotnet build --configuration Release` により、`PktSecurity.Api` と `PktSecurity.Worker` のコンテナイメージ（マルチステージビルド、DistrolessまたはAlpine/Ubuntu Chiseledベース）を生成。`docker-compose.yml` 1つでPostgreSQL、API、Worker、スキャナーイメージ群、Next.js UI、およびオプションのローカルLLM（Ollama）までをワンコマンドで起動可能にする。
- **デバッグとテスト**：xUnit + **Testcontainers for .NET**（実際のPostgreSQLコンテナを使用した統合テスト）により、モックではなく本物のPostgreSQL RLSポリシー、インデックス、バルクインサート、並行ジョブリースを自動テストで検証する。

### 4.4 将来技術を変更しやすくする拡張ポイント（Clean Boundaries）
将来、特定のコンポーネントを別技術や外部サービスへ移行する必要が生じた場合でも、ドメイン層やAPI層を書き直さずに済むよう、以下の5つのインターフェースを厳格に分離する。
1. **`IJobQueueProvider`**：初期実装は `PostgresJobQueueProvider`（`FOR UPDATE SKIP LOCKED` + `LISTEN/NOTIFY`）。将来秒間数千ジョブのスケールが必要になった際は、インターフェース実装をRedis StreamsやRabbitMQ / Kafkaへ差し替えるだけで移行可能。
2. **`ISandboxExecutionProvider`**：初期実装は `DockerSandboxProvider`（`--runtime=runsc` オプション対応）および開発・テスト環境向けの `RestrictedProcessSandboxProvider`。将来Kubernetes JobsやFirecracker MicroVMへ移行する際もこの境界内で完結する。
3. **`IScannerAdapter`**：スキャナーごとのコマンド引数構築、出力形式検証、SARIF/CycloneDXへの正規化を担当。新しいスキャナーの追加は1クラスの追加のみで完結する。
4. **`IFindingSearchEngine`**：初期実装は `PostgresFindingSearchEngine`（パーティショニング + GIN/B-Tree + Keyset Pagination）。将来1億件規模でOpenSearch / ParadeDBへオフロードする場合もAPIコントローラを変更せずに差し替え可能。
5. **`IAiRemediationProvider`**：初期実装はOpenAI互換 / Anthropic / Ollama対応のHTTPクライアントとプロンプトサニタイザ。モデルの変更やオンプレミスLLMへの切り替えを設定ファイルのみで完結させる。
