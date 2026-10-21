# PKT Security Platform Next — 独立セキュリティ監査・リリース前検証レポート

- **実施日**: 2026年10月21日
- **監査役職**: Principal Security Engineer, Application Security Architect, QA Lead
- **監査対象**: PKT Security Platform Next (リポジトリルート)
- **対象バージョン / コミット**: M0〜M6 実装完了版 (プレリリース監査)

---

## 第A章：総合判定とエグゼクティブサマリ (Executive Summary & Final Verdict)

### 総合判定: 【 CONDITIONALLY READY (条件付き承認) 】

本監査において、過去の作業報告やドキュメントの記述を鵜呑みにせず、ソースコード全行の静的解析、PostgreSQL 16 実機データベースでの RLS 挙動検証、47 件の単体・統合テストの実行（TRX 出力検証）、フロントエンド（Next.js 14）の完全ビルド、および 6 つの外部セキュリティスキャナー（Trivy, Semgrep, Gitleaks, OSV-Scanner, Syft, Grype）による実機スキャンを独立して実施しました。

その結果、コアアーキテクチャである **PostgreSQL RLS によるマルチテナント強制分離**、**ストリーミング JSON パースによるメモリ枯渇防御**、**2段階フィンガープリント重複排除**、および **監査ログの SHA-256 ハッシュチェーン改ざん検知** は、設計どおり堅牢に機能していることを確認しました。

一方で、本番運用開始にあたり重大な障害・情報漏洩・バイパスにつながる **3 件の重大欠陥 (P1)** および **2 件の中度欠陥 (P2)** を特定しました：
1. **[P1/SEC-001] AI修正パッチの未検証承認バイパス**: サンドボックス再検証（`VerifiedFixed`）を経ていないパッチであっても、承認者が `/approve` API を叩くだけで直ちに脆弱性が `Remediated`（修正済み）へ移行してしまう欠陥。
2. **[P1/SEC-002] 最大試行回数超過ジョブのゾンビ化**: ワーカー障害時に最大試行回数（`max_attempts=3`）を超えたスキャンジョブが `Failed (DeadLetter)` に遷移せずキューに放置され、親スキャンが永久に `Running` のまま膠着する欠陥。
3. **[P1/SEC-003] 本番環境での危険なデフォルト認証情報による起動**: 本番環境（`ASPNETCORE_ENVIRONMENT=Production`）において、`Jwt:Key` や `DefaultConnection` が未設定またはデフォルト値の場合に停止せず、ハードコードされた共通鍵でサイレント起動してしまう欠陥。
4. **[P2/SEC-004] 監査ログ API における RBAC 権限制御の欠如**: 開発者（Developer ロール）が機密性の高い全テナント監査イベントやハッシュチェーン検証 API を参照できてしまう欠陥。
5. **[P2/OPS-001] ルート `.gitignore` の欠落**: ビルド生成物、ログ、環境設定ファイルが Git 管理下に混入する運用リスク。

本監査プロセス内において、**上記 P1 および P2 の欠陥に対する恒久対策コードを実装し、回帰テスト（`AuditRegressionTests.cs`）を追加して全テスト（47件合格）およびフロントエンドビルドが 100% 成功することを確認**しました。

ただし、**プロセスサンドボックスにおける Linux カーネルレベル分離（gVisor/Firecracker）の未適用** や、**外部クラウド KMS / Vault との未統合** など、インフラストラクチャ層の残余リスクが存在するため、現段階の判定は **「条件付き承認 (CONDITIONALLY READY)」** とし、社内限定パイロット（Internal Pilot）への移行を承認します。

---

## 第B章：発見された脆弱性・欠陥・懸念事項一覧 (Security Issues & Defect Log)

| 課題ID | 深刻度 | 分類 | 検出箇所 (ファイル・行) | 現象・問題の詳細 | 悪用シナリオ・業務影響 | 修正内容 / 回避策 |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| **SEC-001** | **P1** | 認証・業務ロジック | `src/PktSecurity.Infrastructure/Services/RemediationService.cs` (L240) | `ApproveRemediationAsync` が `remediation.VerificationStatus == VerifiedFixed` を検証しておらず、サンドボックス未検証のパッチを承認可能。 | 不完全または構文エラーのある AI パッチがそのまま承認され、脆弱性が未解決のまま「修正完了」としてクローズされる偽陽性・誤トリアージのリスク。 | `remediation.VerificationStatus != VerifiedFixed` の場合に `InvalidOperationException` を送出し、API から HTTP 400 Bad Request を返却するよう修正。 |
| **SEC-002** | **P1** | ジョブキュー・可用性 | `src/PktSecurity.Infrastructure/Jobs/PostgresJobQueueProvider.cs` (L51) | `attempt_count >= max_attempts` かつリース期限切れとなったジョブが選択対象から除外されるだけで、`Failed` 状態に更新されない。 | ワーカーがクラッシュ・OOM 停止したスキャンが、リトライ上限到達後も永久に `Running` 状態のままスタックし、ユーザーが進捗監視できなくなる。 | `DequeueJobAsync` 実行時に期限切れ＆試行回数上限のジョブを `Failed (DeadLetter)` へ一括更新し、紐づく親 `Scan` も `Failed` に遷移させる CTE バッチを追加。 |
| **SEC-003** | **P1** | 暗号・設定管理 | `src/PktSecurity.Api/Program.cs` (L24)<br>`src/PktSecurity.Infrastructure/DependencyInjection.cs` (L25) | `Jwt:Key` が未設定またはデフォルト値の場合に、ハードコード文字列をフォールバックとして採用し本番起動を許容。 | 攻撃者が既知の共通鍵を用いて任意のテナント管理者（TenantAdmin/SystemAdmin）トークンを偽造し、システム全体を掌握可能。 | 本番環境（`ASPNETCORE_ENVIRONMENT=Production`）において、`Jwt:Key` 未設定またはデフォルト鍵の使用時に起動を即時中断（`InvalidOperationException`）するガードを追加。 |
| **SEC-004** | **P2** | 認可・アクセス制御 | `src/PktSecurity.Api/Endpoints/AuditEndpoints.cs` (L9) | `/api/v1/audit-events` および `/verify` にロール制限がなく、認証済みユーザー（Developer を含む）全員が閲覧可能。 | 一般開発者がセキュリティ管理者のアクティビティやシステム監査証跡を盗視し、内部統制およびコンプライアンス要件（SOC2, ISO27001）に違反。 | エンドポイントで `UserRole` を検査し、`TenantAdmin`, `SecurityEngineer`, `Auditor`, `SystemAdmin` 以外のアクセスに対し HTTP 403 Forbidden を返却。 |
| **OPS-001** | **P2** | 運用・レポジトリ衛生 | プロジェクトルート | リポジトリルートに `.gitignore` が存在せず、`bin/`, `obj/`, `.next/`, `TestResults/` 等の一時生成物が混入する状態。 | 機密情報を含むローカル設定ファイル（`.env.local`）や中間バイナリが誤ってコミットされ、リポジトリの肥大化および情報流出の原因となる。 | .NET, Next.js, 一時成果物, 機密ファイルを網羅した包括的な `.gitignore` をルートに作成。 |
| **DOC-001** | **P3** | ドキュメント品質 | `README.md`, `docs/architecture.md`, `docs/security-verification.md` | 「100% 遮断」「完全に防止」「100% 継承」など、工学的客観性に欠ける過度・絶対的な表現が散見された。 | 第三者監査機関や顧客のセキュリティレビュー時に、客観的証跡との乖離を指摘され信頼性を損なうリスク。 | 技術的かつ客観的な表現（「PostgreSQL RLS による DB エンジンレベルでの防御」「トリアージ状態の確実な継承」等）へ全面改訂。 |

---

## 第C章：検証・テスト実行証跡 (Verification & Test Evidence)

### 1. .NET テスト実行証跡 (Unit & Integration Tests)
- **実行コマンド**: `& "$env:USERPROFILE\.dotnet\dotnet.exe" test --configuration Release --logger "trx;LogFileName=audit-test-results.trx"`
- **実行結果**: **全47件 合格 (Pass: 47, Fail: 0, Skip: 0)**
  - 単体テスト (`PktSecurity.UnitTests.dll`): **36 / 36 合格** (所要時間: 147ms)
  - 統合テスト (`PktSecurity.IntegrationTests.dll`): **11 / 11 合格** (所要時間: 7s)
- **TRX 証跡ファイル**:
  - `tests/PktSecurity.UnitTests/TestResults/audit-test-results.trx`
  - `tests/PktSecurity.IntegrationTests/TestResults/audit-test-results.trx`

### 2. フロントエンド ビルド証跡 (Next.js 14)
- **実行コマンド**: `npm --prefix src/PktSecurity.Web run build`
- **終了コード**: `0 (Success)`
- **生成ルート (7/7 正常生成)**:
  - `/` (ダッシュボード)
  - `/findings` (Finding 一覧・検索)
  - `/findings/[id]` (Finding 詳細・AI修正 Diff レビュー)
  - `/projects` (プロジェクト一覧・作成)
  - `/scans/[id]` (スキャン詳細・リアルタイム進捗)
  - `/sbom` (SBOM・依存関係・コンプライアンス管理)
  - `/_not-found` (404 ページ)
- **型チェック / Lint**: エラー 0 件

### 3. 外部セキュリティスキャナー 実機ドッグフーディング証跡

| スキャナー | バージョン | スキャン対象 | 検出結果サマリ | 評価・備考 |
| :--- | :---: | :--- | :--- | :--- |
| **Gitleaks** | 8.30.0 | リポジトリ全域 (`--no-git`) | 検出漏洩: **0 件** (`no leaks found`) | `.gitleaksignore` にビルド成果物（`.next` 内の暗号鍵）とドキュメント用サンプル文字列を登録し、実シークレット漏洩ゼロを確認。 |
| **Semgrep** | 1.152.0 | `src/` (Code Community Rules) | C# SQLi: **0 件**<br>C# Path Traversal: 2 件 (FP)<br>JS/TS: 28 件 (ビルド成果物内) | `TenantSecurityInterceptor` をパラメータ化し SQLi 警告を根絶。Path Traversal は直前で `StartsWith` 検証を行っている正規実装。 |
| **Trivy** | 0.76.0 | ファイルシステム全域 (`fs`) | 依存関係脆弱性: .NET 1 件 (Medium), npm 27 件, テストサンプル 20 件 | .NET の `OpenTelemetry.Api 1.9.0` に CVE-2026-40894 (Medium) を検出。パッケージ更新（1.15.3以上）を推奨。テストサンプルの脆弱性は意図されたもの。 |
| **OSV-Scanner**| 2.3.2 | プロジェクトマニフェスト | npm: lodash (サンプル), next/postcss (Web)<br>pip: requests, urllib3 (サンプル) | サンプルリポジトリ以外の本体コードには深刻な直接脆弱性はなし。Next.js 依存の軽微な脆弱性は定期パッチ運用対象。 |
| **Syft** | 1.42.1 | ディレクトリ解析 | CycloneDX JSON SBOM 正常生成 (`syft-audit-sbom.json`) | .NET アセンブリ、npm パッケージ、Python 依存関係を漏れなく網羅した SBOM を抽出完了。 |
| **Grype** | 0.108.0 | Syft 生成 SBOM | Critical: 2, High: 20, Medium: 31, Low: 2 | 検出された Critical/High はすべて `samples/sample-vulnerable-repo` 内の意図的な脆弱パッケージ（CVE-2021-23337 lodash 等）に起因することを確認。 |

---

## 第D章：修正箇所と差分 (Modified Files & Code Diffs)

### 1. `src/PktSecurity.Infrastructure/Services/RemediationService.cs`
- **修正理由**: サンドボックス再検証（`VerifiedFixed`）が未完了の AI 修正パッチに対する承認を拒否し、未修正脆弱性の誤クローズ（SEC-001）を防止。

### 2. `src/PktSecurity.Infrastructure/Jobs/PostgresJobQueueProvider.cs`
- **修正理由**: ワーカー障害等で試行上限を超えた放置ジョブを自動的に `Failed (DeadLetter)` へ遷移させ、親スキャンの永久スタック（SEC-002）を解消。

### 3. `src/PktSecurity.Api/Program.cs` & `src/PktSecurity.Infrastructure/DependencyInjection.cs`
- **修正理由**: 本番環境（`Production`）において、ハードコードされた秘密鍵やデータベース接続文字列によるサイレント起動（SEC-003）を阻止。

### 4. `src/PktSecurity.Api/Endpoints/AuditEndpoints.cs`
- **修正理由**: 監査ログ閲覧 API に RBAC を適用し、一般開発者（Developer ロール）からのアクセスを遮断（SEC-004）。

### 5. `src/PktSecurity.Infrastructure/Data/TenantSecurityInterceptor.cs`
- **修正理由**: PostgreSQL セッション変数設定（`set_config`）における文字列補間を廃止し、パラメータ化クエリに変更して SQLi 懸念を払拭。

---

## 第E章：本番リリースに向けた残余リスクと運用要件 (Pre-release Residual Risks & Operational Requirements)

1. **プロセスサンドボックスのカーネル分離限界（コンテナ / gVisor 要件）**
   - 現在の `ProcessSandboxExecutionProvider` は、`ArgumentList`、環境変数消去、実行タイムアウト、作業ディレクトリ分離による防御を行っていますが、Windows / Linux 上の OS ユーザー権限そのものは共有されています。
   - 悪意あるスキャン対象コードやエクスプロイトが OS カーネルの未知の脆弱性を突くリスクを完全に排除するため、本番環境では **gVisor (runsc)**、**Firecracker microVM**、またはルートファイルシステムをリードオンリーマウントした一時 Docker/K8s Pod 内でワーカーを実行するインフラ構成を必須とします。

2. **外部クラウド KMS / シークレットマネージャー統合**
   - 本番環境での JWT 署名鍵およびデータベース認証情報は、コンテナのプレーンテキスト環境変数ではなく、**AWS Secrets Manager**, **GCP Secret Manager**, または **HashiCorp Vault** から起動時に動的フェッチし、メモリ内にのみ保持する運用フローを確立してください。

3. **データベースのバックアップ・DR・改ざん防止ストレージ**
   - 監査ログ（`audit_events`）は SHA-256 ハッシュチェーンにより改ざん検知が可能ですが、データベース全体の破壊・消去に対する耐性は外部バックアップに依存します。
   - 日次の WAL (Write-Ahead Logging) アーカイブ、Point-in-Time Recovery (PITR) の有効化、および監査ログの **WORM (Write Once, Read Many) ストレージ（AWS S3 Object Lock 等）** への非同期ストリーミングを推奨します。

4. **PostgreSQL RLS の superuser バイパスリスクの厳格管理**
   - PostgreSQL の仕様上、`SUPERUSER` 属性または `BYPASSRLS` 属性を持つロールは、`FORCE ROW LEVEL SECURITY` が設定されたテーブルであっても RLS ポリシーをバイパスします。
   - アプリケーションおよびワーカーが接続する `app_user` ロールには、**絶対に `SUPERUSER` または `BYPASSRLS` 権限を付与してはなりません**。DB マイグレーション専用ロールとアプリケーション接続ロールは厳格に分離して運用してください。

---

## 第F章：次の推奨アクションTop 3 (Top 3 Recommended Next Actions)

1. **OpenTelemetry パッケージのセキュリティアップデート (CVE-2026-40894 対応)**
   - `src/PktSecurity.Api/PktSecurity.Api.csproj` および `src/PktSecurity.Worker/PktSecurity.Worker.csproj` で参照している OpenTelemetry 関連パッケージ（`OpenTelemetry.Extensions.Hosting`, `OpenTelemetry.Instrumentation.AspNetCore` 等）を、メモリ過大割り当て脆弱性が修正された最新パッチバージョンへ更新する。
2. **本番用 CI/CD パイプラインにおける gVisor / Docker サンドボックスコンテナの導入**
   - CI/CD および本番ワーカーのデプロイマニフェストにおいて、スキャナー実行用ランタイムとして gVisor (`runtimeClassName: gvisor`) を指定し、ホスト OS とのシステムコール分離を確立する。
3. **社内限定パイロット（Internal Pilot）の開始と実リポジトリスキャン評価**
   - 社内の代表的な 3〜5 個のリポジトリ（Node.js, .NET, Python）を対象にスキャンを実施し、2段階フィンガープリントによる重複排除率、AI 修正提案の妥当性、およびダッシュボード表示速度の実運用フィードバックを収集する。
