# PKT Security Platform Next - セキュリティ検証レポート

本ドキュメントは、`MASTER_DEVELOPMENT_PROMPT.md` および `docs/reference/architecture_recommendations.md`（第2章セキュリティ16要件）に基づき、**PKT Security Platform Next** において実装・検証されたセキュリティ機構と攻撃耐性テスト結果を詳述した検証レポートです。

---

## 1. セキュリティ16要件 対応・実装マトリクス

| 要件番号 | セキュリティ要件項目 | 実装方針・防御機構 | 実装箇所 | 検証結果 |
| :---: | :--- | :--- | :--- | :---: |
| **REQ-01** | **マルチテナント完全分離** | PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`) により DB エンジン側で物理遮断。 | `DatabaseInitializer.cs`, `TenantSecurityInterceptor.cs` | **合格 [PASS]** |
| **REQ-02** | **Zip Slip (パストラバーサル) 防御** | アーカイブ展開時に正規化パスを検証し、展開先ルート外への相対パス（`../`）を拒否。 | `SecurityValidationService.cs` | **合格 [PASS]** |
| **REQ-03** | **Zip Bomb (高圧縮爆弾) 防御** | 展開前サイズ比率チェック（最大100倍制限）および展開後最大サイズ制限（500MB）。 | `SecurityValidationService.cs` | **合格 [PASS]** |
| **REQ-04** | **コマンドインジェクション防御** | シェル経由（`/bin/sh -c`, `cmd.exe /c`）の呼出しを完全排除。引数は配列として直接プロセスへ渡す。 | `ProcessSandboxExecutionProvider.cs` | **合格 [PASS]** |
| **REQ-05** | **SSRF (プライベートIP遮断)** | リポジトリURL取得時、ローカルホスト（`127.0.0.1`）、プライベートIP（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）、リンクローカル（`169.254.169.254`）へのアクセスを即時拒否。 | `SecurityValidationService.cs` | **合格 [PASS]** |
| **REQ-06** | **AIプロンプトインジェクション無力化** | ユーザー入力コードを XML 風デリミタで厳格に囲み、事実（`verified_facts`）と推論（`ai_hypothesis_analysis`）を構造分離。 | `AiRemediationService.cs` | **合格 [PASS]** |
| **REQ-07** | **監査ログ改ざん検知 (ハッシュチェーン)** | 前行の SHA-256 ハッシュを含めてブロックチェーン状に連鎖計算し、中間行の改ざん・削除を即時検知。 | `AuditLogService.cs` | **合格 [PASS]** |
| **REQ-08** | **ジョブ二重取り込み防止** | `Idempotency-Key` ヘッダーによる重複排除と、PostgreSQL `FOR UPDATE SKIP LOCKED` による単一ワーカー排他的取得。 | `PostgresJobQueueProvider.cs` | **合格 [PASS]** |
| **REQ-09** | **エビデンス内シークレット自動マスキング** | Gitleaks 等のシークレット検知結果およびログ出力において、トークン値・APIキー文字列を正規表現で自動 Redact（`[REDACTED]`）。 | `ScanExecutionService.cs` | **合格 [PASS]** |
| **REQ-10** | **隔離サンドボックス再検証** | 一時ディレクトリ（Temp Workspace）でパッチ適用＆再スキャンを実行し、ホスト環境から分離。 | `ProcessSandboxExecutionProvider.cs` | **合格 [PASS]** |
| **REQ-11** | **SQLインジェクション完全防止 (CWE-89)** | 生SQL文字列連結を排除し、EF Core パラメータ化クエリおよび Npgsql 型付けパラメータのみ使用。 | `AppDbContext.cs`, `PostgresFindingSearchService.cs` | **合格 [PASS]** |
| **REQ-12** | **クロスサイトスクリプティング防御 (CWE-79)** | React / Next.js の組み込み JSX 自動エスケープ機構および Content Security Policy (CSP) の適用。 | `PktSecurity.Web` | **合格 [PASS]** |
| **REQ-13** | **ハードコードシークレット排除 (CWE-798)** | DBパスワード、JWT署名キー、APIキーをコード内に記述せず、環境変数・シークレットストア経由で注入。 | `Program.cs`, `appsettings.json` | **合格 [PASS]** |
| **REQ-14** | **最小権限実行原則** | コンテナ実行時の非 root ユーザー実行、Worker の読み取り専用ファイルシステムマウント。 | `Dockerfile`, `docker-compose.yml` | **合格 [PASS]** |
| **REQ-15** | **セキュアな認証・認可** | HMAC-SHA256 (256ビット鍵) による JWT 署名検証、有効期限（24時間）、BCrypt パスワードハッシュ化（WorkFactor=11）。 | `JwtTokenService.cs`, `ApiKeyAuthenticationHandler.cs` | **合格 [PASS]** |
| **REQ-16** | **レートリミット・リソースクォータ** | 検索 API への Limit 上限（最大200件）、アップロードファイルサイズ制限、およびタイムアウト設定。 | `PostgresFindingSearchService.cs` | **合格 [PASS]** |

---

## 2. 攻撃耐性・セキュリティ統合テスト結果

`tests/PktSecurity.IntegrationTests` において、以下の攻撃シナリオに対する実テストを実施し、全件合格を確認しました。

### 1. マルチテナント分離テスト (`TenantIsolationTests`)
- **シナリオ**: テナント A（TenantAlpha）で発行された認証トークンを用い、テナント B（TenantBeta）に属するプロジェクト、スキャン結果、および Finding 詳細を取得・更新するリクエストを送信。
- **結果**: **404 Not Found または 403 Forbidden** となり、他テナントのデータアクセス要求を確実に遮断。

### 2. Zip Slip パストラバーサル攻撃テスト (`SecurityMitigationTests`)
- **シナリオ**: ヘッダーに `../../../../etc/passwd` や `..\\..\\Windows\\System32\\calc.exe` を含む悪意の Zip アーカイブをアップロード。
- **結果**: `SecurityException ("Path traversal detected")` が送出され、展開処理を未然に阻止。

### 3. Zip Bomb 展開阻止テスト (`SecurityMitigationTests`)
- **シナリオ**: 1MB の圧縮データが展開後に 10GB 以上に膨張する高圧縮アーカイブを送信。
- **結果**: 圧縮比率制限（100倍）または最大展開サイズ（500MB）違反により拒否。

### 4. コマンドインジェクション攻撃テスト (`SecurityMitigationTests`)
- **シナリオ**: スキャナー引数に `; rm -rf /`, `& calc.exe`, `| whoami` 等のメタ文字を注入。
- **結果**: シェルを介さず引数配列として実行されるため、メタ文字は解釈されず無害なリテラル文字列として処理。

### 5. SSRF (Server-Side Request Forgery) 攻撃テスト (`SecurityMitigationTests`)
- **シナリオ**: リポジトリ取得 URL に `http://169.254.169.254/latest/meta-data/`（AWSメタデータ）および `http://127.0.0.1:5432`（内部DB）を指定。
- **結果**: IP アドレス名前解決後のプライベート IP フィルタにより、リクエスト発行前に `SecurityException` で拒否。

### 6. 監査ログ改ざん検知テスト (`AuditLogIntegrityTests`)
- **シナリオ**: データベース内の過去の監査ログレコードの本文を直接書き換え、整合性検証 API を実行。
- **結果**: SHA-256 ハッシュチェーンの不一致が検出され、改ざんされたブロックの ID と改ざん発生が正確に特定・報告。
