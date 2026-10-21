# PKT Security Platform Next - アーキテクチャ設計書

本ドキュメントは、**PKT Security Platform Next** のシステム構造、コンポーネント構成、セキュリティ分離設計、非同期ジョブ実行、データ重複排除、およびリスク算出アルゴリズムの詳細を記述した設計書です。

---

## 1. クリーンアーキテクチャ設計とレイヤー責務

本プラットフォームは、ビジネスロジックのフレームワーク非依存性とテスタビリティを担保するため、厳格なクリーンアーキテクチャ（Clean Architecture）を採用しています。

```
                    ┌────────────────────────────┐
                    │      PktSecurity.Web       │ (Next.js 14 App Router, TypeScript)
                    └─────────────┬──────────────┘
                                  │ HTTP / JSON / SSE
                    ┌─────────────▼──────────────┐
                    │      PktSecurity.Api       │ (Presentation / ASP.NET Core Minimal API)
                    └─────────────┬──────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
┌────────▼──────────────┐ ┌───────▼──────────────┐ ┌───────▼──────────────┐
│  PktSecurity.Worker   │ │PktSecurity.Application│ │PktSecurity.Infrastructure│
│ (Background Consumer) │ │  (Use Cases & DTOs)  │ │(Postgres, Adapters, AI)│
└────────┬──────────────┘ └───────┬──────────────┘ └───────┬──────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │     PktSecurity.Domain     │ (Core Entities & Logic)
                    └────────────────────────────┘
```

### レイヤー構成と依存関係の規則
1. **`PktSecurity.Domain`**:
   - 外部依存ゼロの純粋な C# ライブラリ。
   - エンティティ（`Project`, `Scan`, `ScanJob`, `Finding`, `Remediation` 等）、列挙型（`FindingSeverity`, `FindingStatus` 等）、ドメインサービス（`FingerprintCalculator`, `RiskScoreCalculator` 等）を保持。
2. **`PktSecurity.Application`**:
   - システムのユースケース、DTO、および抽象インターフェース（`IScannerAdapter`, `IJobQueueProvider`, `IAiRemediationProvider`, `IFindingSearchService`, `ITenantContext`）を定義。
   - データベース技術や外部CLIに依存しない。
3. **`PktSecurity.Infrastructure`**:
   - `PktSecurity.Application` のインターフェースに対する具象実装。
   - PostgreSQL（EF Core 8 ＋ Dapper ＋ Npgsql）、RLS設定、スキャナーアダプター（Semgrep, Trivy, Gitleaks, OSV-Scanner, Syft）、プロセスサンドボックス（`ProcessSandboxExecutionProvider`）、および AI パッチ生成器。
4. **`PktSecurity.Worker`**:
   - スキャンジョブキューを監視し、スキャナーの実行、SARIF/CycloneDXパース、重複排除、リスク計算、およびDB保存を非同期で実行するバックグラウンドプロセス。
5. **`PktSecurity.Api`**:
   - REST API エンドポイント（Minimal APIs）、JWT/APIキー認証、テナントコンテキスト解決、SSEストリーミング、およびOpenTelemetry/ヘルスチェックを提供。
6. **`PktSecurity.Web`**:
   - Next.js 14（App Router）および Tailwind CSS によるエンタープライズ UI。

---

## 2. データベースアーキテクチャとマルチテナント分離 (Row-Level Security)

### 2.1 テナント分離の設計原則
本システムは共有データベース・共有スキーマアプローチを採用しつつ、データ分離をアプリケーション層の `WHERE` 句に依存させず、PostgreSQL の **Row-Level Security (RLS)** によって物理的に強制します。

```sql
-- RLS 有効化と強制適用
ALTER TABLE "findings" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "findings" FORCE ROW LEVEL SECURITY;

-- テナント分離ポリシーの定義
CREATE POLICY "tenant_isolation_findings" ON "findings"
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
```

### 2.2 EF Core インターセプターによるテナントコンテキスト注入
`TenantSecurityInterceptor` がデータベース接続オープン直後に `SELECT set_config('app.current_tenant_id', @tenantId, false);` を発行し、セッション内で実行されるすべての SQL にテナント ID を自動バインドします。

---

## 3. 非同期スキャンジョブキューと耐障害性 (Lease & Dead-Letter)

### 3.1 PostgreSQL SKIP LOCKED による高信頼キュー
外部メッセージブローカー（RabbitMQ / Kafka等）を追加することなく、PostgreSQL の `FOR UPDATE SKIP LOCKED` 構文を利用して高信頼なジョブキューを実現しています。

```sql
SELECT * FROM scan_jobs
WHERE status = 0 OR (status = 1 AND leased_until < NOW())
ORDER BY priority DESC, created_at ASC
FOR UPDATE SKIP LOCKED
LIMIT 1;
```

### 3.2 リース延長とクラッシュリカバリー
- ワーカーはジョブ処理中、定期的に `ExtendLeaseAsync` を呼び出し、`leased_until` を更新します。
- ワーカープロセスが突然クラッシュ・OOM 停止した場合、`leased_until` が期限切れとなり、別の正常なワーカーが即座にジョブを再取得します。
- 最大再試行回数（3回）を超えたジョブは自動的に `Failed (DeadLetter)` 状態へ遷移し、キューの長期滞留（Poison Message）を抑制・防止します。

---

## 4. 2段階フィンガープリント重複排除エンジン

コードの編集やリファクタリング、再スキャン時に脆弱性が誤って重複登録されるのを防ぐため、2 段階のフィンガープリントを実装しています。

```
[スキャン結果 (SARIF)]
         │
         ├─── 完全一致? ───> [primary_fingerprint]
         │                     SHA-256(scanner | rule_id | file_path | start_line)
         │                     ※同一行・同一ツールの同一脆弱性を高速完全一致
         │
         └─── 行番号ズレ? ──> [secondary_fingerprint]
                               SHA-256(tenant | project | category | cwe | file_path | enclosing_symbol | normalized_tokens)
                               ※関数名/クラス名と空白・コメント除去コードトークン列による追跡
```

### トリアージ状態の確実な継承
再スキャン時に `primary_fingerprint` または `secondary_fingerprint` が一致した場合：
- 既存の Finding レコードの `start_line`, `end_line`, `last_seen_scan_id`, `occurrence_count` のみを更新。
- 過去にエンジニアやセキュリティ担当者が設定したステータス（`FalsePositive`, `RiskAccepted`）、担当者、コメント履歴を確実に保持。

---

## 5. 多層リスクスコアリングアルゴリズム

固定の CVSS 基本値のみで優先順位を判断する誤りを防ぐため、客観的脅威情報とビジネスコンテキストを融合した決定論的スコアリングを採用しています。

### 計算式 (Formula Version 1.0)
$$\text{BaseScore} = \text{MapSeverity}(\text{Severity})$$
$$\text{ThreatScore} = (\text{IsKev} \times 1.5) + (\text{EpssScore} \times 2.0)$$
$$\text{ReachabilityMultiplier} = \begin{cases} 1.2 & (\text{Reachable}) \\ 0.6 & (\text{Unreachable}) \\ 1.0 & (\text{Unknown}) \end{cases}$$
$$\text{AssetMultiplier} = (1.0 + \text{CriticalityBonus} + \text{InternetFacingBonus})$$
$$\text{FinalScore} = \min(100.0, \text{BaseScore} \times \text{AssetMultiplier} \times \text{ReachabilityMultiplier} + \text{ThreatScore})$$

- **非推測原則**: EPSS や到達可能性が `null`（情報なし）の場合、デフォルト値（1.0 等）を補完せず、`missing_inputs` として記録した上で確定的スコアを算出。

---

## 6. AI調査・修正支援パイプラインとサンドボックス自動検証

```
┌──────────────────┐     ┌────────────────────────┐     ┌───────────────────────┐
│ Finding & Source │ ──> │  IAiRemediationProvider│ ──> │ Unified Diff Patch    │
│ Context Extract  │     │  (LLM or Deterministic)│     │ & Fact/Hypothesis Sep │
└──────────────────┘     └────────────────────────┘     └───────────┬───────────┘
                                                                    │
                                                         POST /remediations/{id}/verify
                                                                    │
┌────────────────────────┐     ┌────────────────────────┐           │
│ Verification Result    │ <── │ Scanner Re-execution   │ <─────────┘
│ (VerifiedFixed / Fail) │     │ (Temporary Workspace)  │
└────────────────────────┘     └────────────────────────┘
```

1. **事実と推論の厳格分離**:
   - `verified_facts`（ツールが検出した行・ファイル・CVE名などの客観的事実）と `ai_hypothesis_analysis`（LLMによる脆弱性原因の推論）を JSON スキーマ上で厳格に分離。
2. **サンドボックス再検証 (`POST /api/v1/remediations/{id}/verify`)**:
   - 対象リポジトリの一時クローンを作成し、Unified Diff パッチを `git apply` / パッチ適用。
   - 同一スキャナーを再実行し、元の Finding が解消されていること、および新規脆弱性が誘発されていないことを機械的に検証。
3. **人間による承認ゲート**:
   - 検証済みのパッチのみ、セキュリティレビュー担当者が承認（`Approve`）することで、本番ブランチへのプルリクエスト作成やコミットが可能。
