# PKT Security Platform Next

> **次世代エンタープライズ統合セキュリティプラットフォーム（Application Security Posture Management / ASPM）**

[![.NET 8](https://img.shields.io/badge/.NET-8.0-blue.svg)](https://dotnet.microsoft.com/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![Next.js 14](https://img.shields.io/badge/Next.js-14.2-black.svg)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

---

## 1. 概要 (Overview)

**PKT Security Platform Next** は、エンタープライズ規模のソフトウェアサプライチェーンおよびソースコード脆弱性を統合管理・トリアージ・AI自動修正するための次世代ASPMプラットフォームです。

主要な静的解析ツール（SAST: Semgrep）、依存関係脆弱性スキャナー（SCA: Trivy / OSV-Scanner）、シークレット検知ツール（Secret: Gitleaks）、およびSBOM生成ツール（Syft / Grype）を統合し、**2段階フィンガープリントによる重複排除**、**根拠に基づく客観的リスクスコアリング**、**OpenVEX / VEX連携**、**隔離サンドボックス内でのAI自動修正パッチ検証**、および**PostgreSQL Row-Level Security (RLS) による完全マルチテナント分離**を提供します。

---

## 2. 主要機能ハイライト (Key Features)

1. **PostgreSQL RLS によるゼロトラスト・マルチテナント分離**
   - データベースレイヤーで `tenant_id` を強制分離 (`FORCE ROW LEVEL SECURITY`)。
   - アプリケーションコードの WHERE 句漏れによるデータ漏洩を DB エンジンレベルで防御。
2. **2段階フィンガープリント重複排除エンジン**
   - `primary_fingerprint`: ツール種別・ルールID・ファイルパス・行番号による完全一致追跡。
   - `secondary_fingerprint`: 包含シンボル（クラス/関数名）＋正規化トークンハッシュにより、コード編集で行番号がズレても同一脆弱性として追跡し、トリアージ状態（FalsePositive/RiskAccepted）を自動継承。
3. **異種スキャナー間のクロス相関（Correlation Grouping）**
   - 同一CVEまたは同一CWE＋ファイル位置を検出した複数スキャナーの結果を自動で 1 つの相関グループに集約。
4. **根拠ベースの多層リスクスコアリング**
   - CVSS 基本値に依存せず、CISA KEV（悪用事実）、EPSS（悪用確率）、到達可能性（Reachable/Unreachable）、および資産重要度（インターネット公開・データ機密性）を乗算・加算した決定論的スコア算出。
5. **AI調査・修正支援 ＆ サンドボックス自動再検証**
   - OpenAI / Anthropic / ローカルLLM（Ollama）およびオフライン決定論的ルールベースによる Unified Diff パッチ生成。
   - `POST /api/v1/remediations/{id}/verify` により、隔離された一時ディレクトリでパッチを適用し、スキャナーを再実行して「脆弱性が本当に消滅したか」を機械的に判定。
6. **ミリ秒応答の Keyset ページネーション ＆ 統合ダッシュボード**
   - 10万件〜100万件規模のデータに対しても O(log N) のインデックスシークにより、検索 p95 **24.83 ms**、ダッシュボード集計 p50 **0.54 ms** を達成。
7. **SBOM (CycloneDX 1.6) ＆ OpenVEX 除外判定**
   - 脆弱性影響外（`not_affected` / `vulnerable_code_not_in_execute_path`）の自動除外とOpenVEX準拠ステートメント出力。

---

## 3. システムアーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────┐
│               Frontend: PktSecurity.Web                     │
│               (Next.js 14, React, Tailwind CSS, TypeScript) │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / REST / SSE Streaming
┌──────────────────────────────▼──────────────────────────────┐
│                  API: PktSecurity.Api                       │
│    (ASP.NET Core 8 Minimal API, JWT & API Key, RLS Context) │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
┌──────────────▼──────────────┐┌──────────────▼───────────────┐
│ Database: PostgreSQL 16     ││ Worker: PktSecurity.Worker   │
│ - Row-Level Security (RLS)  ││ - ScanWorker (Queue Consumer)│
│ - Keyset Composite Indexes  ││ - Scanner Adapters (CLI)     │
│ - Skip-Locked Job Queue     ││ - Process Sandbox Provider   │
└─────────────────────────────┘└──────────────────────────────┘
```

---

## 4. クイックスタート (Quickstart)

### 前提条件
- .NET 8.0 SDK (`dotnet --version` >= 8.0.400)
- Node.js 20.x (`node --version` >= 20.0.0, `npm` >= 10.0.0)
- PostgreSQL 16.x (ポート 5432)

### 1. データベースの起動と接続確認
```bash
# PostgreSQLが起動していることを確認
psql -U postgres -d pktsecurity -c "SELECT version();"
```

### 2. バックエンド API および Worker のビルド・起動
```bash
# 依存関係の復元とビルド
dotnet restore
dotnet build --configuration Release

# データベースマイグレーション＆シード初期化（初回起動時に自動適用）
dotnet run --project src/PktSecurity.Api
```

別のターミナルでスキャン実行ワーカーを起動：
```bash
dotnet run --project src/PktSecurity.Worker
```

### 3. フロントエンド Web アプリケーションの起動
```bash
cd src/PktSecurity.Web
npm install
npm run dev
```
ブラウザで `http://localhost:3000` にアクセスすると統合セキュリティダッシュボードが表示されます。

---

## 5. テスト・ベンチマークの実行

### 全単体テスト・統合テスト・セキュリティテストの実行
```bash
dotnet test --configuration Release --verbosity normal
```

### 10万件規模性能ベンチマークの実行
```bash
dotnet run --project tests/PktSecurity.Benchmarks --configuration Release
```
ベンチマーク測定結果は `docs/benchmark-report.md` に自動出力されます。

### フロントエンド型チェック・本番ビルド
```bash
cd src/PktSecurity.Web
npm run build
```

---

## 6. ドキュメント一覧

- [アーキテクチャ設計書 (`docs/architecture.md`)](docs/architecture.md)
- [API 仕様書 (`docs/api-spec.md`)](docs/api-spec.md)
- [セキュリティ16要件検証レポート (`docs/security-verification.md`)](docs/security-verification.md)
- [M5 性能ベンチマーク実測レポート (`docs/benchmark-report.md`)](docs/benchmark-report.md)
- [サードパーティライセンス表示 (`THIRD_PARTY_NOTICES.md`)](THIRD_PARTY_NOTICES.md)
