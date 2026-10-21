# PKT Security Platform Next - REST API 仕様書

本ドキュメントは、**PKT Security Platform Next** が提供するすべての REST API および Server-Sent Events (SSE) エンドポイントの仕様書です。

- **Base URL**: `http://localhost:5000` (開発環境) / `https://api.pktsecurity.local` (本番環境)
- **API バージョン**: `v1` (`/api/v1`)
- **認証方式**:
  - JWT Bearer トークン: `Authorization: Bearer <jwt_token>`
  - API キー: `X-API-Key: pkt_live_<key>` または `Authorization: Bearer pkt_live_<key>`

---

## 1. 認証・APIキー管理 (Authentication)

### `POST /api/v1/auth/login`
ユーザー認証を行い、テナント情報を含んだ JWT Bearer トークンを発行します。

- **Request Body**:
  ```json
  {
    "email": "admin@tenant-alpha.local",
    "password": "AdminPassword123!"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 86400,
    "tenantId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "email": "admin@tenant-alpha.local",
    "role": "TenantAdmin"
  }
  ```

### `POST /api/v1/auth/api-keys`
CI/CD パイプライン連携用の API キーを発行します。

- **Headers**: `Authorization: Bearer <jwt_token>`
- **Request Body**:
  ```json
  {
    "name": "GitHub Actions CI",
    "expiresAt": "2027-12-31T23:59:59Z"
  }
  ```
- **Response (201 Created)**:
  ```json
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "GitHub Actions CI",
    "apiKey": "pkt_live_abc123def456...",
    "createdAt": "2026-10-21T12:00:00Z"
  }
  ```

---

## 2. プロジェクト管理 (Projects)

### `GET /api/v1/projects`
テナントに属するプロジェクトの一覧を取得します。

- **Response (200 OK)**:
  ```json
  [
    {
      "id": "2d8517f7-ec68-4714-96a2-931f6d7c5cf8",
      "name": "Payment Gateway Service",
      "description": "Core payment processing service",
      "businessCriticality": "Critical",
      "isInternetFacing": true,
      "dataSensitivity": "Restricted",
      "findingsCount": 42,
      "createdAt": "2026-10-21T10:00:00Z"
    }
  ]
  ```

### `POST /api/v1/projects`
新規プロジェクトを作成し、ビジネスコンテキスト（重要度・公開性・機密度）を設定します。

- **Request Body**:
  ```json
  {
    "name": "Auth Service",
    "description": "OAuth2 / OIDC authentication service",
    "businessCriticality": "High",
    "isInternetFacing": true,
    "dataSensitivity": "Confidential"
  }
  ```
- **Response (201 Created)**: 作成された Project オブジェクト。

---

## 3. スキャン実行・リアルタイム進捗 (Scans & SSE)

### `POST /api/v1/projects/{projectId}/scans`
指定プロジェクトに対する統合スキャンをキューに投入します。

- **Headers**: `Idempotency-Key: <unique-uuid>` (重複投入防止)
- **Request Body**:
  ```json
  {
    "scannerTypes": ["Semgrep", "Trivy", "Gitleaks", "OSV-Scanner"],
    "targetBranch": "main"
  }
  ```
- **Response (202 Accepted)**:
  ```json
  {
    "scanId": "8f8774e1-7d1f-4ef8-8dc0-5bb96fc4c9bb",
    "status": "Queued",
    "enqueuedAt": "2026-10-21T12:00:00Z"
  }
  ```

### `GET /api/v1/scans/{id}/events`
スキャンの進捗状況（各スキャナーの実行中・完了、検出数、エラー）をリアルタイムに Server-Sent Events (SSE) でストリーミングします。

- **Response Headers**: `Content-Type: text/event-stream`
- **Stream Output**:
  ```
  data: {"scanId":"8f8774...","step":"Running Semgrep SAST","progressPercent":25,"status":"Running"}

  data: {"scanId":"8f8774...","step":"Running Trivy SCA","progressPercent":50,"status":"Running"}

  data: {"scanId":"8f8774...","step":"Deduplication & Risk Scoring","progressPercent":90,"status":"Running"}

  data: {"scanId":"8f8774...","step":"Completed","progressPercent":100,"status":"Completed"}
  ```

### `POST /api/v1/scans/{id}/cancel`
実行中またはキュー待ちのスキャンをキャンセルします。

---

## 4. 脆弱性検索・トリアージ (Findings & Keyset Pagination)

### `GET /api/v1/findings`
複合フィルタおよび Keyset カーソルページネーションを用いた高速脆弱性検索。

- **Query Parameters**:
  - `ProjectId`: GUID (任意)
  - `Severity`: `Critical`, `High`, `Medium`, `Low`, `Info` (任意)
  - `Status`: `Open`, `InReview`, `Confirmed`, `FalsePositive`, `RiskAccepted`, `Resolved` (任意)
  - `Category`: `SAST`, `SCA`, `Secret`, `Container`, `IaC` (任意)
  - `IsKev`: `true` / `false` (任意)
  - `Keyword`: ファイルパス、タイトル、CWE、CVEでの検索 (任意)
  - `Limit`: 取得件数 (デフォルト 50, 最大 200)
  - `Cursor`: 次ページ取得用 Base64 カーソル
- **Response (200 OK)**:
  ```json
  {
    "items": [
      {
        "id": "e44d32a1-8d2b-4560-9b6e-1d54f3b798cf",
        "projectId": "2d8517f7-ec68-4714-96a2-931f6d7c5cf8",
        "title": "SQL Injection in QueryBuilder",
        "severity": "Critical",
        "riskScore": 92.5,
        "status": "Open",
        "scannerName": "Semgrep",
        "cweId": "CWE-89",
        "cveId": "CVE-2024-1234",
        "filePath": "src/Handlers/OrderHandler.cs",
        "startLine": 142,
        "isKev": true,
        "epssScore": 0.854,
        "reachability": "Reachable",
        "occurrenceCount": 3,
        "createdAt": "2026-10-21T10:15:00Z"
      }
    ],
    "nextCursor": "OTIuNV9lNDRkMzJhMS04ZDJiLTQ1NjAtOWI2ZS0xZDU0ZjNiNzk4Y2Y=",
    "totalCount": 100248
  }
  ```

### `GET /api/v1/findings/{id}`
脆弱性の詳細、エビデンス（コードスニペット・Taintフロー）、および詳細リスクスコア内訳を取得します。

### `PATCH /api/v1/findings/{id}/triage`
トリアージステータス、担当者、およびコメントを更新します。

- **Request Body**:
  ```json
  {
    "status": "FalsePositive",
    "assignedTo": "security-engineer@company.local",
    "comment": "入力値はORMのプレースホルダーで安全にパラメータ化されているため誤検知と判定。"
  }
  ```

---

## 5. AI調査・修正パッチ支援 (AI Remediation & Verification)

### `POST /api/v1/findings/{id}/remediations`
LLM または決定論的ルールエンジンにより、Unified Diff 形式の修正パッチと影響分析を生成します。

- **Response (200 OK)**:
  ```json
  {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "findingId": "e44d32a1-8d2b-4560-9b6e-1d54f3b798cf",
    "verifiedFacts": [
      "File: src/Handlers/OrderHandler.cs",
      "Line 142 contains string interpolation in raw SQL query.",
      "CWE-89 SQL Injection detected by Semgrep."
    ],
    "aiHypothesisAnalysis": "外部から渡された注文IDがサニタイズされずに直接SQL文に連結されており、任意のSQL実行が可能です。",
    "proposedUnifiedDiff": "--- a/src/Handlers/OrderHandler.cs\n+++ b/src/Handlers/OrderHandler.cs\n@@ -141,3 +141,3 @@\n- var sql = $\"SELECT * FROM orders WHERE id = '{orderId}'\";\n+ var sql = \"SELECT * FROM orders WHERE id = @orderId\";\n",
    "sideEffectsWarning": "パラメータ化クエリへの移行により、ADO.NETの型マッピングが厳格化されます。単体テストの通過を確認してください。",
    "verificationStatus": "Pending",
    "createdAt": "2026-10-21T12:30:00Z"
  }
  ```

### `POST /api/v1/remediations/{id}/verify`
一時サンドボックス環境にパッチを適用し、元のスキャナーを再実行して「脆弱性が本当に解消されたか」を自動検証します。

- **Response (200 OK)**:
  ```json
  {
    "remediationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "verificationStatus": "VerifiedFixed",
    "verificationOutput": "Semgrep re-scan passed with 0 findings in modified files. No regressions detected.",
    "verifiedAt": "2026-10-21T12:31:00Z"
  }
  ```

### `POST /api/v1/remediations/{id}/approve`
検証済みの修正パッチをセキュリティ担当者が承認します。

---

## 6. エクスポート・SBOM・OpenVEX (Exports & VEX)

### `GET /api/v1/projects/{projectId}/export`
- **Query Parameter**: `format=json|csv|sarif`
- フィルタ条件に合致するすべての Finding を標準形式で出力します。

### `GET /api/v1/projects/{projectId}/sbom`
- プロジェクトの CycloneDX 1.6 依存関係コンポーネントツリーと、OpenVEX（脆弱性影響有無の機械可読表明）を取得します。

---

## 7. ヘルスチェック・監視 (Health & Observability)

### `GET /health/live`
サービスの生存確認（Liveness Probe）。
- **Response (200 OK)**: `{"status":"Healthy","timestamp":"..."}`

### `GET /health/ready`
データベースおよびジョブキューの正常稼働確認（Readiness Probe）。
- **Response (200 OK)**:
  ```json
  {
    "status": "Ready",
    "database": "Connected",
    "jobQueue": "Operational",
    "queuedJobs": 0,
    "timestamp": "2026-10-21T12:35:00Z"
  }
  ```
