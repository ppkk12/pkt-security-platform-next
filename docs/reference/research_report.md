# 次世代企業向けAIセキュリティプラットフォーム構築に向けた包括的調査レポート

## 1. 製品戦略と品質目標のトレードオフ分析

現代のソフトウェア開発組織は、静的アプリケーションセキュリティテスト（SAST）、ソフトウェアコンポジション解析（SCA）、シークレット検出、Infrastructure as Code（IaC）検査、コンテナイメージスキャン、およびサプライチェーン健全性評価など、多数の専門スキャナーを併用している。しかし、単一画面に複数ツールの出力を集約しただけの従来型プラットフォームは、膨大な検出結果（Finding）によるアラート疲労（Alert Fatigue）、スキャナー間の重複報告、悪用可能性や到達可能性の文脈欠如、そして修正アクションへの断絶という構造的課題を抱えている。

目指すべき次世代プラットフォームは、複数スキャナーの検出結果を標準スキーマへ正規化・統合し、客観的根拠（Evidence）に基づいてリスクを優先順位付けし、AIによる原因調査と安全な修正パッチ（Unified Diff）の生成・再検証までを一気通貫で支援する統合Application Security Posture Management（ASPM）および修正支援基盤である。

11の品質目標をすべて同時に無条件で最大化することは工学的に不可能であり、明確な優先順位付けとトレードオフの定義が不可欠である。以下のテーブルに、品質目標間のトレードオフと設計上の優先順位を示す。

| 品質目標 | 優先度 | 競合する目標（トレードオフ） | 設計上の解決方針と優先順位の根拠 |
| :--- | :--- | :--- | :--- |
| セキュリティとテナント分離 | 最優先（P0 / Non-Negotiable） | 開発速度・クエリ単純性・スキャン起動オーバーヘッド | セキュリティ製品自身が侵害・情報漏洩源となることは許されない。API層とPostgreSQLの[Row-Level Security (RLS)](https://www.google.com/search?q=https%3A%2F%2Fwww.postgresql.org%2Fdocs%2Fcurrent%2Fddl-rowsecurity.html)による二重分離、およびスキャン実行環境の[gVisor](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fgvisor)やRootlessコンテナによる厳格な隔離を最優先する。 |
| スキャン処理の安全な隔離 | 最優先（P0 / Non-Negotiable） | スキャン起動レイテンシ・ホストリソース効率 | 検査対象リポジトリやアーカイブは「信頼できない入力（Untrusted Input）」である。Web APIプロセスとは完全に分離されたワーカーとエフェメラルサンドボックスで実行し、数ミリ秒〜数百ミリ秒の起動コスト増加を許容して安全性を担保する。 |
| 検出能力と検出結果の信頼性 | 高（P1） | スキャン実行時間・CPU/メモリ消費量 | 自前で未熟な解析エンジンを再発明せず、[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)、[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)、[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)等の実績あるOSSスキャナーを統合し、行番号ズレに強い2段階フィンガープリント重複排除と到達可能性・VEX統合により信頼性を高める。 |
| 大量検出結果の検索性能・API性能 | 高（P1） | データ正規化の厳密性・書き込み時のインデックス更新コスト | 100万件規模のFindingに対してミリ秒単位のフィルタリングを実現するため、正規化テーブルに加えて検索用の非正規化投影カラム・複合B-Tree/GINインデックス・Keysetページネーションを採用し、書き込み時のわずかなオーバーヘッドを許容する。 |
| 拡張性と長期的な保守性 | 高（P1） | 初期プロトタイプ作成の簡易さ | 初期からマイクロサービスを乱立させるのではなく、強い型付けを持つC# / [ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0)によるモジュラーモノリス＋独立ワーカー構成を採り、運用負荷を抑えつつ境界を明確化する。 |
| 高い同時実行性と運用・障害復旧 | 中〜高（P2） | インフラ構成の単純さ | リース方式（Lease & Heartbeat）のジョブキューと冪等な結果取り込みにより、ワーカークラッシュ時の自動復旧と水平スケールを両立する。 |
| AIによる調査・修正支援の有用性 | 中〜高（P2） | 外部LLM推論コスト・レイテンシ | 全Findingに無差別でLLMを実行するのではなく、決定論的リスク評価で優先度が高い項目やユーザー要求時に限定してAI解析を実行し、必ず人間が差分（Diff）を承認するHuman-in-the-Loop設計とする。 |
| 優れたUI・UXとコストバランス | 中（P2） | 多機能化の網羅性 | 初期フェーズではコアワークフロー（一覧・トリアージ・根拠表示・AI修正差分確認・エクスポート）の応答性と操作性に集中し、過剰なダッシュボード装飾を排して少人数開発での実現可能性を守る。 |

## 2. 世界水準の既存製品・オープンソースの徹底調査

### 2.1 セキュリティ統合プラットフォーム（OSS）の分析

#### OWASP DefectDojo
[OWASP DefectDojo](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fdefectdojo%2Fdjango-defectdojo)は、PythonおよびDjangoフレームワークで実装されたオープンソース（BSD-3-Clauseライセンス）の脆弱性管理・ASPMプラットフォームである。180種類以上のセキュリティツールのレポートパーサーを備え、Product Type → Product（Asset） → Engagement → Test → Findingという階層構造でデータを管理する。

[DefectDojoの公式重複排除ドキュメント](https://www.google.com/search?q=https%3A%2F%2Fdocs.defectdojo.com%2Ftriage_findings%2Ffinding_deduplication%2Fabout_deduplication%2F)によると、オープンソース版ではパーサーごとに以下の4種類の重複排除アルゴリズムを選択できる。
1. `Unique ID From Tool`：スキャナー側が出力する固有ID（`unique_id_from_tool` または `vuln_id_from_tool`）のみを用いて同一性を判定する。エンドポイント情報は無視される。
2. `Hash Code`：スキャナーごとに定義されたフィールド群（`HASHCODE_FIELDS_PER_SCANNER`）および共通必須フィールド（デフォルトでは `HASH_CODE_FIELDS_ALWAYS = ["service"]`）からハッシュ値を計算して比較する。
3. `Unique ID From Tool or Hash Code`：スキャナー固有IDの一致を優先し、一致しない場合にハッシュコード比較へフォールバックする。
4. `Legacy`：静解析と動解析で異なる複合条件を用いる旧来のアルゴリズム。

さらに注目すべき点として、同一Testへの「Reimport（再インポート）」と別Test間の「Same-Tool Deduplication」ではハッシュ計算フィールドが異なる場合がある。たとえばReimport時に行番号（Line Number）をハッシュに含めると、コード編集で行番号が数行ずれただけで「既存のFindingがクローズされ、新規Findingが作成される」という状態リセット問題が発生する。また、商用版（DefectDojo Pro）では複数アセットを束ねる「Dedupe Pools」や、アセット横断の「Global Component Deduplication」「Global Locations Deduplication」が追加されているが、OSS版では原則として同一Product（またはEngagement）内にスコープが限定される。バックグラウンド処理にはCeleryとRedis/RabbitMQを使用するが、数万件規模のSARIFやSCAレポートを一括インポートする際にDjango ORMのオブジェクト生成とハッシュ再計算が集中し、メモリ消費とデータベース負荷が急増する制約が知られている。

#### OWASP Dependency-Track
[OWASP Dependency-Track](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FDependencyTrack%2Fdependency-track)は、Java（独自軽量フレームワークAlpineおよびJersey、DataNucleus JDO）で構築されたソフトウェアサプライチェーン・コンポーネント解析プラットフォーム（Apache-2.0ライセンス）である。[OWASP CycloneDX](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2F)形式のSBOMをファーストクラスで取り込み、NVD、GitHub Advisories、OSV、VulnDB、および[FIRST EPSS](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fepss%2F)と照合してポートフォリオ全体のリスクおよびライセンス違反を継続的に監視する。

設計上の重要な教訓は、次世代アーキテクチャとして開発された[Hyadesプロジェクト](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FDependencyTrack%2Fhyades-apiserver)（Dependency-Track v5系へ統合）の変遷にある。旧来のv4系モノリスでは、APIサーバーがSBOMパース、外部脆弱性DB同期、ポリシー評価、メトリクス集計を単一JVMプロセス内で抱え込んでいたため、大規模エンタープライズ環境で数千プロジェクトのSBOMを同時処理する際にヒープメモリ枯渇とDBロック競合が発生していた。Hyades（v5系）ではこの課題を解決するため、APIサーバー、BOM処理ワーカー、脆弱性アナライザー、ミラーリングサービスを分離する設計へ移行した。ただし、完全なKafkaクラスタを必須とする構成は中規模組織やセルフホスト環境において運用コストが高くなるため、新規プラットフォーム設計においては「初期はPostgreSQLベースの軽量キュー＋独立ワーカープロセスとし、インターフェース抽象化によって将来メッセージブローカーへ差し替え可能にする」という現実的なバランスを学ぶべきである。

### 2.2 主要オープンソース・セキュリティスキャナーの分析

以下のテーブルに、調査対象とした主要OSSスキャナー7製品の技術特性、解析手法、ライセンス、および統合時の設計上の考慮点を示す。

| スキャナー名 / リポジトリ | 実装言語 / ライセンス | 対象領域・検出可能な問題 | 解析手法・内部アーキテクチャ | 統合時の強みと公開情報から確認できる制約 |
| :--- | :--- | :--- | :--- | :--- |
| [Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy) (`aquasecurity/trivy`) | Go / Apache-2.0 | コンテナイメージ、ファイルシステム、Gitリポジトリ、SBOM、Kubernetes、IaC設定不備、シークレット | パッケージマネージャのロックファイル・OSパッケージDB解析、Rego/組み込みルールによるIaC検査、BoltDBによるローカル脆弱性DBキャッシュ | 単一バイナリでSCA・IaC・Secret・SBOM生成（CycloneDX/SPDX）・SARIF出力・OpenVEXフィルタに対応。Client/Serverモードを持つが、初回DBダウンロードや巨大イメージ展開時のディスクI/O制限が必要。 |
| [OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner) (`google/osv-scanner`) | Go / Apache-2.0 | オープンソース依存関係（ロックファイル、SBOM、コンテナ、C/C++ gitコミットハッシュ） | [OSV.dev](https://www.google.com/search?q=https%3A%2F%2Fosv.dev%2F)分散脆弱性データベースへのバッチAPIクエリ、ロックファイル厳密抽出、実験的コールグラフ到達可能性解析 | エコシステム固有のパッケージ名を正確に扱うOSVスキーマに直結し、破壊的変更を最小化する「Guided Remediation」を備える。オフライン環境ではローカルOSVミラーの構築が必要。 |
| [Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep) (`semgrep/semgrep`) | OCaml（コアエンジン）+ Python（CLI） / LGPL-2.1 | SAST（多言語ソースコードの脆弱性パターン、アンチパターン、フレームワーク固有の不備） | `tree-sitter`によるCST解析と汎用AST（`AST_generic`）への変換、YAMLルールによる構文パターンマッチングとファイル内データフロー（Taint）解析 | コンパイル不要で高速に多言語を解析しSARIF出力に対応。ただしOSSエンジンは「単一ファイル内（Intra-file）」解析に限定され、ファイル横断（Cross-file / Interprocedural）解析や一部高度ルールは商用Semgrep Pro / Rules Licenseの対象となる点に注意が必要。 |
| [Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks) (`gitleaks/gitleaks`) | Go / MIT | Gitコミット履歴、ワーキングツリー、ディレクトリ内のハードコードされたAPIキー・トークン・秘密鍵 | Aho-Corasickアルゴリズムによるキーワード事前フィルタリング、正規表現マッチング、Shannonエントロピー計算、`.gitleaksignore`管理 | メモリ効率が高く極めて高速。Git履歴全体を走査するモードでは巨大リポジトリで時間がかかるため、`--log-opts`による差分コミット走査とフルスキャンの使い分けが必要。 |
| [Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft) (`anchore/syft`) | Go / Apache-2.0 | コンテナイメージ、ファイルシステム、アーカイブからの高精度SBOM生成 | 言語・OS別のCatalogerパイプラインによるパッケージ・バイナリ・ライセンス情報の抽出、CycloneDX / SPDX / Syft JSON出力 | 脆弱性検出を行わず「正確な部品表（SBOM）の生成」に特化しているため、一度生成したSBOMをDBに保存し、後から脆弱性DBと高速照合する分離アーキテクチャの要となる。 |
| [Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype) (`anchore/grype`) | Go / Apache-2.0 | コンテナイメージ、ファイルシステム、およびSyft等が生成したSBOMに対する脆弱性スキャン | SQLiteベースの脆弱性DBとパッケージバージョン制約の照合、KEV/EPSS情報の付加、OpenVEX/CSAFによるステータス除外 | Syftが生成したSBOMを入力として受け取ることで、ファイルシステム再走査なしに秒単位で再スキャン（Re-scan）を実行できる。 |
| [OpenSSF Scorecard](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fossf%2Fscorecard) (`ossf/scorecard`) | Go / Apache-2.0 | GitHub / GitLabリポジトリおよびローカルディレクトリのサプライチェーンセキュリティ健全性評価 | Branch-Protection、Pinned-Dependencies、Token-Permissions、SAST、Signed-Releasesなど18以上のProbes/Checksによる0〜10点スコアリング | ソースコード自体ではなくリポジトリ運用とCI/CDの安全性を評価できる。完全な評価にはGitHub/GitLab APIトークンが必要であり、APIレート制限を考慮したキャッシュとレート制御が必須。 |

### 2.3 企業向け商用セキュリティ製品の調査と示唆

#### GitHub Code Security / Secret Protection
[GitHub Advanced Security](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsecurity%2Fadvanced-security)は、[CodeQL](https://www.google.com/search?q=https%3A%2F%2Fdocs.github.com%2Fcode-security%2Fcode-scanning%2Fautomatically-scanning-your-code-for-vulnerabilities-and-errors%2Fabout-code-scanning)によるセマンティックコード解析、Dependabotによるサプライチェーン保護、およびSecret Protection（Push Protectionを含む）を統合している。特筆すべきは[GitHub Copilot Autofix](https://www.google.com/search?q=https%3A%2F%2Fdocs.github.com%2Fen%2Fcode-security%2Fhow-tos%2Fmanage-security-alerts%2Fmanage-code-scanning-alerts%2Fresolve-alerts)と[Security Campaigns](https://www.google.com/search?q=https%3A%2F%2Fdocs.github.com%2Fen%2Fcode-security%2Fconcepts%2Fsecurity-at-scale%2Fabout-security-campaigns)である。Copilot Autofixは、CodeQLが検出したアラートに対して「なぜ脆弱なのか」の自然言語解説と、ビルドやテストを壊さないための依存ファイル変更を含めた具体的なコード差分（Diff）をPull Request上で直接提示する。また、Security Campaignsはセキュリティチームが大量の技術的負債の中から特定のテーマ（例：SQLインジェクションの根絶）でアラートを束ね、開発チームへ進捗追跡付きで割り当てる機能であり、セキュリティ部門と開発部門の協業UXとして極めて参考になる。

#### Snyk（Snyk Code / DeepCode AI / Reachability Analysis）
[Snyk](https://www.google.com/search?q=https%3A%2F%2Fsnyk.io%2Fplatform%2Fdeepcode-ai%2F)は、開発者ファーストのUXと、[DeepCode AI](https://www.google.com/search?q=https%3A%2F%2Fsnyk.io%2Fplatform%2Fdeepcode-ai%2F)と呼ばれるシンボリックAI（プログラム解析・ルール推論）と生成AI（LLM）を組み合わせたハイブリッドエンジンを特徴とする。[SnykのReachability Analysis公式ドキュメント](https://www.google.com/search?q=https%3A%2F%2Fdocs.snyk.io%2Fscan-fix-and-prevent%2Ffix%2Fprioritize-issues-for-fixing%2Freachability-analysis)によれば、Snykはオープンソースの脆弱性修正コミット（Fix Commit）を解析して根本原因となる関数・クラスを特定し、アプリケーションのコールグラフと照合して `REACHABLE`、`NO PATH FOUND`、`NOT APPLICABLE` のステータスを付与する。同時に、Snykは公式ドキュメント上で「静的解析で `NO PATH FOUND` と判定されても、リフレクションや動的挙動により実際には到達可能である可能性（偽陰性）があること」や「アップロード上限（30万ファイル、合計3GB、単一ファイル1MB）」といった技術的制約を明示している。この「到達可能性をリスクスコアの重要な加点要素としつつ、未検出を100%安全と断定しない」設計姿勢は、本プラットフォームのリスク評価設計にそのまま取り入れるべき重要な原則である。

#### Wiz Code
[Wiz Code](https://www.google.com/search?q=https%3A%2F%2Fwww.wiz.io%2Fplatform%2Fwiz-code)は、クラウドセキュリティ（CNAPP）で培った[Wiz Security Graph](https://www.google.com/search?q=https%3A%2F%2Fwww.wiz.io%2Flp%2Fwiz-security-graph)をソースコードとCI/CDパイプラインへ拡張し、「Code-to-Cloud（コードからクラウド実行環境まで）」の双方向トレーサビリティを実現している。単なるCVSSスコアではなく、「そのコードがデプロイされているコンテナがインターネットに公開されているか」「機密データへのIAMアクセス権を持っているか」というランタイム・インフラ文脈を掛け合わせて実際の悪用経路（Attack Path）を特定する。新規プラットフォームにおいても、スキャン対象プロジェクトに対して「外部公開有無（Internet Exposure）」「取扱データ機密度（Data Sensitivity）」「本番環境稼働有無」の資産コンテキスト（Asset Context）を付与し、リスク算出に反映する設計が有効である。

#### GitLab Ultimate Security / GitLab Duo & Endor Labs
[GitLab Advanced SAST](https://www.google.com/search?q=https%3A%2F%2Fdocs.gitlab.com%2Fuser%2Fapplication_security%2Fsast%2Fgitlab_advanced_sast%2F)は、ファイル横断・関数横断のTaint解析による誤検知削減と、コードフロー（SourceからSinkまでの伝播経路）の視覚的表示を提供する。さらに[GitLab Duo](https://www.google.com/search?q=https%3A%2F%2Fdocs.gitlab.com%2Fuser%2Fapplication_security%2Fsast%2Fevaluation_guide%2F)のVulnerability ExplanationおよびVulnerability Resolutionは、脆弱性詳細画面からワンクリックでAIによる解説と修正Merge Requestを生成する。また、[Endor Labs](https://www.google.com/search?q=https%3A%2F%2Fwww.endorlabs.com%2Fuse-case%2Fsca-with-reachability)は、マニフェストファイルに明記されていないにもかかわらずコード内で使用されている「[Phantom Dependencies（幽霊依存関係）](https://www.google.com/search?q=https%3A%2F%2Fdocs.endorlabs.com%2Fscan%2Fsca%2Freachability-analysis)」や推移的依存関係の関数レベル到達可能性を精密に可視化することで、SCAのノイズを80%以上削減するアプローチを確立している。

### 2.4 既存製品から何を学び、何を再現せず、どこで差別化するか

1. **学ぶべき設計（Adopt）**
   - **SBOM生成と脆弱性照合の分離（Syft + Grype / Dependency-Track型）**：ソースコードやコンテナから一度[Syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft)や[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)で標準[CycloneDX](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2F) SBOMを生成・永続化すれば、新たなCVEや[CISA KEV](https://www.google.com/search?q=https%3A%2F%2Fwww.cisa.gov%2Fknown-exploited-vulnerabilities-catalog)が公開された際、リポジトリを再クローンすることなくデータベース上のパッケージグラフおよび[Grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype)/OSV照合だけで数秒で影響範囲を特定できる。
   - **行番号変動に耐性のある重複排除（DefectDojoの改善版）**：単なる行番号一致ではなく、ファイルパス＋CWE/RuleID＋対象シンボル名（関数・クラス名）＋前後コードの正規化トークンハッシュを組み合わせた「Location-Drift-Resilient Fingerprint」を実装する。
   - **根拠明示型の複合リスクスコアとHuman-in-the-Loop AI修正（Snyk / GitHub Copilot Autofix型）**：AIの出力を決定論的スキャナーの証拠（Evidence）と明確に区別し、Unified Diff形式で提示して人間が承認するフローを採用する。
2. **再現する必要がないもの（Avoid / Do Not Reinvent）**
   - **独自のSAST構文解析エンジンや独自CVEクローラーのゼロからの自作**：これらは数十年分のルール資産・言語対応が必要であり、[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)、[Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)、[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)、[OSV-Scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner)をプラガブルなアダプター経由で呼び出し、[SARIF 2.1.0](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fsarif%2Fsarif%2Fv2.1.0%2Fsarif-v2.1.0.html)および[CycloneDX 1.6](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FCycloneDX%2Fspecification%2Fblob%2Fmaster%2Fschema%2Fbom-1.6.schema.json)へ正規化する方が圧倒的に高品質かつ合理的である。
   - **DefectDojoのような180種類以上のレガシー独自XML/CSVパーサーの初期実装**：現代の主要ツールはほぼすべてSARIFまたはCycloneDX JSONを出力できるため、標準フォーマット（SARIF 2.1.0 / CycloneDX / OpenVEX）＋主要OSSスキャナーのネイティブJSONアダプターに集中する。
3. **本プラットフォームが差別化できる領域（Differentiate）**
   - **異種スキャナー間のクロス相関（Cross-Scanner Correlation）**：たとえば「SCA（Trivy/OSV）で検出された脆弱なライブラリ」と「SAST（Semgrep）で検出された当該ライブラリの危険なAPI呼び出し箇所」を同一グラフ上で結合し、「実際にコード内で悪用可能な形で呼び出されている」ことを決定論的証拠として提示する。
   - **AI修正パッチの自動再スキャン検証（Closed-Loop Verification）**：LLMが生成した修正パッチ案をそのままユーザーに見せるだけでなく、隔離サンドボックス内で仮想適用して該当スキャナーを再実行し、「本当にFindingが消滅し、新たな脆弱性を生んでいないか」を検証したバッジ付きで提示する。
   - **日本企業のエンタープライズ要件へのネイティブ適合**：経済産業省の「[ソフトウェア管理に向けたSBOMの導入に関する手引 Ver2.0](https://www.google.com/search?q=https%3A%2F%2Fwww.meti.go.jp%2Fpress%2F2024%2F08%2F20240829001%2F20240829001.html)」や[IPAの脆弱性対策基準](https://www.google.com/search?q=https%3A%2F%2Fwww.ipa.go.jp%2Fsecurity%2Fvuln%2Findex.html)に準拠した日本語レポート出力、完全オフライン（エアギャップ）/セルフホスト動作、ローカルLLM（Ollama / vLLM等）切り替え、および承認ワークフロー（稟議・リスク受容承認証跡）を標準搭載する。

## 3. GitHub公開リポジトリの内部構造・設計調査と教訓

主要OSSリポジトリの実装構成を確認し、アーキテクチャ・モジュール境界・テスト・ライセンスの観点から以下の知見を抽出した。なお、公開リポジトリのコード・ドキュメントから確認できた事実と、本番環境での非公開テレメトリ等を含む不明点は厳密に区別している。

| リポジトリ | ディレクトリ・モジュール境界の特徴 | テスト・CI/CD・品質管理の特徴 | ライセンスと商用組み込み時の法的・技術的注意点 |
| :--- | :--- | :--- | :--- |
| [aquasecurity/trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy) | `pkg/fanal`（ファイルシステム・イメージ・言語別解析）、`pkg/detector`（OS/言語別脆弱性判定）、`pkg/vex`（OpenVEX/CSAF評価）、`pkg/rpc`（Client/Server gRPC/HTTP通信）に明確に分離。 | ゴールデンファイル（入力ファイルと期待されるJSON/SARIF出力のペア）を用いた統合テストが充実。GitHub ActionsでマルチOSビルドとE2Eテストを実行。 | Apache-2.0。外部プロセスまたはServerモードとしての呼び出し、出力JSON/SARIFの取り込みともに商用利用に最適。著作権表示とNOTICEの保持が必要。 |
| [google/osv-scanner](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner) | `pkg/lockfile`（各言語ロックファイル抽出器）、`pkg/osv`（APIクライアント）、`pkg/remediation`（アップグレード計算）、`internal/Semantic`（エコシステム別バージョン比較）。 | 各パッケージマネージャのテストフィクスチャに対するスナップショットテストと異常系テストを完備。OpenSSF Scorecardを自身のCIで実行。 | Apache-2.0。ロックファイルパーサーの設計およびOSVバッチ照合の実装パターンとして極めて参考になる。 |
| [semgrep/semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep) | `src/`配下にOCamlによるコア解析エンジン（`parsing`, `matching`, `tainting`, `engine`）、`cli/`配下にPython製ラッパーとSARIFフォーマッタを配置。 | OCaml側の単体テストとPython CLI側のE2Eテストを分離。 | コアはLGPL-2.1。ライブラリとして静的リンクするとLGPLのソース開示義務が生じるため、**必ず独立したCLIプロセス（コンテナ内サブプロセス）として標準入出力/ファイル経由で実行する疎結合アダプター方式**を採るべきである。また、`semgrep-rules`リポジトリの一部ルールは独自ライセンス（Semgrep Rules License）であるため、商用製品にバンドルするルールはMIT/Apache-2.0等のパーミッシブなルールまたは自社作成ルールに限定する必要がある。 |
| [gitleaks/gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks) | `detect/`（スキャナー本体、Aho-Corasick + Regexp）、`config/`（TOMLルール定義）、`report/`（SARIF/JSON/CSV出力）、`sources/`（Git/Directory入力抽象化）。 | ルールごとの陽性・陰性テストケースを網羅し、誤検知防止の回帰テストを自動化。 | MIT。極めて寛容であり、バイナリ同梱・サブプロセス実行ともに問題ない。 |
| [anchore/syft](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft) & [anchore/grype](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype) | Syftは `syft/pkg/cataloger/` 配下にエコシステム別の独立したCatalogerを実装。Grypeは `grype/matcher/` でエコシステム別のバージョン照合ロジックを分離。 | 両者とも豊富なモックイメージとテーブル駆動テスト（Table-driven tests）を採用。 | Apache-2.0。SyftとGrypeのインターフェース分離（SBOM JSONを介した疎結合）は、本プラットフォームの内部パイプライン設計の模範となる。 |
| [DefectDojo/django-DefectDojo](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fdefectdojo%2Fdjango-DefectDojo) | `dojo/tools/` 配下に180以上のスキャナー別ディレクトリ（`parser.py`）を配置し、`dojo/deduplication/` と `dojo/finding/` で共通処理を行うモノリシック構造。 | Django TestCaseによる単体・APIテストおよびPlaywright等のUIテスト。 | BSD-3-Clause。パーサー群の正規化マッピング知見は参考になるが、Python/Django ORMの密結合モデルをそのまま模倣すると大規模検索性能でボトルネックとなる。 |

## 4. 言語と技術スタックの徹底比較（14コンポーネント領域別評価）

一般論（「Pythonは遅い」「C++は速い」など）を排し、セキュリティプラットフォームの実際のワークロード特性（I/Oバウンド、CPUバウンド、メモリ割り当て、プロセス制御、型安全性、エコシステム）に照らして、C# / [ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0)、Go、Rust、C++、Python / FastAPI の5候補を14のコンポーネント領域ごとに比較評価した。

### 4.1 14コンポーネント領域別の適性比較マトリクス

| # | コンポーネント領域 | C# / ASP.NET Core (.NET 8/9/10) | Go | Rust | C++ | Python / FastAPI | 最適候補と選定理由の核心 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | HTTP APIとリクエスト処理 | ◎ 最良（Kestrel、System.Text.Json Source Generator、Minimal APIs） | ◎ 優秀（net/http、高速・省メモリ） | ◎ 優秀（Axum / Actix-web） | △ 過剰（開発コスト大・メモリ安全リスク） | ○ 良好（非同期I/Oは可だがシリアライズとCPU負荷に弱い） | **C# / ASP.NET Core**：Kestrelの圧倒的スループットとOpenAPI/型安全・ミドルウェア生産性のバランスが最良。 |
| 2 | 認証・認可・RBAC | ◎ 最良（ASP.NET Core Identity、Policy/Claimsベース認可、OIDC/SAML標準対応） | ○ 良好（ライブラリ組み合わせが必要） | ○ 良好（Tower等の自前実装比率が高め） | × 不適 | ○ 良好（外部ライブラリ依存） | **C# / ASP.NET Core**：エンタープライズ認証（OIDC/Entra ID/Keycloak）、細粒度RBAC/ABAC、監査フックがフレームワーク標準で成熟。 |
| 3 | テナント管理とデータアクセス | ◎ 最良（EF Core Global Query Filters + Npgsql接続インターセプタによるRLS注入） | ○ 良好（pgx + sqlc、動的クエリ構築はやや冗長） | ○ 良好（SQLx / SeaORM、コンパイル時検証は強力） | × 不適 | ○ 良好（SQLAlchemy 2.0、ただし大量オブジェクト生成時のGC/メモリ負荷大） | **C# / ASP.NET Core**：`DbCommandInterceptor`等によりすべてのDB接続で確実にPostgreSQL `SET LOCAL app.current_tenant_id` を強制でき、EF CoreとDapperの併用が容易。 |
| 4 | 大量の検出結果の検索・フィルタリング | ◎ 最良（Npgsql非同期ストリーミング、式木による動的クエリ構築） | ○ 良好（文字列/ビルダによる動的SQL構築） | ○ 良好（型安全な動的フィルタ構築の記述量が多い） | △ 不適 | △ 課題あり（大量行フェッチ時のPythonオブジェクト化コストが高い） | **C# + PostgreSQL**：検索速度の90%はPostgreSQLのインデックス設計とクエリプランで決まるが、数千件の結果セットをJSONへストリーミング変換する処理でC#が極めて高速。 |
| 5 | データ変換と集計（SARIF / CycloneDX数万件パース） | ◎ 最良（`Utf8JsonReader`、`Span<T>`、`ArrayPool<T>`によるゼロアロケーションに近い高速解析） | ◎ 優秀（ストリーム処理は得意だが標準`encoding/json`はリフレクション負荷あり） | ◎ 最良（`serde_json`による最高速クラスのゼロコピーデシリアライズ） | ◎ 高速（ただしパースバグがメモリ破壊・RCEに直結） | × ボトルネック（Pydantic v2で改善したものの巨大JSONの加工・重複排除ループでGILが阻害） | **C#（またはRust）**：数十MB〜数百MBのSARIF/SBOM JSONをストリーミング解析し、ハッシュ計算・正規化する処理において、C#の`Span<T>`とServer GCはPython比で桁違いの性能と省メモリ性を発揮する。 |
| 6 | ジョブの登録・配信・状態管理 | ◎ 最良（`System.Threading.Channels`、`BackgroundService`、PostgreSQL `FOR UPDATE SKIP LOCKED`） | ◎ 最良（Goroutine + Channel） | ◎ 優秀（Tokio async tasks） | △ 過剰 | ○ 良好（Celery/Arq等の別プロセス・Redis必須化） | **C# / Go**：C#の`BackgroundService`とPostgreSQLのリース管理により、初期段階でRedis等を増やさずとも堅牢な非同期ワーカーを構築可能。 |
| 7 | スキャンのオーケストレーション | ◎ 優秀（`CliWrap` / `System.Diagnostics.Process`、CancellationToken連動） | ◎ 最良（`os/exec`、コンテナランタイム・CRI・Docker APIとの親和性が業界最高） | ◎ 優秀（`tokio::process`） | △ 不適 | ○ 良好（`asyncio.subprocess`） | **Go または C#**：コンテナランタイム（Docker / containerd / gVisor）やOSSスキャナー（多くがGo製）の制御にはGoまたはC#が適する。 |
| 8 | ファイル解析とアーカイブ処理（Zip Bomb対策等） | ◎ 優秀（`System.IO.Compression` + ストリーム上限ラッパー） | ◎ 優秀（`archive/zip`, `archive/tar` + `io.LimitReader`） | ◎ 最良（メモリ安全かつネイティブ最高速、パストラバーサル防止型設計） | × 危険（バッファオーバーフロー・メモリ破壊の温床） | △ 低速（大量ファイル展開・ハッシュ計算でCPUボトルネック） | **Rust / Go / C#**：C++は脆弱性リスクが高すぎるため除外。C#のストリーム制限またはRust/Goの安全な展開処理が適切。 |
| 9 | CPU負荷の高い処理（ハッシュ計算・AST/トークン正規化・エントロピー計算） | ◎ 優秀（JIT最適化、SIMD `System.Runtime.Intrinsics`、マルチコア並列処理） | ○〜◎ 良好（並行処理は得意だが密な数値・文字列ループはC#/Rustが優位） | ◎ 最良（GCポーズなし、SIMD、LLVM最適化） | ◎ 最良（ただし安全性コスト大） | × 不適（GILによりマルチコアを使い切れず、ネイティブ拡張なしでは10〜50倍遅い） | **C#（および必要に応じRust）**：C#（.NET 8/9/10）のJITとSIMD最適化により、大半のCPU処理はC#単体で十分に高速。さらに極限のAST解析が必要な場合のみRust製バイナリを併用する。 |
| 10 | 大量の並行I/O（DB・外部脆弱性API・SSE配信） | ◎ 最良（`async/await` ステートマシン、ValueTask、極めて低いコンテキストスイッチ負荷） | ◎ 最良（Goroutineスケジューラによる軽量並行I/O） | ◎ 最良（Tokio M:Nランタイム） | △ 実装複雑 | ○ 良好（`asyncio`、ただしCPU処理が混ざるとイベントループが詰まる） | **C# / Go**：C#の非同期I/OはCPU処理が混在してもスレッドプールが自動スケールし、SSE（Server-Sent Events）の何千本もの同時接続も軽快に捌ける。 |
| 11 | メトリクス・ログ・監査処理 | ◎ 最良（OpenTelemetry .NET標準統合、構造化ログ`ILogger`高効率Source Generator） | ◎ 優秀（`slog` + OpenTelemetry Go） | ○ 良好（`tracing`クレート） | △ 負担大 | ○ 良好（OpenTelemetry Python、オーバーヘッドはやや高め） | **C# / ASP.NET Core**：.NET 8以降のOpenTelemetryネイティブ統合と構造化ロギングはゼロアロケーション設計が進んでおりエンタープライズ監査に最適。 |
| 12 | AI推論や外部AI APIとの連携 | ◎ 優秀（`Microsoft.Extensions.AI`、Semantic Kernel、OpenAI/Anthropic/Ollama HTTP統合） | ○ 良好（HTTP/JSONクライアント連携は容易） | ○ 良好（`rig`等のクレート） | △ 不適 | ◎ 最良（LangChain/LlamaIndex/PyTorch等の研究開発エコシステムは最大） | **C#（外部API/ローカルLLM呼び出し）**：自前でディープラーニングモデルを学習するのではなく、LLM API（OpenAI/Claude/vLLM/Ollama）に対して構造化プロンプトを送りJSON Schema出力を検証する用途では、C#の非同期HTTPと型安全なJSON検証で完全に完結する。 |
| 13 | 配布用エージェントやCLI（CI/CDランナー投入用） | ○ 良好（Native AOTで単一バイナリ化可能だがクロスコンパイルはGoが手軽） | ◎ 最良（依存ゼロの単一静的バイナリ、全OS/Archへのクロスコンパイルが数秒） | ◎ 優秀（単一バイナリ・省メモリ、ビルド時間は長め） | △ 配布困難 | × 不適（ランタイム同梱で肥大化・環境依存トラブル多発） | **Go（またはC# Native AOT）**：顧客のCI/CDパイプラインやオンプレミス環境に配布する軽量CLI/エージェントを作成する場合、Goのクロスコンパイル単一バイナリが圧倒的に有利。 |
| 14 | メモリ使用量とリソース制御 | ○〜◎ 良好（Server GCはスループット重視でメモリを多めに確保するが、DATAS / コンテナ制限設定で制御可能） | ◎ 優秀（バイナリ・ヒープともに小さく予測しやすい） | ◎ 最良（GCなし、最小メモリフットプリント） | ◎ 最小（手動管理） | △ 課題あり（ワーカープロセス複製時のメモリ消費が大きい） | **Rust / Go / C#（DATAS有効化）**：.NET 8/9以降のDynamic Adaptation To Application Sizes（DATAS）を有効化することで、コンテナ環境でのC#のメモリ使用量は大幅に最適化される。 |

### 4.2 性能評価に関する厳密な原則と公開ベンチマークの正しい解釈

[TechEmpower Framework Benchmarks (Round 22 / Round 23)](https://www.google.com/search?q=https%3A%2F%2Fwww.techempower.com%2Fbenchmarks%2F)等の公開ベンチマークでは、[ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0)（C#）とRust（Actix/Axum）、C++（Drogon等）が最上位グループに位置し、Goがそれに続き、Python（FastAPI/Uvicorn）はPlaintextやJSONシリアライズ、複数DBクエリ（Fortunes / Multiple Queries）において数分の一〜十数分の一のスループットとなる傾向が示されている。しかし、これらのベンチマーク数値をそのまま本製品の性能根拠として無批判に引用してはならない。実際のアプリケーション性能は以下の5つの要因に分解して評価する必要がある。

1. **言語・ランタイムの違いで直接改善する部分**
   - 50MB〜200MBの巨大なSARIF / CycloneDX JSONファイルのストリームパースとオブジェクトマッピング。
   - 数万件のFindingに対する正規化トークン抽出、SHA-256フィンガープリント計算、Aho-Corasick / 正規表現マッチング、およびインメモリでの重複排除ループ。
   - 多数のSSEクライアントへのリアルタイム進捗配信と大量リクエストの同時受付（ここでPythonのGILやオブジェクト生成コストに対するC# / Go / Rustの優位性が明確に現れる）。
2. **データベース設計・インデックス・クエリによって決まる部分（言語を変えても速くならない部分）**
   - 100万件のFindingテーブルに対する「重要度＝Critical AND ステータス＝Open AND パッケージ名部分一致」といった検索・フィルタリング・ソート速度。
   - `OFFSET 50000 LIMIT 50` のような深いオフセットページネーションによる全件走査の遅延（Keyset / Cursorページネーションへの変更が必須）。
   - PostgreSQLのRLSポリシー評価時に、`tenant_id` が複合インデックスの先頭に含まれていないことによるSequential Scanの発生。
3. **外部プロセス（スキャナー）やネットワーク待ちによって決まる部分**
   - [Trivy](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)、[Semgrep](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)、[Gitleaks](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)のサブプロセス実行時間そのもの（メインAPIをC#にしてもRustにしても、Semgrep自体の実行時間は変わらない）。
   - 外部LLM API（OpenAI / Anthropic / ローカルvLLM）のトークン生成待ち時間（数秒〜数十秒）、およびOSV.dev / EPSS / CISA KEVフィードのHTTP取得時間。
4. **アーキテクチャやアルゴリズムによって決まる部分**
   - リポジトリのフルクローンを繰り返すか、`git clone --depth 1` やキャッシュ済みSBOMに対する差分照合（Syft + Grype分離モデル）を行うか。
   - Findingを1件ずつ `INSERT` するか（N+1問題）、PostgreSQLの `COPY`（C# `NpgsqlBinaryImporter`）やバルクUpsertを用いて一括永続化するか。
5. **実測するまで優劣を断定できない部分**
   - PostgreSQL RLSを有効化した状態でのパーティションテーブルに対する複雑集計クエリのプランナ挙動。
   - サンドボックス方式（Rootless Docker/Podman vs gVisor `runsc`）によるファイルシステムI/O中心スキャン（Trivy/Semgrep）の実行時間オーバーヘッド比率。

## 5. 製品の独自価値（差別化戦略）と日本市場への適合

### 5.1 異種スキャナー結果の正規化・3階層重複排除・クロス相関

各スキャナーの出力は、標準フォーマットである[OASIS SARIF Version 2.1.0](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fsarif%2Fsarif%2Fv2.1.0%2Fsarif-v2.1.0.html)および[OWASP CycloneDX v1.6/v1.7](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2Fspecification%2Foverview%2F)を取り込みの共通基底としつつ、スキャナー固有のメタデータ（Gitleaksのコミットハッシュやエントロピー値、TrivyのLayer情報など）を欠落させないよう `FindingEvidence` のJSONBフィールドにロスレス保持する。その上で、以下の3階層アルゴリズムによって重複排除と相関付けを行う。

- **第1階層（Exact Tool Identity Match）**：同一スキャナー・同一ルール・同一ファイル・同一行（または同一パッケージPURL＋CVE ID）の完全一致。再スキャン時は新規レコードを作らず `last_seen_scan_id` と `occurrence_count` を更新する。
- **第2階層（Location-Drift-Resilient Fingerprint Match）**：ソースコードの編集により行番号が上下に移動しても同一の脆弱性として追跡できるよう、`SHA256(tenant_id + project_id + scanner_category + normalized_rule_or_cwe + file_path + enclosing_symbol_name + normalized_code_snippet_tokens)` を計算する。空白・コメント・変数リネームを正規化したトークン列のハッシュを用いることで、[DefectDojoの課題](https://www.google.com/search?q=https%3A%2F%2Fdocs.defectdojo.com%2Ftriage_findings%2Ffinding_deduplication%2Fabout_deduplication%2F)であった「行番号ズレによるトリアージ状態の消失（誤検知フラグやリスク受容コメントのリセット）」を防止する。
- **第3階層（Cross-Scanner Semantic Correlation）**：異なるスキャナーが同一の根本原因を報告した場合（例：TrivyとOSV-Scannerが同じ `pkg:npm/lodash@4.17.15` の `CVE-2020-8203` を報告、あるいはSemgrepと別SASTが同じファイルの同じ関数内で `CWE-89` を報告）、それらを勝手に削除して証拠を消すのではなく、1つの親 `FindingGroup`（またはプライマリFinding）の下に複数の `ScannerEvidence` として統合リンクする。複数ツールが独立して同一箇所を検出した事実は「検出確信度（Confidence Score）」の引き上げ根拠として利用する。

### 5.2 根拠に基づく決定論的リスク評価（Evidence-Based Risk Scoring）

CVSS基本値（Base Score）のみに依存すると、実際には悪用コードが存在しない脆弱性や内部テスト用ツール内の脆弱性がすべて「Critical」となり、対応が麻痺する。本プラットフォームでは、[CVSS v4.0](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fcvss%2Fv4.0%2Fspecification-document)（またはv3.1）、[FIRST EPSS（30日以内の悪用確率）](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fepss%2F)、[CISA KEV（既知の悪用が確認された脆弱性カタログ）](https://www.google.com/search?q=https%3A%2F%2Fwww.cisa.gov%2Fknown-exploited-vulnerabilities-catalog)、コード到達可能性（Reachability）、資産重要度（Asset Criticality & Internet Exposure）、およびスキャナー確信度（Confidence）を組み合わせた0〜100点の決定論的リスクスコアを算出する。

重要な設計原則として、**「外部情報が存在しない場合は推測で埋めない（No-Guessing Policy on Missing Data）」**を徹底する。たとえば独自コードのSAST検出（CVE番号を持たないCWE検出）にはEPSSやKEVは存在しない。このときAIに勝手に悪用確率を推測させるのではなく、`epss_score = null`, `is_kev = false` として記録し、SAST用の評価式（CWEの危険度 × データフロー確信度 × 資産の外部公開度）を適用する。スコアの内訳（なぜ88点なのか）は、すべての構成要素と参照URL（NVD、OSV、CISA KEV、EPSS取得日時）とともにJSON構造体として保存・UI表示し、完全な説明可能性（Explainability）を担保する。

### 5.3 AIによる調査・修正支援とHuman-in-the-Loop統制

AI機能は「チャットボットのおまけ」ではなく、構造化された調査・修正パイプラインとして設計する。
1. **事実（Facts）とAI推論（AI Hypotheses）の厳格な分離**：AIの出力スキーマをJSON Schemaで厳격に定義し、`verified_facts`（スキャナー出力・CVE/CWE定義・該当コード行から直接引用された事実）と、`ai_analysis`（影響分析・攻撃シナリオの推論）、`proposed_patch`（Unified Diff形式の修正案）、`limitations_and_risks`（この修正による副作用や未検証事項）を別フィールドとして強制分離する。
2. **自動再スキャンによるパッチ検証（Sandbox Patch Verification）**：AIが生成したUnified Diffを、隔離サンドボックス内のワークツリーコピーに `git apply --check` で適用可能性を検査し、適用後に該当スキャナー（Semgrep等）を再実行して「対象のFindingが解消され、かつ新規Findingが発生していないか」を自動検証し、`verification_status`（`VerifiedFixed` / `PatchAppliesButFindingRemains` / `PatchInvalid` / `Unverified`）を記録する。
3. **人間による承認（Human-in-the-Loop）の原則**：AIが生成したパッチを無条件で本番ブランチへコミット・プッシュすることは禁止する。必ずUI上でシンタックスハイライトされたUnified Diffと検証結果を確認し、権限を持つ開発者またはセキュリティ担当者が明示的に承認（Approve）した上で、パッチエクスポートまたはPull Request作成を行う。

### 5.4 日本市場への適合（法規制・ガイドライン・企業運用要件）

日本国内のエンタープライズ企業や重要インフラ事業者・製造業・SIerへ導入するためには、欧米のSaaS専業製品が見落としがちな以下の要件を初期設計から組み込む必要がある。
- **経済産業省SBOM手引書およびIPA基準への準拠**：経済産業省が公表している「[ソフトウェア管理に向けたSBOMの導入に関する手引 Ver2.0](https://www.google.com/search?q=https%3A%2F%2Fwww.meti.go.jp%2Fpress%2F2024%2F08%2F20240829001%2F20240829001.html)」では、SBOM作成・脆弱性管理・取引先間の連携における最小要素や運用フロー（PSIRT/CSIRT連携、VEXによる影響有無の伝達）が整理されている。また、独立行政法人情報処理推進機構（IPA）の「[情報セキュリティ10大脅威 2026](https://www.google.com/search?q=https%3A%2F%2Fwww.ipa.go.jp%2Fsecurity%2F10threats%2F10threats2026.html)」および「[脆弱性対策情報](https://www.google.com/search?q=https%3A%2F%2Fwww.ipa.go.jp%2Fsecurity%2Fvuln%2Findex.html)」では、サプライチェーンの弱点を悪用した攻撃や脆弱性対策情報の公開に伴う悪用増加、AIの利用をめぐるサイバーリスクが重要脅威として挙げられている。本プラットフォームは、経産省手引書で推奨されるCycloneDX/SPDX形式でのSBOM入出力と、JVN iPedia / CWE日本語名称に対応した日本語レポート出力を備える。
- **オンプレミス・セルフホスト・閉域網（Air-Gapped）動作とプロキシ対応**：日本の金融・公共・製造業ではソースコードを外部クラウド（および外部LLM API）へ送信できない規定を持つ組織が多い。したがって、Docker ComposeまたはKubernetes（Helm）により単一企業内のオンプレミス/プライベートクラウドで完全セルフホストでき、HTTP/HTTPSプロキシ経由での脆弱性DB同期や、外部通信を一切遮断した状態でのオフラインDBバンドル更新、および社内ホスト型LLM（Ollama / vLLM / Azure OpenAI閉域エンドポイント）への切り替えを設定変更のみで実現する。
- **日本企業の組織構造・稟議・監査ワークフローへの適合**：「検出 → トリアージ → 担当者割当 → 修正または例外申請（リスク受容・一時緩和策の登録） → 上長/セキュリティ管理者による承認 → 再スキャン確認 → クローズ」という状態遷移に厳格なRBACと変更理由の必須入力、および改ざん検知可能な監査証跡（Audit Log）を紐付け、監査法人や親会社・委託元へ提出可能な証跡レポートを出力できるようにする。

### 5.5 差別化機能の優先順位評価マトリクス（8観点評価）

最初からすべての機能を巨大モノリスとして同時開発するのではなく、以下の8観点評価に基づきフェーズ分けを行う。

| 機能領域 | ユーザー価値 | 既存製品との差別化 | 実装コスト | 性能上の利点 | セキュリティ上の重要性 | 既存ツール活用度 | 少人数での実現可能性 | 維持管理の難しさ | 導入フェーズ判定 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1. 隔離サンドボックスでの主要OSSスキャナー統合（Trivy / Semgrep / Gitleaks）とSARIF/CycloneDX正規化 | 極大 | 中（基盤機能） | 中 | 高（C#高速ストリーム解析） | 極大（RCE・汚染防止） | 高（OSS活用） | 高 | 低〜中 | **Phase 1（MVP必須）** |
| 2. 行番号ズレ耐性を持つ2段階重複排除とクロススキャナー証拠統合 | 極大 | 高（DefectDojoの弱点克服） | 中 | 高（重複レコード爆発防止） | 高（トリアージ消失防止） | 中（独自ハッシュ実装） | 高 | 低 | **Phase 1（MVP必須）** |
| 3. 根拠明示型の決定論的リスク評価（CVSS + EPSS + KEV + 資産重要度） | 大 | 高（ブラックボックス排除） | 低〜中 | 高（事前計算・インデックス検索） | 高（優先順位の正確性） | 高（公開フィード連携） | 高 | 低 | **Phase 1〜2** |
| 4. SBOM永続化（Syft/Trivy）とファイル再走査なしの高速脆弱性再照合 | 大 | 高（秒単位の再評価） | 中 | 極大（I/O・クローン削減） | 高（ゼロデイ公開時の即応） | 高（CycloneDX / OSV） | 高 | 中 | **Phase 2** |
| 5. AI調査・Unified Diff修正案生成＋サンドボックス再スキャン検証＋人間承認 | 極大 | 極大（検証済みパッチ提示） | 中〜高 | 中（オンデマンド非同期実行） | 極大（Prompt Injection防御必須） | 高（LLM API / ローカルLLM） | 高 | 中 | **Phase 2〜3** |
| 6. 日本語UI・経産省SBOM手引書対応エクスポート・リスク受容承認ワークフロー | 大 | 高（日本企業特化） | 低〜中 | 影響なし | 高（監査・統制） | 中 | 高 | 低 | **Phase 2〜3** |
| 7. フルスクラッチのファイル横断コールグラフ到達可能性解析エンジン自作 | 中〜大 | 中（Snyk/Endorが先行） | 極大（言語ごとに膨大） | 低（解析負荷が極めて高い） | 中 | 低（OSSでは限定的） | **低（少人数では非現実的）** | **極めて高い** | **初期スコープ外（OSV-Scanner等の機能連携とSAST×SCA相関で代替）** |

## 6. 未解決の課題と実測検証が必要な仮説

公開情報の調査のみでは断定できず、後続の開発エージェントが実装・ベンチマークフェーズで実測検証すべき仮説は以下のとおりである。
1. **PostgreSQL RLSと複合インデックス・パーティショニングの実効レイテンシ**：100万件〜1,000万件のFindingレコードに対し、`FORCE ROW LEVEL SECURITY` と `current_setting('app.current_tenant_id')::uuid` ポリシーを適用した状態で、複数条件フィルタ＋Keysetページネーションが目標のp95 < 150msを維持できるか。PostgreSQLのクエリプランナがRLS述語をインデックススキャンに正しくプッシュダウンするかを `EXPLAIN (ANALYZE, BUFFERS)` で実測検証する必要がある。
2. **Windows開発環境（Docker Desktop / WSL2）とLinux本番環境におけるサンドボックス隔離オーバーヘッドの差**：Windowsローカル開発環境とLinuxコンテナ環境の間で、ボリュームマウントやプロセス起動時のI/O性能差がどの程度生じるか。抽象化された `ISandboxExecutionProvider` により環境別の実行時間と隔離強度を実測する必要がある。
3. **行番号ズレ耐性ハッシュ（トークン正規化スニペット）の衝突率と追跡精度**：同一ファイル内に酷似した複数の脆弱コードブロックが存在する場合に、行番号を完全に除外すると誤って同一Findingにマージされるリスクがある。そのため、「関数/メソッド名（ASTまたは正規表現によるEnclosing Symbol）＋CWE＋正規化トークンハッシュ＋同一ファイル内での相対出現順序」の組み合わせをテストスイートで検証する必要がある。

## 7. 参照文献・出典一覧

- [OWASP DefectDojo GitHub Repository (DefectDojo/django-DefectDojo)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fdefectdojo%2Fdjango-defectdojo)
- [OWASP DefectDojo Documentation - About Deduplication](https://www.google.com/search?q=https%3A%2F%2Fdocs.defectdojo.com%2Ftriage_findings%2Ffinding_deduplication%2Fabout_deduplication%2F)
- [OWASP Dependency-Track GitHub Repository (DependencyTrack/dependency-track)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FDependencyTrack%2Fdependency-track)
- [OWASP Dependency-Track Hyades API Server (DependencyTrack/hyades-apiserver)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FDependencyTrack%2Fhyades-apiserver)
- [Aqua Security Trivy GitHub Repository (aquasecurity/trivy)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Faquasecurity%2Ftrivy)
- [Google OSV-Scanner GitHub Repository (google/osv-scanner)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgoogle%2Fosv-scanner)
- [Semgrep GitHub Repository (semgrep/semgrep)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsemgrep%2Fsemgrep)
- [Gitleaks GitHub Repository (gitleaks/gitleaks)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fgitleaks%2Fgitleaks)
- [Anchore Syft GitHub Repository (anchore/syft)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fsyft)
- [Anchore Grype GitHub Repository (anchore/grype)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fanchore%2Fgrype)
- [OpenSSF Scorecard GitHub Repository (ossf/scorecard)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fossf%2Fscorecard)
- [GitHub Advanced Security Overview](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsecurity%2Fadvanced-security)
- [GitHub Docs - Resolving code scanning alerts with GitHub Copilot Autofix](https://www.google.com/search?q=https%3A%2F%2Fdocs.github.com%2Fen%2Fcode-security%2Fhow-tos%2Fmanage-security-alerts%2Fmanage-code-scanning-alerts%2Fresolve-alerts)
- [GitHub Docs - About security campaigns](https://www.google.com/search?q=https%3A%2F%2Fdocs.github.com%2Fen%2Fcode-security%2Fconcepts%2Fsecurity-at-scale%2Fabout-security-campaigns)
- [Snyk Platform - DeepCode AI](https://www.google.com/search?q=https%3A%2F%2Fsnyk.io%2Fplatform%2Fdeepcode-ai%2F)
- [Snyk User Docs - Reachability analysis](https://www.google.com/search?q=https%3A%2F%2Fdocs.snyk.io%2Fscan-fix-and-prevent%2Ffix%2Fprioritize-issues-for-fixing%2Freachability-analysis)
- [Wiz Code Platform Overview](https://www.google.com/search?q=https%3A%2F%2Fwww.wiz.io%2Fplatform%2Fwiz-code)
- [Wiz Security Graph Overview](https://www.google.com/search?q=https%3A%2F%2Fwww.wiz.io%2Flp%2Fwiz-security-graph)
- [GitLab Docs - GitLab Advanced SAST \& GitLab Duo Vulnerability Resolution](https://www.google.com/search?q=https%3A%2F%2Fdocs.gitlab.com%2Fuser%2Fapplication_security%2Fsast%2Fgitlab_advanced_sast%2F)
- [Endor Labs Documentation - Reachability Analysis \& Phantom Dependencies](https://www.google.com/search?q=https%3A%2F%2Fdocs.endorlabs.com%2Fscan%2Fsca%2Freachability-analysis)
- [OASIS Standard - Static Analysis Results Interchange Format (SARIF) Version 2.1.0](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fsarif%2Fsarif%2Fv2.1.0%2Fsarif-v2.1.0.html)
- [OWASP CycloneDX Specification Overview](https://www.google.com/search?q=https%3A%2F%2Fcyclonedx.org%2Fspecification%2Foverview%2F)
- [OpenVEX Specification Repository (openvex/spec)](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fopenvex%2Fspec)
- [OASIS Common Security Advisory Framework (CSAF) v2.0 Standard](https://www.google.com/search?q=https%3A%2F%2Fdocs.oasis-open.org%2Fcsaf%2Fcsaf%2Fv2.0%2Fos%2Fcsaf-v2.0-os.html)
- [FIRST.org - Common Vulnerability Scoring System (CVSS) v4.0 Specification](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fcvss%2Fv4.0%2Fspecification-document)
- [FIRST.org - Exploit Prediction Scoring System (EPSS)](https://www.google.com/search?q=https%3A%2F%2Fwww.first.org%2Fepss%2F)
- [CISA - Known Exploited Vulnerabilities (KEV) Catalog](https://www.google.com/search?q=https%3A%2F%2Fwww.cisa.gov%2Fknown-exploited-vulnerabilities-catalog)
- [Microsoft Learn - Kestrel web server in ASP.NET Core](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Faspnet%2Fcore%2Ffundamentals%2Fservers%2Fkestrel%3Fview%3Daspnetcore-10.0)
- [TechEmpower Web Framework Benchmarks (Round 23)](https://www.google.com/search?q=https%3A%2F%2Fwww.techempower.com%2Fbenchmarks%2F)
- [経済産業省 - 「ソフトウェア管理に向けたSBOMの導入に関する手引 Ver2.0」の策定・公表](https://www.google.com/search?q=https%3A%2F%2Fwww.meti.go.jp%2Fpress%2F2024%2F08%2F20240829001%2F20240829001.html)
- [独立行政法人情報処理推進機構（IPA） - 情報セキュリティ10大脅威 2026](https://www.google.com/search?q=https%3A%2F%2Fwww.ipa.go.jp%2Fsecurity%2F10threats%2F10threats2026.html)
- [独立行政法人情報処理推進機構（IPA） - 脆弱性対策情報](https://www.google.com/search?q=https%3A%2F%2Fwww.ipa.go.jp%2Fsecurity%2Fvuln%2Findex.html)
