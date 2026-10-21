'use client';

import React, { useEffect, useState } from 'react';
import {
  FileSpreadsheet,
  Download,
  RefreshCw,
  Plus,
  ShieldCheck,
  AlertTriangle,
  Layers,
  FileCheck,
  Package,
  CheckCircle2,
  ExternalLink,
  BookOpen
} from 'lucide-react';
import { api } from '@/lib/api';
import { Project, ProjectDependencyDto, VexStatementDto, SbomRescanResultDto } from '@/lib/types';

export default function SbomPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [dependencies, setDependencies] = useState<ProjectDependencyDto[]>([]);
  const [vexStatements, setVexStatements] = useState<VexStatementDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fast SBOM Rescan State
  const [rescanning, setRescanning] = useState(false);
  const [rescanResult, setRescanResult] = useState<SbomRescanResultDto | null>(null);

  // OpenVEX Register Modal
  const [isVexOpen, setIsVexOpen] = useState(false);
  const [vulnId, setVulnId] = useState('');
  const [packagePurl, setPackagePurl] = useState('');
  const [vexStatus, setVexStatus] = useState('not_affected');
  const [justification, setJustification] = useState('inline_mitigations_already_exist');
  const [impactStatement, setImpactStatement] = useState('');
  const [registeringVex, setRegisteringVex] = useState(false);

  // Load initial projects
  useEffect(() => {
    api.getProjects()
      .then((projs) => {
        setProjects(projs);
        if (projs.length > 0) {
          setSelectedProjectId(projs[0].id);
        }
      })
      .catch((err) => {
        setError(err.message || 'プロジェクトの取得に失敗しました');
      })
      .finally(() => setLoading(false));
  }, []);

  // Fetch dependencies and VEX when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    loadProjectSbomData(selectedProjectId);
  }, [selectedProjectId]);

  const loadProjectSbomData = async (projId: string) => {
    setLoading(true);
    setError(null);
    try {
      const [deps, vex] = await Promise.all([
        api.getProjectDependencies(projId),
        api.getVexStatements(projId),
      ]);
      setDependencies(deps);
      setVexStatements(vex);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'SBOMデータの読み込みに失敗しました');
    } finally {
      setLoading(false);
    }
  };

  const handleFastRescan = async () => {
    if (!selectedProjectId) return;
    setRescanning(true);
    setRescanResult(null);
    try {
      const result = await api.rescanSbom(selectedProjectId);
      setRescanResult(result);
      loadProjectSbomData(selectedProjectId);
    } catch (err: any) {
      alert(`高速再スキャン失敗: ${err.message}`);
    } finally {
      setRescanning(false);
    }
  };

  const handleRegisterVex = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId) return;
    setRegisteringVex(true);
    try {
      await api.registerVexStatement(selectedProjectId, {
        vulnerabilityId: vulnId,
        packagePurl: packagePurl || undefined,
        status: vexStatus,
        justification,
        impactStatement,
      });
      setIsVexOpen(false);
      setVulnId('');
      setPackagePurl('');
      setImpactStatement('');
      loadProjectSbomData(selectedProjectId);
    } catch (err: any) {
      alert(`OpenVEX登録失敗: ${err.message}`);
    } finally {
      setRegisteringVex(false);
    }
  };

  const handleDownload = async (format: 'sarif' | 'cyclonedx' | 'meti' | 'csv' | 'json') => {
    if (!selectedProjectId) return;
    try {
      const blob = await api.downloadExport(selectedProjectId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'cyclonedx' ? 'cyclonedx.json' : format === 'meti' ? 'meti_audit_report.json' : format;
      a.download = `project_${selectedProjectId}_export.${ext}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      alert(`エクスポートのダウンロードに失敗しました: ${err.message}`);
    }
  };

  const selectedProj = projects.find((p) => p.id === selectedProjectId);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileSpreadsheet className="h-6 w-6 text-emerald-400" />
            <span>SBOM・OpenVEX・日本語監査レポート出力</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            経済産業省「ソフトウェア管理に向けたSBOMの導入に関する手引書」準拠の監査証跡管理
          </p>
        </div>

        {/* Project Selector */}
        <div className="flex items-center gap-3">
          <label className="text-xs text-slate-400">対象プロジェクト:</label>
          <select
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-semibold text-white focus:border-emerald-500 focus:outline-none cursor-pointer"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Action Banner: Fast SBOM Rescan & METI Export */}
      <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900/80 to-slate-950 p-6 flex flex-col md:flex-row md:items-center md:justify-between gap-6 shadow-sm">
        <div className="space-y-1">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-cyan-400" />
            <span>経産省SBOM手引書準拠 監査レポート生成 & 高速再照合</span>
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            ソースコードの物理再走査をスキップし、登録済みSBOMパッケージ群と最新脆弱性DB・OpenVEX除外ステートメントをミリ秒単位で高速再照合します。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleFastRescan}
            disabled={rescanning || !selectedProjectId}
            className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/20 transition shadow-sm"
          >
            <RefreshCw className={`h-4 w-4 ${rescanning ? 'animate-spin' : ''}`} />
            {rescanning ? '高速再スキャン中...' : 'ファイル再走査なし高速再スキャン'}
          </button>

          <button
            onClick={() => setIsVexOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-700 transition border border-slate-700 shadow-sm"
          >
            <Plus className="h-4 w-4" />
            OpenVEX 登録
          </button>
        </div>
      </div>

      {/* Fast Rescan Result Banner */}
      {rescanResult && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-300 flex items-center justify-between animate-fadeIn">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="h-5 w-5 text-emerald-400 flex-shrink-0" />
            <span>
              <strong>高速再スキャン完了 ({rescanResult.durationMs}ms):</strong> 依存パッケージ {rescanResult.dependenciesCount} 件を照合し、
              脆弱性 {rescanResult.vulnerabilitiesFoundCount} 件を検出、OpenVEXにより {rescanResult.suppressedByVexCount} 件を自動除外（未影響）判定しました。
            </span>
          </div>
        </div>
      )}

      {/* Export Buttons Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* METI Japanese Audit Report */}
        <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-br from-cyan-950/20 to-slate-900/60 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">経済産業省手引書準拠</span>
              <FileCheck className="h-5 w-5 text-cyan-400" />
            </div>
            <h3 className="font-bold text-white text-sm mt-2">日本語監査報告書 (METI Audit Report)</h3>
            <p className="text-xs text-slate-400 mt-1">
              ソフトウェア識別、SBOM構成要素、CVE評価、OpenVEX影響有無判定、監査適合サマリー。
            </p>
          </div>
          <button
            onClick={() => handleDownload('meti')}
            className="mt-4 w-full inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-3 py-2 text-xs font-semibold text-white hover:bg-cyan-500 transition shadow-sm"
          >
            <Download className="h-4 w-4" />
            経産省監査レポート出力 (JSON)
          </button>
        </div>

        {/* CycloneDX 1.5 Export */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">業界標準仕様</span>
              <Layers className="h-5 w-5 text-emerald-400" />
            </div>
            <h3 className="font-bold text-white text-sm mt-2">CycloneDX 1.5 SBOM</h3>
            <p className="text-xs text-slate-400 mt-1">
              OWASP標準フォーマット。全依存パッケージPURL、バージョン、ライセンス、脆弱性を含む。
            </p>
          </div>
          <button
            onClick={() => handleDownload('cyclonedx')}
            className="mt-4 w-full inline-flex items-center justify-center gap-2 rounded-lg bg-slate-800 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-700 transition border border-slate-700 shadow-sm"
          >
            <Download className="h-4 w-4" />
            CycloneDX 1.5 出力
          </button>
        </div>

        {/* SARIF 2.1.0 Export */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">OASIS標準</span>
              <FileSpreadsheet className="h-5 w-5 text-amber-400" />
            </div>
            <h3 className="font-bold text-white text-sm mt-2">SARIF 2.1.0 レポート</h3>
            <p className="text-xs text-slate-400 mt-1">
              GitHub Advanced Security や各種CIツールにインポート可能な静的解析結果標準。
            </p>
          </div>
          <button
            onClick={() => handleDownload('sarif')}
            className="mt-4 w-full inline-flex items-center justify-center gap-2 rounded-lg bg-slate-800 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-700 transition border border-slate-700 shadow-sm"
          >
            <Download className="h-4 w-4" />
            SARIF 2.1.0 出力
          </button>
        </div>
      </div>

      {/* Package Dependencies Inventory Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">構成パッケージ一覧 (Package Dependencies Inventory)</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              プロジェクト内で検出・管理されている全ライブラリとパッケージPURL
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {dependencies.length} 件登録済み
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">パッケージ名</th>
                <th className="py-3 px-4">バージョン</th>
                <th className="py-3 px-4">依存種別</th>
                <th className="py-3 px-4">Package URL (PURL)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono text-[11px]">
              {loading ? (
                <tr>
                  <td colSpan={4} className="py-12 text-center text-slate-500 font-sans">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto text-emerald-400 mb-2" />
                    SBOMデータを読み込み中...
                  </td>
                </tr>
              ) : dependencies.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-12 text-center text-slate-500 font-sans">
                    登録されているパッケージ依存情報はありません。スキャンを実行してください。
                  </td>
                </tr>
              ) : (
                dependencies.map((dep) => (
                  <tr key={dep.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-semibold text-white font-sans">
                      {dep.packageName}
                    </td>
                    <td className="py-3 px-4 text-emerald-400">
                      {dep.version}
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-semibold ${
                        dep.isDirect ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {dep.isDirect ? '直接依存' : '間接依存'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 truncate max-w-md">
                      {dep.packagePurl}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* OpenVEX Statements Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">登録済み OpenVEX ステートメント</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              脆弱性の影響有無（not_affected）と正当化理由を宣言し、不要な警告を抑止
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {vexStatements.length} 件有効
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">脆弱性ID (CVE)</th>
                <th className="py-3 px-4">ステータス</th>
                <th className="py-3 px-4">対象PURL</th>
                <th className="py-3 px-4">正当化理由 (Justification)</th>
                <th className="py-3 px-4">影響説明文</th>
                <th className="py-3 px-4">登録日時</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {vexStatements.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    登録されているOpenVEXステートメントはありません。
                  </td>
                </tr>
              ) : (
                vexStatements.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-bold text-rose-400">
                      {v.vulnerabilityId}
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center rounded-md bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300 border border-emerald-500/30">
                        {v.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px] truncate max-w-xs">
                      {v.packagePurl || 'プロジェクト全体'}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {v.justification || 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] max-w-xs truncate">
                      {v.impactStatement || 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-500 text-[11px]">
                      {new Date(v.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* OpenVEX Register Modal */}
      {isVexOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-1">OpenVEX ステートメント登録</h2>
            <p className="text-xs text-slate-400 mb-4">
              指定した脆弱性に対し、自社製品・システムにおいて影響がない理由（正当化）を宣言します。
            </p>

            <form onSubmit={handleRegisterVex} className="space-y-4 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1">脆弱性ID (CVE-ID) *</label>
                <input
                  type="text"
                  required
                  placeholder="例: CVE-2023-44487"
                  value={vulnId}
                  onChange={(e) => setVulnId(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white font-mono placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">対象パッケージPURL (任意、空欄で全対象)</label>
                <input
                  type="text"
                  placeholder="例: pkg:npm/axios@0.21.1"
                  value={packagePurl}
                  onChange={(e) => setPackagePurl(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white font-mono placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-slate-300 mb-1">VEX ステータス</label>
                  <select
                    value={vexStatus}
                    onChange={(e) => setVexStatus(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="not_affected">not_affected (影響を受けない)</option>
                    <option value="fixed">fixed (修正済み)</option>
                    <option value="under_investigation">under_investigation (調査中)</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-slate-300 mb-1">正当化理由 (Justification)</label>
                  <select
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="inline_mitigations_already_exist">inline_mitigations_already_exist (緩和策適用済)</option>
                    <option value="component_not_present">component_not_present (コンポーネント未使用)</option>
                    <option value="vulnerable_code_not_present">vulnerable_code_not_present (脆弱コード未包含)</option>
                    <option value="vulnerable_code_not_in_execute_path">vulnerable_code_not_in_execute_path (到達不能)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">影響説明文 (Impact Statement) *</label>
                <textarea
                  required
                  rows={2}
                  placeholder="例: HTTP/2 Rapid Reset 攻撃に対し、上位リバースプロキシで最大同時ストリーム数を100に制限しているため自社環境への影響はありません。"
                  value={impactStatement}
                  onChange={(e) => setImpactStatement(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsVexOpen(false)}
                  className="rounded-lg border border-slate-700 px-4 py-2 font-semibold text-slate-300 hover:bg-slate-800 transition"
                >
                  キャンセル
                </button>
                <button
                  type="submit"
                  disabled={registeringVex}
                  className="rounded-lg bg-emerald-600 px-4 py-2 font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
                >
                  {registeringVex ? '登録中...' : 'OpenVEX 登録確定'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
