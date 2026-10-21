'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  Flame,
  Shield,
  Activity,
  ArrowUpRight,
  TrendingUp,
  RefreshCw,
  FolderGit2,
  CheckCircle2,
  ExternalLink,
  Layers
} from 'lucide-react';
import { api } from '@/lib/api';
import { DashboardSummaryDto } from '@/lib/types';

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummaryDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err: any) {
      console.error('Failed to load dashboard summary', err);
      setError(err.message || 'ダッシュボード情報の取得に失敗しました');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  return (
    <div className="space-y-8">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span>統合セキュリティダッシュボード</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            脆弱性リスクスコア・CISA KEV脅威情報・重要度別Findingの全体サマリー
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchSummary}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800 transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            再取得
          </button>
          <Link
            href="/projects"
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
          >
            <FolderGit2 className="h-3.5 w-3.5" />
            スキャン起動
          </Link>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Findings */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">検出脆弱性 総数</span>
            <span className="rounded-md bg-slate-800 p-1.5 text-slate-300">
              <Shield className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">
              {loading ? '-' : summary?.totalFindings ?? 0}
            </span>
            <span className="text-xs text-slate-400">件</span>
          </div>
          <div className="mt-3 text-xs text-slate-400 flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-full bg-emerald-400"></span>
            プロジェクト数: {summary?.totalProjects ?? 0} 件
          </div>
        </div>

        {/* CISA KEV Exploit Alerts */}
        <div className="rounded-xl border border-rose-900/50 bg-gradient-to-br from-rose-950/40 to-slate-900/60 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-rose-300">CISA KEV 悪用確認済み</span>
            <span className="rounded-md bg-rose-500/20 p-1.5 text-rose-400 animate-pulse">
              <Flame className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-rose-400 tracking-tight">
              {loading ? '-' : summary?.kevCount ?? 0}
            </span>
            <span className="text-xs text-rose-300/80">件の即時対応脅威</span>
          </div>
          <div className="mt-3 text-xs text-rose-300/70">
            野外悪用が確認された優先パッチ対象
          </div>
        </div>

        {/* Average Risk Score */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">平均リスクスコア</span>
            <span className="rounded-md bg-slate-800 p-1.5 text-amber-400">
              <TrendingUp className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">
              {loading ? '-' : summary?.averageRiskScore ?? 0}
            </span>
            <span className="text-xs text-slate-400">/ 100.0</span>
          </div>
          <div className="mt-3 w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className="bg-amber-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.min(summary?.averageRiskScore ?? 0, 100)}%` }}
            />
          </div>
        </div>

        {/* Active Scans */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">稼働中スキャン</span>
            <span className="rounded-md bg-slate-800 p-1.5 text-emerald-400">
              <Activity className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">
              {loading ? '-' : summary?.activeScansCount ?? 0}
            </span>
            <span className="text-xs text-slate-400">ジョブ進行中</span>
          </div>
          <div className="mt-3 text-xs text-emerald-400 flex items-center gap-1.5">
            <CheckCircle2 className="h-3 w-3" />
            PostgreSQL ワーカー稼働中
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
        <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <Layers className="h-4 w-4 text-slate-400" />
          <span>重要度別内訳 (Severity Breakdown)</span>
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3">
            <div className="text-xs font-semibold text-rose-400">CRITICAL</div>
            <div className="text-2xl font-bold text-white mt-1">{summary?.criticalCount ?? 0}</div>
          </div>
          <div className="rounded-lg border border-orange-500/30 bg-orange-500/10 p-3">
            <div className="text-xs font-semibold text-orange-400">HIGH</div>
            <div className="text-2xl font-bold text-white mt-1">{summary?.highCount ?? 0}</div>
          </div>
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
            <div className="text-xs font-semibold text-amber-400">MEDIUM</div>
            <div className="text-2xl font-bold text-white mt-1">{summary?.mediumCount ?? 0}</div>
          </div>
          <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3">
            <div className="text-xs font-semibold text-blue-400">LOW</div>
            <div className="text-2xl font-bold text-white mt-1">{summary?.lowCount ?? 0}</div>
          </div>
          <div className="rounded-lg border border-slate-700 bg-slate-800/40 p-3 col-span-2 sm:col-span-1">
            <div className="text-xs font-semibold text-slate-400">INFO</div>
            <div className="text-2xl font-bold text-white mt-1">{summary?.infoCount ?? 0}</div>
          </div>
        </div>
      </div>

      {/* Priority Action Items: Top Risk Findings */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">優先対応上位リスク脆弱性 (Top Priority Findings)</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              CVSS、EPSS、CISA KEV、到達可能性、アセット重要度を複合したリスクスコア降順
            </p>
          </div>
          <Link
            href="/findings"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 hover:text-emerald-300 transition"
          >
            <span>全件トリアージ一覧</span>
            <ArrowUpRight className="h-4 w-4" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">リスクスコア</th>
                <th className="py-3 px-4">重要度</th>
                <th className="py-3 px-4">脆弱性 / ルール</th>
                <th className="py-3 px-4">根拠バッジ (Rationale)</th>
                <th className="py-3 px-4">スキャナー</th>
                <th className="py-3 px-4">対象ファイル・位置</th>
                <th className="py-3 px-4 text-right">アクション</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto text-emerald-400 mb-2" />
                    データを読み込み中...
                  </td>
                </tr>
              ) : summary?.topRiskFindings && summary.topRiskFindings.length > 0 ? (
                summary.topRiskFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4 font-bold text-white">
                      <span className="inline-flex items-center gap-1.5 rounded-md bg-slate-800 px-2 py-1 text-sm font-bold text-amber-400 border border-slate-700">
                        {f.riskScore.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-bold ${
                          f.severity === 'Critical'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : f.severity === 'High'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : f.severity === 'Medium'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-semibold text-white truncate">{f.title}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        {f.cveId || f.ruleId || 'N/A'}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1.5">
                        {f.isKev && (
                          <span className="inline-flex items-center gap-1 rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-bold text-rose-300 border border-rose-500/40 animate-pulse">
                            <Flame className="h-2.5 w-2.5" />
                            CISA KEV
                          </span>
                        )}
                        {f.epssScore !== undefined && f.epssScore !== null && (
                          <span className="inline-flex items-center rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] font-medium text-purple-300 border border-purple-500/30">
                            EPSS: {(f.epssScore * 100).toFixed(1)}%
                          </span>
                        )}
                        <span className="inline-flex items-center rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-300 border border-slate-700">
                          {f.reachability}
                        </span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {f.scannerName}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px] max-w-xs truncate">
                      {f.filePath ? (
                        <span>
                          {f.filePath}:{f.startLine ?? 1}
                        </span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        href={`/findings/${f.id}`}
                        className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 hover:text-white transition"
                      >
                        <span>詳細</span>
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    脆弱性は検出されていません。プロジェクトからスキャンを実行してください。
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
