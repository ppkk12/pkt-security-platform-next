'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Search,
  Filter,
  Flame,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  SlidersHorizontal,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  AlertCircle,
  Clock,
  Edit3
} from 'lucide-react';
import { api } from '@/lib/api';
import { FindingSummaryDto, FindingSeverity, FindingStatus, PagedResult } from '@/lib/types';

function FindingsContent() {
  const searchParams = useSearchParams();
  const initialProjectId = searchParams.get('projectId') || '';

  const [findings, setFindings] = useState<FindingSummaryDto[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [cursorHistory, setCursorHistory] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [projectId, setProjectId] = useState(initialProjectId);
  const [severity, setSeverity] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const [isKev, setIsKev] = useState<boolean | undefined>(undefined);
  const [keyword, setKeyword] = useState<string>('');

  // Triage Modal
  const [triageFinding, setTriageFinding] = useState<FindingSummaryDto | null>(null);
  const [newStatus, setNewStatus] = useState<FindingStatus>('RiskAccepted');
  const [triageReason, setTriageReason] = useState('');
  const [triaging, setTriaging] = useState(false);

  const fetchFindings = async (cursor?: string) => {
    setLoading(true);
    setError(null);
    try {
      const res: PagedResult<FindingSummaryDto> = await api.searchFindings({
        projectId: projectId || undefined,
        severity: severity || undefined,
        status: status || undefined,
        isKev: isKev,
        keyword: keyword || undefined,
        cursor: cursor,
        limit: 50,
      });

      setFindings(res.items);
      setTotalCount(res.totalCount);
      setNextCursor(res.nextCursor);
    } catch (err: any) {
      console.error(err);
      setError(err.message || '脆弱性一覧の取得に失敗しました');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setCursorHistory([]);
    fetchFindings();
  }, [projectId, severity, status, isKev]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCursorHistory([]);
    fetchFindings();
  };

  const handleNextPage = () => {
    if (nextCursor) {
      setCursorHistory((prev) => [...prev, nextCursor]);
      fetchFindings(nextCursor);
    }
  };

  const handlePrevPage = () => {
    if (cursorHistory.length > 0) {
      const newHistory = [...cursorHistory];
      newHistory.pop(); // remove current
      const prev = newHistory[newHistory.length - 1];
      setCursorHistory(newHistory);
      fetchFindings(prev);
    }
  };

  const handleTriageSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!triageFinding) return;
    if (!triageReason.trim()) {
      alert('トリアージステータス変更理由の入力は必須です（監査要件）');
      return;
    }

    setTriaging(true);
    try {
      await api.updateFindingStatus(triageFinding.id, newStatus, triageReason);
      setTriageFinding(null);
      setTriageReason('');
      fetchFindings();
    } catch (err: any) {
      alert(`トリアージ更新に失敗しました: ${err.message}`);
    } finally {
      setTriaging(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Search className="h-6 w-6 text-emerald-400" />
            <span>高速Finding検索・トリアージ</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Keysetページネーションによるミリ秒一覧遷移・複合条件フィルタ・トリアージ監査記録
          </p>
        </div>

        <button
          onClick={() => fetchFindings()}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800 transition self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
          再検索
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          {/* Keyword Search */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              placeholder="タイトル、CVE-ID (CVE-2023-xxxx)、CWE、ファイルパス等で検索..."
              className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
          >
            <option value="">重要度: すべて</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>

          {/* Status Filter */}
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
          >
            <option value="">ステータス: すべて</option>
            <option value="Open">Open (未対応)</option>
            <option value="Triaged">Triaged (確認済)</option>
            <option value="RiskAccepted">RiskAccepted (リスク受容)</option>
            <option value="FalsePositive">FalsePositive (誤検知)</option>
            <option value="Remediated">Remediated (修正完了)</option>
          </select>

          {/* CISA KEV Filter Button */}
          <button
            type="button"
            onClick={() => setIsKev(isKev === true ? undefined : true)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold transition ${
              isKev === true
                ? 'border-rose-500/60 bg-rose-500/20 text-rose-300'
                : 'border-slate-700 bg-slate-950 text-slate-400 hover:text-white'
            }`}
          >
            <Flame className="h-3.5 w-3.5 text-rose-400" />
            <span>CISA KEV のみ</span>
          </button>

          <button
            type="submit"
            className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
          >
            検索適用
          </button>
        </form>

        <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
          <div>
            該当件数: <span className="font-bold text-white">{totalCount}</span> 件
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-500">Keyset Cursor Indexed</span>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">リスク</th>
                <th className="py-3 px-4">重要度</th>
                <th className="py-3 px-4">ステータス</th>
                <th className="py-3 px-4">脆弱性 / CVE</th>
                <th className="py-3 px-4">脅威根拠</th>
                <th className="py-3 px-4">スキャナー</th>
                <th className="py-3 px-4">ファイル位置</th>
                <th className="py-3 px-4">出現回数</th>
                <th className="py-3 px-4 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-16 text-center text-slate-500">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto text-emerald-400 mb-2" />
                    高速インデックス走査中...
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-16 text-center text-slate-500">
                    条件に一致する脆弱性は見つかりませんでした。
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4 font-bold text-white">
                      <span className="inline-flex items-center rounded-md bg-slate-800 px-2 py-0.5 text-xs font-bold text-amber-400 border border-slate-700">
                        {f.riskScore.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold ${
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
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-semibold ${
                          f.status === 'Open'
                            ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                            : f.status === 'Remediated'
                            ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                            : f.status === 'RiskAccepted'
                            ? 'bg-amber-950/60 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}
                      >
                        {f.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-semibold text-white truncate">{f.title}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        {f.cveId || f.cweId || 'N/A'}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {f.isKev && (
                          <span className="inline-flex items-center gap-1 rounded bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-bold text-rose-300 border border-rose-500/40 animate-pulse">
                            <Flame className="h-2 w-2" />
                            KEV
                          </span>
                        )}
                        {f.epssScore !== undefined && f.epssScore !== null && (
                          <span className="inline-flex items-center rounded bg-purple-500/20 px-1 py-0.5 text-[9px] font-mono text-purple-300 border border-purple-500/30">
                            {(f.epssScore * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {f.scannerName}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px] max-w-xs truncate">
                      {f.filePath ? `${f.filePath}:${f.startLine ?? 1}` : '-'}
                    </td>
                    <td className="py-3.5 px-4 text-center font-mono text-slate-400">
                      {f.occurrenceCount}回
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => {
                            setTriageFinding(f);
                            setNewStatus(f.status);
                            setTriageReason('');
                          }}
                          title="トリアージ状態の変更"
                          className="rounded-md border border-slate-700 bg-slate-800/80 p-1.5 text-slate-300 hover:text-white hover:bg-slate-700 transition"
                        >
                          <Edit3 className="h-3.5 w-3.5" />
                        </button>
                        <Link
                          href={`/findings/${f.id}`}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 hover:text-white transition"
                        >
                          <span>詳細</span>
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Keyset Pagination Bar */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            表示件数: {findings.length} 件 / 総件数: {totalCount} 件
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrevPage}
              disabled={cursorHistory.length === 0 || loading}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
              前へ
            </button>
            <button
              onClick={handleNextPage}
              disabled={!nextCursor || loading}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              次へ
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Triage Status Change Modal */}
      {triageFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-1">トリアージステータス変更</h2>
            <p className="text-xs text-slate-400 mb-4 line-clamp-1">{triageFinding.title}</p>

            <form onSubmit={handleTriageSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">新規ステータス</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as FindingStatus)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none cursor-pointer"
                >
                  <option value="Open">Open (未対応)</option>
                  <option value="Triaged">Triaged (調査確認中)</option>
                  <option value="RiskAccepted">RiskAccepted (リスク受容 - 管理者承認要件)</option>
                  <option value="FalsePositive">FalsePositive (誤検知)</option>
                  <option value="Remediated">Remediated (修正完了)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  変更理由・監査根拠 (必須入力) *
                </label>
                <textarea
                  required
                  rows={3}
                  value={triageReason}
                  onChange={(e) => setTriageReason(e.target.value)}
                  placeholder="例: 社内ネットワーク限定かつWAFによる入力検証が配備されているためリスク受容。"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="mt-6 flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setTriageFinding(null)}
                  className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
                >
                  キャンセル
                </button>
                <button
                  type="submit"
                  disabled={triaging}
                  className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
                >
                  {triaging ? '保存中...' : '確定・監査記録'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default function FindingsPage() {
  return (
    <React.Suspense fallback={<div className="py-20 text-center text-slate-500">脆弱性一覧を読み込み中...</div>}>
      <FindingsContent />
    </React.Suspense>
  );
}
