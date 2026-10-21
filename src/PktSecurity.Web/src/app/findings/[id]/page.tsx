'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ArrowLeft,
  ShieldAlert,
  Flame,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Sparkles,
  Play,
  Check,
  X,
  FileCode,
  Layers,
  Activity,
  History,
  Lock,
  RefreshCw,
  GitCompare,
  Info
} from 'lucide-react';
import { api } from '@/lib/api';
import { FindingDetailDto, RemediationDto, RemediationVerificationResultDto, FindingStatus } from '@/lib/types';

export default function FindingDetailPage() {
  const params = useParams();
  const findingId = params.id as string;

  const [finding, setFinding] = useState<FindingDetailDto | null>(null);
  const [remediation, setRemediation] = useState<RemediationDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // AI & Remediation Action states
  const [generatingAi, setGeneratingAi] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<RemediationVerificationResultDto | null>(null);
  const [approving, setApproving] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [approvalReason, setApprovalReason] = useState('');
  const [isApproveOpen, setIsApproveOpen] = useState(false);
  const [isRejectOpen, setIsRejectOpen] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const f = await api.getFinding(findingId);
      setFinding(f);

      // Check if remediation already exists
      try {
        const r = await api.getRemediation(findingId);
        setRemediation(r);
      } catch {
        // No remediation generated yet, which is normal
      }
    } catch (err: any) {
      console.error(err);
      setError(err.message || '詳細情報の取得に失敗しました');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (findingId) {
      fetchData();
    }
  }, [findingId]);

  const handleGenerateRemediation = async () => {
    setGeneratingAi(true);
    setActionMessage(null);
    try {
      const r = await api.generateRemediation(findingId);
      setRemediation(r);
      setActionMessage('AI修正パッチ案を正常に生成しました。');
    } catch (err: any) {
      alert(`AI修正パッチ生成失敗: ${err.message}`);
    } finally {
      setGeneratingAi(false);
    }
  };

  const handleVerifySandbox = async () => {
    if (!remediation) return;
    setVerifying(true);
    setActionMessage(null);
    try {
      const res = await api.verifyRemediation(remediation.id);
      setVerifyResult(res);
      // Reload remediation state
      const updatedR = await api.getRemediation(findingId);
      setRemediation(updatedR);
      setActionMessage(`サンドボックス再スキャン完了: 結果=${res.verificationStatus} (${res.durationMs}ms)`);
    } catch (err: any) {
      alert(`サンドボックス検証失敗: ${err.message}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleApprove = async () => {
    if (!remediation) return;
    setApproving(true);
    try {
      const updatedR = await api.approveRemediation(remediation.id, approvalReason);
      setRemediation(updatedR);
      setIsApproveOpen(false);
      setApprovalReason('');
      setActionMessage('修正パッチを承認しました。FindingはRemediatedステータスへ自動遷移しました。');
      fetchData(); // refresh finding status
    } catch (err: any) {
      alert(`承認エラー: ${err.message}`);
    } finally {
      setApproving(false);
    }
  };

  const handleReject = async () => {
    if (!remediation) return;
    if (!approvalReason.trim()) {
      alert('却下理由を入力してください。');
      return;
    }
    setRejecting(true);
    try {
      const updatedR = await api.rejectRemediation(remediation.id, approvalReason);
      setRemediation(updatedR);
      setIsRejectOpen(false);
      setApprovalReason('');
      setActionMessage('修正パッチを却下しました。');
    } catch (err: any) {
      alert(`却下エラー: ${err.message}`);
    } finally {
      setRejecting(false);
    }
  };

  if (loading) {
    return (
      <div className="py-20 text-center text-slate-500">
        <RefreshCw className="h-6 w-6 animate-spin mx-auto text-emerald-400 mb-2" />
        Finding詳細と証拠データを読み込み中...
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-6 text-center text-rose-300 space-y-4">
        <AlertTriangle className="h-8 w-8 mx-auto text-rose-400" />
        <p>{error || '該当するFindingは見つかりませんでした'}</p>
        <Link href="/findings" className="inline-flex items-center gap-2 text-xs font-semibold text-white underline">
          <ArrowLeft className="h-3.5 w-3.5" />
          一覧へ戻る
        </Link>
      </div>
    );
  }

  const assessment = finding.latestRiskAssessment;
  const primaryEvidence = finding.evidences?.[0];

  return (
    <div className="space-y-8">
      {/* Back button & Action Toast */}
      <div className="flex items-center justify-between">
        <Link
          href="/findings"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-white transition"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>脆弱性一覧へ戻る</span>
        </Link>

        {actionMessage && (
          <div className="inline-flex items-center gap-2 rounded-lg bg-emerald-500/20 border border-emerald-500/40 px-3 py-1.5 text-xs text-emerald-300 animate-fadeIn">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            <span>{actionMessage}</span>
          </div>
        )}
      </div>

      {/* Main Header Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold ${
                  finding.severity === 'Critical'
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    : finding.severity === 'High'
                    ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                }`}
              >
                {finding.severity}
              </span>

              <span className="inline-flex items-center rounded-md bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-300 border border-slate-700">
                {finding.status}
              </span>

              {finding.isKev && (
                <span className="inline-flex items-center gap-1 rounded bg-rose-500/20 px-2 py-0.5 text-xs font-bold text-rose-300 border border-rose-500/40 animate-pulse">
                  <Flame className="h-3 w-3" />
                  CISA KEV 悪用確認済み
                </span>
              )}

              <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-400 border border-slate-700">
                {finding.scannerName}
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">{finding.title}</h1>
            <p className="text-xs text-slate-400 leading-relaxed">{finding.description}</p>
          </div>

          <div className="flex md:flex-col items-center md:items-end justify-between gap-2 border-t md:border-t-0 pt-3 md:pt-0 border-slate-800">
            <div className="text-right">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">総合リスクスコア</div>
              <div className="text-3xl font-extrabold text-amber-400">{finding.riskScore.toFixed(1)}</div>
            </div>
          </div>
        </div>

        {/* Location & Metadata info */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-4 border-t border-slate-800/80 text-xs text-slate-400">
          <div>
            <span className="text-slate-500 block mb-0.5">ファイル位置:</span>
            <span className="font-mono text-slate-200">
              {finding.filePath ? `${finding.filePath}:${finding.startLine ?? 1}` : 'N/A'}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block mb-0.5">識別番号 (CVE / CWE):</span>
            <span className="font-mono text-emerald-400">
              {finding.cveId || finding.cweId || 'N/A'}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block mb-0.5">初回 / 最新検出:</span>
            <span className="text-slate-200">
              {new Date(finding.createdAt).toLocaleDateString()} (出現 {finding.occurrenceCount}回)
            </span>
          </div>
        </div>
      </div>

      {/* Visual Risk Score Breakdown */}
      {assessment && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Activity className="h-4 w-4 text-amber-400" />
            <span>リスクスコア算出根拠の視覚的ブレークダウン (Formula v{assessment.formulaVersion})</span>
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center text-xs">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <span className="text-slate-400 block mb-1">基本深刻度 (CVSS)</span>
              <span className="text-lg font-bold text-white">{assessment.baseSeverityScore.toFixed(1)}</span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <span className="text-slate-400 block mb-1">脅威スコア (EPSS/KEV)</span>
              <span className="text-lg font-bold text-rose-400">+{assessment.threatScore.toFixed(1)}</span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <span className="text-slate-400 block mb-1">到達可能性係数</span>
              <span className="text-lg font-bold text-cyan-400">×{assessment.reachabilityScore.toFixed(2)}</span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <span className="text-slate-400 block mb-1">アセット重要度補正</span>
              <span className="text-lg font-bold text-amber-400">×{assessment.assetMultiplier.toFixed(2)}</span>
            </div>
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 col-span-2 sm:col-span-1">
              <span className="text-amber-300 block mb-1 font-semibold">最終算出スコア</span>
              <span className="text-xl font-extrabold text-amber-400">{assessment.finalScore.toFixed(1)}</span>
            </div>
          </div>
        </div>
      )}

      {/* Source Code Snippet & Evidence */}
      {primaryEvidence?.codeSnippetRedacted && (
        <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs">
            <span className="font-mono text-slate-300 flex items-center gap-2">
              <FileCode className="h-4 w-4 text-emerald-400" />
              <span>{finding.filePath}</span>
              <span className="text-slate-500">(行 {finding.startLine ?? 1} 〜 {finding.endLine ?? finding.startLine ?? 1})</span>
            </span>
            <span className="text-slate-400 text-[11px]">シークレット自動マスキング済</span>
          </div>
          <pre className="p-4 font-mono text-xs text-emerald-300/90 overflow-x-auto leading-relaxed bg-black/40">
            <code>{primaryEvidence.codeSnippetRedacted}</code>
          </pre>
        </div>
      )}

      {/* AI Investigation & Remediation Section */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-purple-400" />
              <span>AI調査・修正支援パイプライン (IAiRemediationProvider)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              客観的事実とAI推論の厳格分離・Unified Diffパッチ・隔離サンドボックス再検証
            </p>
          </div>

          {!remediation && (
            <button
              onClick={handleGenerateRemediation}
              disabled={generatingAi}
              className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-xs font-semibold text-white hover:bg-purple-500 transition shadow-sm"
            >
              <Sparkles className={`h-4 w-4 ${generatingAi ? 'animate-spin' : ''}`} />
              {generatingAi ? 'AIパッチ生成中...' : 'AI修正案を生成'}
            </button>
          )}
        </div>

        {remediation && (
          <div className="space-y-5">
            {/* Strict Separation Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Verified Facts Card (Emerald) */}
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-2">
                <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>客観的事実 (Verified Facts)</span>
                </h3>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {remediation.verifiedFacts.map((fact, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-emerald-400 font-bold">•</span>
                      <span>{fact}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* AI Hypothesis Analysis Card (Purple) */}
              <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 p-4 space-y-2">
                <h3 className="text-xs font-bold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Sparkles className="h-4 w-4" />
                  <span>AI推論・分析 (AI Hypothesis & Analysis)</span>
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {remediation.aiHypothesisAnalysis}
                </p>
              </div>
            </div>

            {/* Side Effects Warning Card */}
            {remediation.sideEffectsWarning && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300 flex items-start gap-2.5">
                <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold block mb-0.5">潜在的副作用の警告:</span>
                  <span>{remediation.sideEffectsWarning}</span>
                </div>
              </div>
            )}

            {/* Unified Diff Comparison Viewer */}
            {remediation.proposedUnifiedDiff && (
              <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
                <div className="px-5 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs">
                  <span className="font-mono text-slate-300 flex items-center gap-2">
                    <GitCompare className="h-4 w-4 text-cyan-400" />
                    <span>提案された修正パッチ (Proposed Unified Diff)</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">Git Patch Format</span>
                </div>
                <div className="p-4 font-mono text-xs overflow-x-auto leading-relaxed bg-black/60">
                  {remediation.proposedUnifiedDiff.split('\n').map((line, idx) => {
                    const isAdded = line.startsWith('+') && !line.startsWith('+++');
                    const isRemoved = line.startsWith('-') && !line.startsWith('---');
                    const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                    return (
                      <div
                        key={idx}
                        className={`px-2 py-0.5 ${
                          isAdded
                            ? 'bg-emerald-500/20 text-emerald-300 font-semibold'
                            : isRemoved
                            ? 'bg-rose-500/20 text-rose-300 font-semibold'
                            : isHeader
                            ? 'text-cyan-400 font-bold'
                            : 'text-slate-400'
                        }`}
                      >
                        {line || ' '}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Verification Status & Action Controls */}
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400">サンドボックス検証ステータス:</span>
                  <span
                    className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-bold ${
                      remediation.verificationStatus === 'VerifiedFixed'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : remediation.verificationStatus === 'VerificationFailed'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {remediation.verificationStatus === 'VerifiedFixed' && <CheckCircle2 className="h-3 w-3" />}
                    {remediation.verificationStatus}
                  </span>

                  <span className="text-slate-400 ml-2">承認ステータス:</span>
                  <span
                    className={`inline-flex items-center rounded px-2 py-0.5 font-bold ${
                      remediation.approvalStatus === 'Approved'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : remediation.approvalStatus === 'Rejected'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {remediation.approvalStatus}
                  </span>
                </div>
                {remediation.verificationDetails && (
                  <p className="text-[11px] text-slate-500">{remediation.verificationDetails}</p>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  onClick={handleVerifySandbox}
                  disabled={verifying}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3.5 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition"
                >
                  <Play className={`h-3.5 w-3.5 ${verifying ? 'animate-spin' : ''}`} />
                  {verifying ? 'サンドボックス検証中...' : 'サンドボックス再検証'}
                </button>

                {remediation.approvalStatus === 'PendingReview' && (
                  <>
                    <button
                      onClick={() => setIsApproveOpen(true)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
                    >
                      <Check className="h-3.5 w-3.5" />
                      承認 (Approve)
                    </button>
                    <button
                      onClick={() => setIsRejectOpen(true)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-rose-600 bg-rose-950/40 px-3.5 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-900/60 transition"
                    >
                      <X className="h-3.5 w-3.5" />
                      却下 (Reject)
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Approve Modal */}
      {isApproveOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-2">修正パッチの承認 (Human-in-the-Loop)</h2>
            <p className="text-xs text-slate-400 mb-4">
              承認を行うと、Findingは自動的に「Remediated」ステータスへ移行します（TenantAdmin / SecurityEngineer 権限が必要）。
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">承認コメント (任意)</label>
                <textarea
                  rows={2}
                  value={approvalReason}
                  onChange={(e) => setApprovalReason(e.target.value)}
                  placeholder="例: サンドボックス再スキャンにて解消確認済み。本番デプロイを承認。"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsApproveOpen(false)}
                  className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
                >
                  キャンセル
                </button>
                <button
                  type="button"
                  onClick={handleApprove}
                  disabled={approving}
                  className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
                >
                  {approving ? '承認処理中...' : '承認を確定する'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Reject Modal */}
      {isRejectOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-2">修正パッチの却下</h2>
            <p className="text-xs text-slate-400 mb-4">
              却下理由の入力は必須です。
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">却下理由 *</label>
                <textarea
                  required
                  rows={3}
                  value={approvalReason}
                  onChange={(e) => setApprovalReason(e.target.value)}
                  placeholder="例: コードスタイル規約に違反しているため再生成が必要。"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsRejectOpen(false)}
                  className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
                >
                  キャンセル
                </button>
                <button
                  type="button"
                  onClick={handleReject}
                  disabled={rejecting}
                  className="rounded-lg bg-rose-600 px-4 py-2 text-xs font-semibold text-white hover:bg-rose-500 transition shadow-sm"
                >
                  {rejecting ? '却下処理中...' : '却下を確定する'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
