'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ArrowRight,
  Shield,
  Layers,
  StopCircle,
  RefreshCw,
  Cpu
} from 'lucide-react';
import { api } from '@/lib/api';
import { ScanDto } from '@/lib/types';

export default function ScanProgressPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanDto | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [isCancelling, setIsCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;

    // Fetch initial scan state
    api.getScan(scanId).then(setScan).catch((err) => {
      setError(err.message || 'スキャン情報の取得に失敗しました');
    });

    // Subscribe to SSE stream
    const unsubscribe = api.subscribeScanEvents(
      scanId,
      (updatedScan) => {
        setScan(updatedScan);
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] スキャン進捗更新: ステータス=${updatedScan.status}, 検出件数=${updatedScan.totalFindingsCount}`,
        ]);
      },
      (completedScan) => {
        setScan(completedScan);
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] スキャン完了: 総検出数=${completedScan.totalFindingsCount} (Critical=${completedScan.criticalCount}, High=${completedScan.highCount})`,
        ]);
      },
      (err) => {
        console.error('SSE Error', err);
      }
    );

    return () => {
      unsubscribe();
    };
  }, [scanId]);

  const handleCancel = async () => {
    if (!scanId) return;
    setIsCancelling(true);
    try {
      await api.cancelScan(scanId);
      const updated = await api.getScan(scanId);
      setScan(updated);
      setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ユーザーによるスキャン中断要求を送信しました`]);
    } catch (err: any) {
      setError(err.message || 'スキャンのキャンセルに失敗しました');
    } finally {
      setIsCancelling(false);
    }
  };

  const isCompleted = scan?.status === 'Completed';
  const isFailed = scan?.status === 'Failed' || scan?.status === 'Cancelled';
  const isRunning = scan?.status === 'Running' || scan?.status === 'Queued';

  // Calculate progress percentage based on completed jobs
  const totalJobs = scan?.jobs?.length || 1;
  const completedJobs = scan?.jobs?.filter((j) => j.status === 'Completed' || j.status === 'Failed').length || 0;
  const progressPercent = isCompleted ? 100 : Math.min(Math.round((completedJobs / totalJobs) * 100), 95);

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Activity className="h-6 w-6 text-emerald-400" />
              <span>リアルタイムスキャン進捗</span>
            </h1>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                isCompleted
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : isFailed
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse'
              }`}
            >
              {isRunning && <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-ping" />}
              {scan?.status ?? '取得中...'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">スキャンID: {scanId}</p>
        </div>

        <div className="flex items-center gap-3">
          {isRunning && (
            <button
              onClick={handleCancel}
              disabled={isCancelling}
              className="inline-flex items-center gap-2 rounded-lg border border-rose-600 bg-rose-950/40 px-3.5 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-900/60 transition shadow-sm"
            >
              <StopCircle className="h-4 w-4" />
              {isCancelling ? 'キャンセル中...' : 'スキャン強制中断'}
            </button>
          )}

          {isCompleted && (
            <Link
              href={`/findings?projectId=${scan?.projectId}`}
              className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
            >
              <span>検出脆弱性の確認へ</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Progress Bar & Phase Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div className="flex items-center justify-between text-sm">
          <span className="font-semibold text-white flex items-center gap-2">
            <Cpu className="h-4 w-4 text-emerald-400" />
            全体進捗状況
          </span>
          <span className="font-mono font-bold text-emerald-400">{progressPercent}%</span>
        </div>

        <div className="w-full bg-slate-800 h-3 rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-500 rounded-full ${
              isCompleted
                ? 'bg-emerald-500'
                : isFailed
                ? 'bg-rose-500'
                : 'bg-gradient-to-r from-emerald-500 to-cyan-500'
            }`}
            style={{ width: `${progressPercent}%` }}
          />
        </div>

        {/* Phase Indicators */}
        <div className="grid grid-cols-4 gap-2 pt-2 text-center text-xs">
          <div className={`p-2 rounded-lg border ${scan ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400' : 'border-slate-800 text-slate-500'}`}>
            1. キュー登録
          </div>
          <div className={`p-2 rounded-lg border ${isRunning || isCompleted ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400' : 'border-slate-800 text-slate-500'}`}>
            2. スキャン実行
          </div>
          <div className={`p-2 rounded-lg border ${completedJobs > 0 || isCompleted ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400' : 'border-slate-800 text-slate-500'}`}>
            3. 重複排除・相関
          </div>
          <div className={`p-2 rounded-lg border ${isCompleted ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400' : 'border-slate-800 text-slate-500'}`}>
            4. リスク評価完了
          </div>
        </div>
      </div>

      {/* Real-time Findings Counter */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <div className="text-xs text-slate-400 font-medium">総検出件数</div>
          <div className="text-2xl font-bold text-white mt-1">{scan?.totalFindingsCount ?? 0}</div>
        </div>
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4">
          <div className="text-xs text-rose-400 font-medium">CRITICAL</div>
          <div className="text-2xl font-bold text-white mt-1">{scan?.criticalCount ?? 0}</div>
        </div>
        <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 p-4">
          <div className="text-xs text-orange-400 font-medium">HIGH</div>
          <div className="text-2xl font-bold text-white mt-1">{scan?.highCount ?? 0}</div>
        </div>
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
          <div className="text-xs text-amber-400 font-medium">MEDIUM / LOW</div>
          <div className="text-2xl font-bold text-white mt-1">
            {(scan?.mediumCount ?? 0) + (scan?.lowCount ?? 0)}
          </div>
        </div>
      </div>

      {/* Scanner Jobs Status */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Layers className="h-4 w-4 text-slate-400" />
          <span>スキャナージョブ一覧 (IScannerAdapter Jobs)</span>
        </h2>

        <div className="space-y-2">
          {scan?.jobs?.map((job) => (
            <div
              key={job.id}
              className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/60 text-xs"
            >
              <div className="flex items-center gap-3">
                {job.status === 'Completed' ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                ) : job.status === 'Failed' ? (
                  <XCircle className="h-4 w-4 text-rose-400 flex-shrink-0" />
                ) : (
                  <RefreshCw className="h-4 w-4 animate-spin text-amber-400 flex-shrink-0" />
                )}
                <span className="font-semibold text-white">{job.scannerType}</span>
                <span className="text-slate-500 font-mono text-[11px]">{job.id.substring(0, 8)}</span>
              </div>

              <div className="flex items-center gap-4 text-slate-400">
                <span>{job.status}</span>
                {job.completedAt && (
                  <span className="text-[11px] text-slate-500">
                    {new Date(job.completedAt).toLocaleTimeString()} 完了
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SSE Live Log Feed */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">
        <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
          <Clock className="h-3.5 w-3.5" />
          リアルタイム中継ログ (SSE Live Stream)
        </h2>
        <div className="rounded-lg bg-black/50 p-3 h-48 overflow-y-auto font-mono text-xs text-slate-300 space-y-1">
          {logs.length === 0 ? (
            <div className="text-slate-600 italic">SSEイベント待機中...</div>
          ) : (
            logs.map((log, i) => (
              <div key={i} className="text-emerald-400/90 leading-relaxed">
                {log}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
