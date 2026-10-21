'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  FolderGit2,
  Plus,
  Play,
  Globe,
  Lock,
  Layers,
  RefreshCw,
  AlertCircle,
  FileCode,
  ShieldCheck,
  Calendar
} from 'lucide-react';
import { api } from '@/lib/api';
import { Project, BusinessCriticality } from '@/lib/types';

export default function ProjectsPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New Project Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [criticality, setCriticality] = useState<BusinessCriticality>('High');
  const [isInternetFacing, setIsInternetFacing] = useState(true);
  const [dataSensitivity, setDataSensitivity] = useState('Confidential');
  const [submitting, setSubmitting] = useState(false);

  // Start Scan Modal State
  const [isScanOpen, setIsScanOpen] = useState(false);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [selectedScanners, setSelectedScanners] = useState<string[]>([
    'Trivy',
    'Semgrep',
    'Gitleaks',
    'OsvScanner',
    'Syft',
    'Grype',
  ]);
  const [targetDir, setTargetDir] = useState('samples/sample-vulnerable-repo');
  const [startingScan, setStartingScan] = useState(false);

  const fetchProjects = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getProjects();
      setProjects(data);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'プロジェクトの読み込みに失敗しました');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.createProject({
        name,
        description,
        businessCriticality: criticality,
        isInternetFacing,
        dataSensitivity,
      });
      setIsCreateOpen(false);
      setName('');
      setDescription('');
      fetchProjects();
    } catch (err: any) {
      setError(err.message || 'プロジェクト作成に失敗しました');
    } finally {
      setSubmitting(false);
    }
  };

  const handleStartScan = async () => {
    if (!selectedProject) return;
    setStartingScan(true);
    setError(null);
    try {
      const scan = await api.startScan(selectedProject.id, {
        scannerTypes: selectedScanners,
        targetDirectory: targetDir,
      });
      setIsScanOpen(false);
      // Navigate to SSE real-time screen
      router.push(`/scans/${scan.id}`);
    } catch (err: any) {
      setError(err.message || 'スキャン起動に失敗しました');
    } finally {
      setStartingScan(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FolderGit2 className="h-6 w-6 text-emerald-400" />
            <span>プロジェクト & スキャン管理</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            ビジネス重要度・アセット公開設定・隔離スキャナーの起動管理
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchProjects}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800 transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            更新
          </button>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
          >
            <Plus className="h-4 w-4" />
            新規プロジェクト登録
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Project Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {loading ? (
          <div className="col-span-full py-16 text-center text-slate-500">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto text-emerald-400 mb-2" />
            プロジェクトを読み込み中...
          </div>
        ) : projects.length === 0 ? (
          <div className="col-span-full rounded-xl border border-dashed border-slate-800 p-12 text-center text-slate-500">
            <FolderGit2 className="h-10 w-10 mx-auto text-slate-600 mb-3" />
            <p className="text-sm font-medium text-slate-300">プロジェクトが登録されていません</p>
            <p className="text-xs text-slate-500 mt-1">「新規プロジェクト登録」からプロジェクトを追加してください。</p>
          </div>
        ) : (
          projects.map((p) => (
            <div
              key={p.id}
              className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 hover:border-slate-700 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <h3 className="font-bold text-white text-base tracking-tight truncate">{p.name}</h3>
                  <span
                    className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold ${
                      p.businessCriticality === 'Critical'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : p.businessCriticality === 'High'
                        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                        : p.businessCriticality === 'Medium'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}
                  >
                    重要度: {p.businessCriticality}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mt-2 line-clamp-2 min-h-[2rem]">
                  {p.description || '説明なし'}
                </p>

                <div className="mt-4 flex flex-wrap gap-2 text-[11px]">
                  <span className="inline-flex items-center gap-1 rounded bg-slate-800/80 px-2 py-0.5 text-slate-300 border border-slate-700">
                    <Globe className="h-3 w-3 text-cyan-400" />
                    {p.isInternetFacing ? '外部公開あり' : '内部限定'}
                  </span>
                  <span className="inline-flex items-center gap-1 rounded bg-slate-800/80 px-2 py-0.5 text-slate-300 border border-slate-700">
                    <Lock className="h-3 w-3 text-amber-400" />
                    機密度: {p.dataSensitivity}
                  </span>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] text-slate-500 flex items-center gap-1">
                  <Calendar className="h-3 w-3" />
                  {new Date(p.createdAt).toLocaleDateString('ja-JP')}
                </span>

                <button
                  onClick={() => {
                    setSelectedProject(p);
                    setIsScanOpen(true);
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
                >
                  <Play className="h-3 w-3 fill-current" />
                  スキャン起動
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* New Project Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-lg font-bold text-white mb-4">新規プロジェクトの作成</h2>
            <form onSubmit={handleCreateProject} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">プロジェクト名 *</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="例: E-Commerce Web API"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">説明</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  placeholder="システムの概要、管轄チーム等"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">ビジネス重要度</label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value as BusinessCriticality)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none cursor-pointer"
                  >
                    <option value="Critical">Critical (極めて高い)</option>
                    <option value="High">High (高い)</option>
                    <option value="Medium">Medium (標準)</option>
                    <option value="Low">Low (低い)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">データ機密度</label>
                  <select
                    value={dataSensitivity}
                    onChange={(e) => setDataSensitivity(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none cursor-pointer"
                  >
                    <option value="Confidential">Confidential (機密)</option>
                    <option value="Restricted">Restricted (厳格)</option>
                    <option value="Internal">Internal (社内限定)</option>
                    <option value="Public">Public (公開)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="internetFacing"
                  checked={isInternetFacing}
                  onChange={(e) => setIsInternetFacing(e.target.checked)}
                  className="h-4 w-4 rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-400"
                />
                <label htmlFor="internetFacing" className="text-xs text-slate-300 cursor-pointer">
                  インターネットに外部公開されているアセット (Is Internet Facing)
                </label>
              </div>

              <div className="mt-6 flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
                >
                  キャンセル
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm"
                >
                  {submitting ? '作成中...' : '登録する'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Start Scan Modal */}
      {isScanOpen && selectedProject && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-lg font-bold text-white mb-1">スキャン起動: {selectedProject.name}</h2>
            <p className="text-xs text-slate-400 mb-4">
              実行するスキャナー種別およびスキャン対象ディレクトリを選択してください。
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  有効にするスキャナー (IScannerAdapter)
                </label>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {['Trivy', 'Semgrep', 'Gitleaks', 'OsvScanner', 'Syft', 'Grype'].map((sc) => {
                    const checked = selectedScanners.includes(sc);
                    return (
                      <label
                        key={sc}
                        className={`flex items-center gap-2 rounded-lg border p-2.5 cursor-pointer transition ${
                          checked
                            ? 'border-emerald-500/50 bg-emerald-500/10 text-white'
                            : 'border-slate-800 bg-slate-950 text-slate-400'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedScanners([...selectedScanners, sc]);
                            } else {
                              setSelectedScanners(selectedScanners.filter((s) => s !== sc));
                            }
                          }}
                          className="h-3.5 w-3.5 rounded text-emerald-500"
                        />
                        <span className="font-semibold">{sc}</span>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  対象ディレクトリ (Target Directory)
                </label>
                <input
                  type="text"
                  value={targetDir}
                  onChange={(e) => setTargetDir(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white font-mono focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                <span>スキャンは隔離ワーカープロセスで非同期に実行され、進捗はSSEでリアルタイム中継されます。</span>
              </div>
            </div>

            <div className="mt-6 flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsScanOpen(false)}
                className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
              >
                キャンセル
              </button>
              <button
                type="button"
                onClick={handleStartScan}
                disabled={startingScan || selectedScanners.length === 0}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition shadow-sm flex items-center gap-2"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                {startingScan ? '起動中...' : 'スキャン開始'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
