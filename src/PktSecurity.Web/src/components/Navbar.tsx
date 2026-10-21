'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldAlert,
  LayoutDashboard,
  FolderGit2,
  Search,
  FileSpreadsheet,
  UserCheck,
  CheckCircle2,
  RefreshCw
} from 'lucide-react';
import { api } from '@/lib/api';

const USERS = [
  { role: 'TenantAdmin', email: 'admin@tenant-alpha.local', label: 'テナント管理者 (Admin)' },
  { role: 'SecurityEngineer', email: 'seceng@tenant-alpha.local', label: 'セキュリティエンジニア' },
  { role: 'Developer', email: 'dev@tenant-alpha.local', label: '開発者 (Developer)' },
  { role: 'Auditor', email: 'auditor@tenant-alpha.local', label: '監査役 (Auditor)' },
];

export function Navbar() {
  const pathname = usePathname();
  const [currentUser, setCurrentUser] = useState(USERS[0]);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [authSuccess, setAuthSuccess] = useState(false);

  useEffect(() => {
    // Initial auto-login with default TenantAdmin
    handleSwitchUser(USERS[0]);
  }, []);

  const handleSwitchUser = async (user: typeof USERS[0]) => {
    setIsLoggingIn(true);
    try {
      await api.login(user.email, user.role === 'TenantAdmin' ? 'AdminPassword123!' : user.role === 'SecurityEngineer' ? 'SecEngPassword123!' : user.role === 'Developer' ? 'DevPassword123!' : 'AuditorPassword123!');
      setCurrentUser(user);
      setAuthSuccess(true);
      setTimeout(() => setAuthSuccess(false), 2000);
    } catch (e) {
      console.error('Login error', e);
    } finally {
      setIsLoggingIn(false);
    }
  };

  const navLinks = [
    { href: '/', label: 'ダッシュボード', icon: LayoutDashboard },
    { href: '/projects', label: 'プロジェクト & スキャン', icon: FolderGit2 },
    { href: '/findings', label: '脆弱性トリアージ', icon: Search },
    { href: '/sbom', label: 'SBOM & 監査レポート', icon: FileSpreadsheet },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand */}
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2 font-bold text-white text-lg tracking-tight hover:opacity-90 transition">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <span>PKT <span className="text-emerald-400">Security</span> Next</span>
          </Link>

          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            PostgreSQL RLS 有効
          </span>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden md:flex items-center gap-1">
          {navLinks.map((link) => {
            const Icon = link.icon;
            const isActive = pathname === link.href || (link.href !== '/' && pathname.startsWith(link.href));
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${
                  isActive
                    ? 'bg-slate-800/80 text-emerald-400 border border-slate-700/60 shadow-sm'
                    : 'text-slate-300 hover:bg-slate-900 hover:text-white'
                }`}
              >
                <Icon className="h-4 w-4" />
                {link.label}
              </Link>
            );
          })}
        </nav>

        {/* Role Switcher */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs text-slate-300">
            <UserCheck className="h-3.5 w-3.5 text-slate-400" />
            <select
              className="bg-transparent font-medium text-white focus:outline-none cursor-pointer"
              value={currentUser.role}
              onChange={(e) => {
                const found = USERS.find((u) => u.role === e.target.value);
                if (found) handleSwitchUser(found);
              }}
              disabled={isLoggingIn}
            >
              {USERS.map((u) => (
                <option key={u.role} value={u.role} className="bg-slate-900 text-slate-200">
                  {u.label}
                </option>
              ))}
            </select>
            {isLoggingIn ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-slate-400" />
            ) : authSuccess ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            ) : null}
          </div>
        </div>
      </div>
    </header>
  );
}
