import './globals.css';
import type { Metadata } from 'next';
import { Navbar } from '@/components/Navbar';

export const metadata: Metadata = {
  title: 'PKT Security Platform Next - 統合セキュリティ管理コンソール',
  description: 'PostgreSQL RLSマルチテナント、2段階重複排除、AI修正支援、SBOM/OpenVEX対応の統合セキュリティ基盤',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ja" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-emerald-500 selection:text-white">
        <Navbar />
        <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-slate-900 bg-slate-950/50 py-6 text-center text-xs text-slate-500">
          <p>© 2026 PKT Security Platform Next. All rights reserved. Zero-Trust Architecture & PostgreSQL RLS Enforced.</p>
        </footer>
      </body>
    </html>
  );
}
