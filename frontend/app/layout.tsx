import './globals.css'
import { Inter } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'Chain-Trace',
  description: 'Zero-key cryptocurrency forensics explorer',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="flex h-screen bg-slate-100">
          <Sidebar />
          <main className="flex-1 overflow-y-auto p-6">
            {children}
          </main>
        </div>
      </body>
    </html>
  )
}

function Sidebar() {
  return (
    <nav className="hidden w-64 flex-col bg-white border-r p-4">
      <h1 className="text-xl font-bold text-primary mb-6">Chain-Trace</h1>
      <div className="space-y-2">
        <a href="/" className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100">
          Dashboard
        </a>
        <a href="/derivation" className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100">
          Derivation Engine
        </a>
        <a href="/explorer" className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100">
          Multi-Chain Explorer
        </a>
        <a href="/heuristics" className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100">
          Heuristics Lab
        </a>
        <a href="/bitcoin" className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100">
          Bitcoin Forensics
        </a>
      </div>
    </nav>
  )
}