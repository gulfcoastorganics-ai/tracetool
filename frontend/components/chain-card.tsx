import { type LucideIcon } from 'lucide-react'
import Link from 'next/link'
import { cn } from '@/lib/utils'

interface ChainCardProps {
  chain: string
  icon: string
  status: 'online' | 'offline' | 'loading'
  onClick?: () => void
}

export function ChainCard({ chain, icon, status, onClick }: ChainCardProps) {
  return (
    <div 
      onClick={onClick}
      className={cn(
        "rounded-lg border p-4 cursor-pointer hover:shadow-md transition-shadow",
        status === 'loading' ? 'bg-slate-100 animate-pulse' : 'bg-white',
        status === 'online' && 'border-green-200',
        status === 'offline' && 'border-slate-200'
      )}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-slate-600">{chain}</p>
          <p className="text-lg font-semibold">{icon}</p>
        </div>
        <div className={cn(
          "w-2 h-2 rounded-full",
          status === 'online' && 'bg-green-500',
          status === 'offline' && 'bg-slate-300',
          status === 'loading' && 'bg-slate-400 animate-pulse'
        )} />
      </div>
    </div>
  )
}