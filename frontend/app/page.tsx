'use client'

import { useEffect, useState } from 'react'
import { Database, Shield, TrendingUp, Users, Globe, Activity } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { NetworkStatus } from '@/components/network-status'

export default function HomePage() {
  const [stats, setStats] = useState({
    chains: 4,
    addresses: 0,
    transactions: 0,
    analyses: 0
  })

  useEffect(() => {
    const interval = setInterval(() => {
      setStats({
        chains: 4,
        addresses: Math.floor(Math.random() * 100),
        transactions: Math.floor(Math.random() * 1000),
        analyses: Math.floor(Math.random() * 50)
      })
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Chain-Trace Dashboard</h1>
        <p className="text-slate-500">Zero-key cryptocurrency forensics explorer</p>
        <NetworkStatus />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard 
          icon={Database}
          title="EVM Networks" 
          value={stats.chains}
          description="Ethereum, Base, BSC, Polygon"
        />
        <StatsCard 
          icon={Shield}
          title="Addresses Tracked" 
          value={stats.addresses}
          description="Derived from mnemonics"
        />
        <StatsCard 
          icon={Activity}
          title="Transactions" 
          value={stats.transactions}
          description="Analyzed across chains"
        />
        <StatsCard 
          icon={Users}
          title="Analyses" 
          value={stats.analyses}
          description="Forensic reports completed"
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="lg:col-span-4">
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Get started with common tasks</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <Button variant="outline" className="w-full justify-start" asChild>
              <a href="/derivation">
                Derive Addresses from Mnemonic
              </a>
            </Button>
            <Button variant="outline" className="w-full justify-start" asChild>
              <a href="/explorer">
                Analyze EVM/BTC Address
              </a>
            </Button>
            <Button variant="outline" className="w-full justify-start" asChild>
              <a href="/heuristics">
                Run Bitcoin Heuristics
              </a>
            </Button>
            <Button variant="outline" className="w-full justify-start" asChild>
              <a href="/bitcoin">
                Bitcoin Forensics Report
              </a>
            </Button>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle>Chain Status</CardTitle>
            <CardDescription>Connected networks</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(CHAINS).map(([chain, info]) => (
                <div key={chain} className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">{info.name}</p>
                    <p className="text-xs text-slate-500">{chain.toUpperCase()}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                    <span className="text-xs text-slate-500">Online</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

interface StatsCardProps {
  icon: any
  title: string
  value: number
  description: string
}

function StatsCard({ icon: Icon, title, value, description }: StatsCardProps) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-full">
            <Icon className="w-5 h-5 text-primary" />
          </div>
          <div>
            <p className="text-sm text-slate-500">{title}</p>
            <p className="text-2xl font-bold">{value.toLocaleString()}</p>
            <p className="text-xs text-slate-400">{description}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

const CHAINS = {
  ethereum: { name: 'Ethereum', symbol: 'Ξ' },
  base: { name: 'Base', symbol: '𝕯' },
  bsc: { name: 'BSC', symbol: '₮' },
  polygon: { name: 'Polygon', symbol: '₽' }
}