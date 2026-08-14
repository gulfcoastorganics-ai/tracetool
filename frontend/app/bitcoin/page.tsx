'use client'

import { useState } from 'react'
import axios from 'axios'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Database, Download, RefreshCw } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { NetworkStatus } from '@/components/network-status'

interface BitcoinReport {
  analysis_timestamp: string
  transactions_analyzed: number
  cioh_clusters: number
  coinjoins_detected: number
  change_addresses: number
  peeling_chains: number
  raw_data: any
}

export default function BitcoinPage() {
  const { toast } = useToast()
  const [blockPath, setBlockPath] = useState('')
  const [report, setReport] = useState<BitcoinReport | null>(null)
  const [loading, setLoading] = useState(false)

  const runBitcoinAnalysis = async () => {
    setLoading(true)
    try {
      const response = await axios.post<BitcoinReport>(
        'http://localhost:8000/api/v1/bitcoin/analyze',
        {
          block_data_path: blockPath || undefined,
          run_heuristics: true,
          max_transactions: 1000
        }
      )
      setReport(response.data)
      toast({ title: 'Analysis Complete', description: `Analyzed ${response.data.transactions_analyzed} transactions` })
    } catch (error: any) {
      toast({ title: 'Analysis Failed', description: error.response?.data?.detail || 'Unknown error', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  const exportReport = async () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `bitcoin-forensics-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast({ title: 'Report Exported', description: 'Downloaded Bitcoin forensics report' })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Bitcoin Forensics</h1>
        <p className="text-slate-500">UTXO parser with heuristic analysis for Bitcoin transactions</p>
        <NetworkStatus />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Bitcoin Analysis</CardTitle>
          <CardDescription>
            Parse local Bitcoin Core block data files (.dat) and apply chain analysis heuristics.
            All analysis is performed locally with zero-key operation.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="block-path">Bitcoin Core Data Path (Optional)</Label>
            <Input
              id="block-path"
              type="text"
              placeholder="/path/to/.bitcoin/blocks/..."
              value={blockPath}
              onChange={(e) => setBlockPath(e.target.value)}
            />
            <p className="text-xs text-slate-500">
              Leave empty to run heuristics on empty dataset or load transactions manually
            </p>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Analysis Options</h3>
              <ul className="text-xs text-slate-600 space-y-1">
                <li>• CoinJoin Detection (equal-output clustering)</li>
                <li>• Common Input Ownership Heuristic (CIOH)</li>
                <li>• Change-Address Detection</li>
                <li>• Peeling Chain Analysis</li>
              </ul>
            </div>

            <div className="flex flex-col gap-2 justify-end">
              <Button onClick={runBitcoinAnalysis} disabled={loading}>
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    Running Analysis...
                  </>
                ) : (
                  <>
                    <Database className="w-4 h-4 mr-2" />
                    Run Bitcoin Forensics
                  </>
                )}
              </Button>
              
              {report && (
                <Button variant="outline" onClick={exportReport}>
                  <Download className="w-4 h-4 mr-2" />
                  Export Report
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {report && (
        <div className="grid gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-5">
                <StatCard title="Transactions" value={report.transactions_analyzed} />
                <StatCard title="CIOH Clusters" value={report.cioh_clusters} color="green" />
                <StatCard title="CoinJoins" value={report.coinjoins_detected} color="purple" />
                <StatCard title="Change Addr" value={report.change_addresses} color="amber" />
                <StatCard title="Peeling Chains" value={report.peeling_chains} color="red" />
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>CIOH Clusters</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="max-h-64 overflow-y-auto">
                  {report.raw_data?.common_input_ownership ? (
                    Object.entries(report.raw_data.common_input_ownership).slice(0, 5).map(([addr, clusters]: [string, number[]], idx: number) => (
                      <div key={idx} className="font-mono text-xs bg-slate-50 p-2 rounded mb-2 break-all">
                        {addr.slice(0, 30)}... → {clusters.length} clusters
                      </div>
                    ))
                  ) : (
                    <p className="text-slate-500 text-sm">No CIOH data available</p>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>CoinJoin Detections</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="max-h-64 overflow-y-auto">
                  {report.raw_data?.coinjoins_detected?.length ? (
                    report.raw_data.coinjoins_detected.slice(0, 3).map((cj: any, idx: number) => (
                      <div key={idx} className="bg-slate-50 p-2 rounded mb-2">
                        <p className="font-mono text-xs break-all">{cj.txid.slice(0, 20)}...</p>
                        <p className="text-xs text-slate-500">{cj.equal_outputs} equal outputs, {Math.round(cj.confidence * 100)}% confidence</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-slate-500 text-sm">No CoinJoin patterns detected</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

interface StatCardProps {
  title: string
  value: number
  color?: 'green' | 'purple' | 'amber' | 'red'
}

function StatCard({ title, value, color = 'blue' }: StatCardProps) {
  const colorMap = {
    blue: 'text-blue-600',
    green: 'text-green-600',
    purple: 'text-purple-600',
    amber: 'text-amber-600',
    red: 'text-red-600'
  }
  
  return (
    <div className="border rounded-lg p-4">
      <p className="text-sm text-slate-500">{title}</p>
      <p className={`text-xl font-bold ${colorMap[color]}`}>{value.toLocaleString()}</p>
    </div>
  )
}