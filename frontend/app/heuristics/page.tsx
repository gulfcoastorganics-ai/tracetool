'use client'

import { useState } from 'react'
import axios from 'axios'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Check, Copy, Download, RefreshCw, Send } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { NetworkStatus } from '@/components/network-status'

interface TxInput {
  txid: string
  vout: number
  script_sig?: string
}

interface TxOutput {
  address: string
  value: number
  script_sig?: string
}

interface BitcoinTransaction {
  txid: string
  inputs: TxInput[]
  outputs: TxOutput[]
  timestamp: number
  version: number
  locktime: number
}

interface CoinJoinResult {
  type: string
  txid: string
  timestamp: number
  input_count: number
  output_count: number
  equal_outputs: number
  addresses: string[]
  total_value: number
  confidence: number
}

export default function HeuristicsPage() {
  const { toast } = useToast()
  const [transactions, setTransactions] = useState<BitcoinTransaction[]>([])
  const [coinJoins, setCoinJoins] = useState<CoinJoinResult[]>([])
  const [ciohClusters, setCiohClusters] = useState<Record<string, number[]>>({})
  const [changeAddresses, setChangeAddresses] = useState<string[]>([])
  const [loading, setLoading] = useState(false)

  const sampleTxData: BitcoinTransaction[] = [
    {
      txid: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0',
      inputs: [
        { txid: 'prev1...', vout: 0, script_sig: '' },
        { txid: 'prev2...', vout: 1, script_sig: '' }
      ],
      outputs: [
        { address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', value: 0.5 },
        { address: '1Bvf8yYmHLbm9TCvHQDbuY6Mr4QH9z1X7g', value: 0.5 }
      ],
      timestamp: Date.now() / 1000,
      version: 2,
      locktime: 0
    }
  ]

  const runCoinJoinDetection = async () => {
    if (transactions.length === 0) {
      toast({ title: 'No Transactions', description: 'Load transactions first', variant: 'destructive' })
      return
    }
    
    setLoading(true)
    try {
      const response = await axios.post(
        'http://localhost:8000/api/v1/heuristics/coinjoin',
        { transactions: transactions.map(t => ({
          txid: t.txid,
          inputs: t.inputs,
          outputs: t.outputs.map(o => ({ address: o.address, value: o.value })),
          timestamp: t.timestamp,
          version: t.version,
          locktime: t.locktime
        })),
          min_outputs: 3
        }
      )
      setCoinJoins(response.data.coinjoins)
      toast({
        title: 'CoinJoin Detection Complete',
        description: `Found ${response.data.coinjoins.length} potential CoinJoin transactions`
      })
    } catch (error: any) {
      toast({ title: 'Detection Failed', description: error.response?.data?.detail || 'Error', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  const runCIOH = async () => {
    if (transactions.length === 0) {
      toast({ title: 'No Transactions', description: 'Load transactions first', variant: 'destructive' })
      return
    }
    
    setLoading(true)
    try {
      const response = await axios.post(
        'http://localhost:8000/api/v1/heuristics/cioh',
        { transactions: transactions.map(t => ({
          txid: t.txid,
          inputs: t.inputs,
          outputs: t.outputs.map(o => ({ address: o.address, value: o.value })),
          timestamp: t.timestamp,
          version: t.version,
          locktime: t.locktime
        }))
      }
      )
      setCiohClusters(response.data.cioh_clusters)
      toast({
        title: 'CIOH Analysis Complete',
        description: `Identified ${response.data.cluster_count} address clusters`
      })
    } catch (error: any) {
      toast({ title: 'Analysis Failed', description: error.response?.data?.detail || 'Error', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  const runChangeDetection = async () => {
    if (transactions.length === 0) {
      toast({ title: 'No Transactions', description: 'Load transactions first', variant: 'destructive' })
      return
    }
    
    setLoading(true)
    try {
      const response = await axios.post(
        'http://localhost:8000/api/v1/heuristics/change',
        { transactions: transactions.map(t => ({
          txid: t.txid,
          inputs: t.inputs,
          outputs: t.outputs.map(o => ({ address: o.address, value: o.value })),
          timestamp: t.timestamp,
          version: t.version,
          locktime: t.locktime
        }))
      }
      )
      setChangeAddresses(response.data.change_addresses)
      toast({
        title: 'Change Detection Complete',
        description: `Identified ${response.data.count} potential change addresses`
      })
    } catch (error: any) {
      toast({ title: 'Analysis Failed', description: error.response?.data?.detail || 'Error', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  const loadSampleData = () => {
    setTransactions(sampleTxData)
    toast({ title: 'Sample Data Loaded', description: 'Loaded sample transaction data for analysis' })
  }

  const importTransactions = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result as string)
        setTransactions(Array.isArray(data) ? data : [data])
        toast({ title: 'Transactions Imported', description: `Loaded ${data.length} transactions` })
      } catch {
        toast({ title: 'Parse Error', description: 'Invalid JSON file', variant: 'destructive' })
      }
    }
    reader.readAsText(file)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Heuristics Lab</h1>
        <p className="text-slate-500">Apply Bitcoin blockchain heuristics to identify transaction patterns</p>
        <NetworkStatus />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Heuristic Analysis</CardTitle>
          <CardDescription>
            Apply Bitcoin blockchain heuristics to identify transaction patterns. 
            All analysis is performed locally with zero-key operation.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="block mb-2">Transaction Data</Label>
            <div className="flex gap-2">
              <Button variant="outline" onClick={loadSampleData}>
                Load Sample Data
              </Button>
              <label className="cursor-pointer">
                <span className="px-3 py-2 bg-slate-100 hover:bg-slate-200 rounded-md text-sm inline-block">
                  Import JSON
                </span>
                <input type="file" accept=".json" className="hidden" onChange={importTransactions} />
              </label>
            </div>
            <p className="text-xs text-slate-500 mt-2">Loaded {transactions.length} transactions</p>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Button variant="outline" onClick={runCoinJoinDetection} disabled={loading || transactions.length === 0}>
              {loading ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Shield className="w-4 h-4 mr-2" />}
              CoinJoin
            </Button>
            <Button variant="outline" onClick={runCIOH} disabled={loading || transactions.length === 0}>
              {loading ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Users className="w-4 h-4 mr-2" />}
              CIOH
            </Button>
            <Button variant="outline" onClick={runChangeDetection} disabled={loading || transactions.length === 0}>
              {loading ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Globe className="w-4 h-4 mr-2" />}
              Change
            </Button>
            <Button variant="outline" disabled>
              <ArrowRightLeft className="w-4 h-4 mr-2" />
              Peeling
            </Button>
          </div>
        </CardContent>
      </Card>

      {(coinJoins.length > 0 || Object.keys(ciohClusters).length > 0 || changeAddresses.length > 0) && (
        <div className="grid gap-4">
          {coinJoins.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>CoinJoin Detections</CardTitle>
                <CardDescription>Equal-output clustering patterns</CardDescription>
              </CardHeader>
              <CardContent>
                {coinJoins.map((result, idx) => (
                  <div key={idx} className="border rounded-lg p-4 bg-slate-50">
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-medium text-sm">TXID: {result.txid.slice(0, 16)}...</h4>
                        <div className="text-xs text-slate-500 space-x-4">
                          <span>{result.input_count} inputs</span>
                          <span>{result.equal_outputs} equal outputs</span>
                          <span>{result.total_value.toFixed(6)} BTC</span>
                        </div>
                      </div>
                      <span className="text-sm font-semibold text-green-600">{Math.round(result.confidence * 100)}%</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {Object.keys(ciohClusters).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>CIOH Clusters</CardTitle>
                <CardDescription>Common Input Ownership clusters</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {Object.entries(ciohClusters).slice(0, 15).map(([addr, ids], idx) => (
                    <div key={idx} className="font-mono text-xs bg-slate-100 p-2 rounded break-all">
                      {addr.slice(0, 40)}... → {ids.length} cluster(s)
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {changeAddresses.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Change Addresses</CardTitle>
                <CardDescription>Potential change output addresses</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {changeAddresses.slice(0, 15).map((addr, idx) => (
                    <div key={idx} className="font-mono text-xs bg-slate-50 p-2 rounded break-all">
                      {addr}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

import { Label } from '@/components/ui/label'
import { Shield, Users, Globe, ArrowRightLeft } from 'lucide-react'

function Shield() {
  return <ShieldIcon className="w-4 h-4" />
}

function Users() {
  return <UsersIcon className="w-4 h-4" />
}

function Globe() {
  return <GlobeIcon className="w-4 h-4" />
}

function ShieldIcon(props: any) {
  return <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3v8z" /></svg>
}

function UsersIcon(props: any) {
  return <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M16 21v-2a4 4 0 0 0-4-4H4a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
}

function GlobeIcon(props: any) {
  return <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>
}