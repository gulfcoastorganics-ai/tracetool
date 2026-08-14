'use client'

import { useState } from 'react'
import axios from 'axios'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Check, Send, RefreshCw } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { NetworkStatus } from '@/components/network-status'

interface ChainData {
  balance: number | null
  transaction_count: number
  transactions: any[]
}

interface AnalysisResponse {
  address: string
  timestamp: string
  chains: Record<string, ChainData>
}

const CHAINS_CONFIG = {
  ethereum: { name: 'Ethereum', symbol: 'Ξ', api: 'https://api.etherscan.io/api' },
  base: { name: 'Base', symbol: '𝕯', api: 'https://api.basescan.org/api' },
  bsc: { name: 'BSC', symbol: '₮', api: 'https://api.bscscan.com/api' },
  polygon: { name: 'Polygon', symbol: '₽', api: 'https://api.polygonscan.com/api' }
}

export default function ExplorerPage() {
  const { toast } = useToast()
  const [address, setAddress] = useState('')
  const [selectedChains, setSelectedChains] = useState(['ethereum', 'base', 'bsc', 'polygon'])
  const [analysisData, setAnalysisData] = useState<AnalysisResponse | null>(null)
  const [loading, setLoading] = useState(false)

  const toggleChain = (chain: string) => {
    if (selectedChains.includes(chain)) {
      setSelectedChains(selectedChains.filter(c => c !== chain))
    } else {
      setSelectedChains([...selectedChains, chain])
    }
  }

  const analyzeAddress = async () => {
    if (!address || !address.startsWith('0x') && !address.startsWith('bc')) {
      toast({ title: 'Invalid Address', description: 'Enter a valid EVM or Bitcoin address', variant: 'destructive' })
      return
    }

    setLoading(true)
    try {
      if (address.startsWith('0x')) {
        const response = await axios.post<AnalysisResponse>(
          'http://localhost:8000/api/v1/evm/analyze',
          { address, chains: selectedChains }
        )
        setAnalysisData(response.data)
        toast({ title: 'Analysis Complete', description: `Found data across ${Object.keys(response.data.chains).length} chains` })
      } else {
        const response = await axios.post(
          'http://localhost:8000/api/v1/bitcoin/analyze',
          { block_data_path: undefined, run_heuristics: false }
        )
        setAnalysisData(null)
        toast({ title: 'Bitcoin Mode', description: 'Use Bitcoin page for BTC analysis' })
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.response?.data?.detail || 'Failed to analyze', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Multi-Chain Explorer</h1>
        <p className="text-slate-500">Analyze addresses across EVM networks using zero-key public endpoints</p>
        <NetworkStatus />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Address Analysis</CardTitle>
          <CardDescription>
            Enter an address to analyze across multiple chains. 
            Uses public RPC endpoints - no API keys required.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="address">Address</Label>
            <div className="flex gap-2">
              <Input
                id="address"
                type="text"
                placeholder="0x... or bc1..."
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                className="font-mono"
              />
              <Button onClick={analyzeAddress} disabled={loading || !address}>
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
            {Object.entries(CHAINS_CONFIG).map(([chain, config]) => (
              <Button
                key={chain}
                variant={selectedChains.includes(chain) ? 'default' : 'outline'}
                onClick={() => toggleChain(chain)}
                className="justify-start"
              >
                <span className="mr-2">{config.symbol}</span>
                {config.name}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {analysisData && (
        <Card>
          <CardHeader>
            <CardTitle>Chain Balances</CardTitle>
            <CardDescription>Token balances across selected chains</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {Object.entries(analysisData.chains).map(([chain, data]) => (
                <Card key={chain} variant="outline">
                  <CardContent className="pt-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium">
                          {chain.charAt(0).toUpperCase() + chain.slice(1)}
                        </p>
                        <p className="text-lg font-semibold">
                          {data.balance !== null ? data.balance.toFixed(6) : '—'}
                        </p>
                      </div>
                      <span className="text-2xl">{CHAINS_CONFIG[chain as keyof typeof CHAINS_CONFIG]?.symbol || '●'}</span>
                    </div>
                    <p className="text-xs text-slate-500 mt-2">
                      {data.transaction_count} transactions
                    </p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}