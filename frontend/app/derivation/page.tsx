'use client'

import { useState } from 'react'
import axios from 'axios'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { AlertCircle, Check, Copy, Database, Send, Plus, Trash2 } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { NetworkStatus } from '@/components/network-status'

interface DerivedAddress {
  path: string
  address: string
  label: string
  chain_type: string
}

export default function DerivationPage() {
  const { toast } = useToast()
  const [mnemonic, setMnemonic] = useState('')
  const [derivationType, setDerivationType] = useState('ethereum')
  const [addressCount, setAddressCount] = useState(10)
  const [derivedAddresses, setDerivedAddresses] = useState<DerivedAddress[]>([])
  const [loading, setLoading] = useState(false)

  const derivationTypes = [
    { value: 'ethereum', label: 'Ethereum (BIP44)', icon: 'Ξ' },
    { value: 'bip44', label: 'Bitcoin Legacy (BIP44)', icon: '1' },
    { value: 'bip49', label: 'Bitcoin SegWit (BIP49)', icon: '3' },
    { value: 'bip84', label: 'Bitcoin Native SegWit (BIP84)', icon: 'bc1' },
    { value: 'slip10', label: 'Solana (SLIP-0010)', icon: 'S' }
  ]

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!mnemonic.trim()) {
      toast({ title: 'Missing Mnemonic', description: 'Please enter a BIP39 mnemonic phrase', variant: 'destructive' })
      return
    }

    setLoading(true)
    try {
      const response = await axios.post<{
        success: boolean
        addresses: DerivedAddress[]
        derivation_type: string
        count: number
      }>(
        'http://localhost:8000/api/v1/derive',
        {
          mnemonic: mnemonic.trim(),
          derivation_type: derivationType,
          count: addressCount
        }
      )

      setDerivedAddresses(response.data.addresses)
      toast({
        title: 'Addresses Derived Successfully',
        description: `Generated ${response.data.count} public addresses`
      })
    } catch (error: any) {
      toast({
        title: 'Derivation Failed',
        description: error.response?.data?.detail || 'Unknown error',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const copyAddress = async (address: string) => {
    await navigator.clipboard.writeText(address)
    toast({ title: 'Copied', description: 'Address copied to clipboard' })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Derivation Engine</h1>
        <p className="text-slate-500">Derive public addresses from BIP39 mnemonics - all operations local</p>
        <NetworkStatus />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Mnemonic to Addresses</CardTitle>
          <CardDescription>
            Enter your BIP39 mnemonic to derive public addresses. 
            All operations are performed locally without exposing your private keys.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="mnemonic">Mnemonic Phrase (12 or 24 words)</Label>
              <Input
                id="mnemonic"
                type="text"
                placeholder="Enter your BIP39 mnemonic..."
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                className="font-mono"
              />
              <p className="text-xs text-slate-500">
                Only the public addresses are sent to the server for analysis
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>Derivation Path</Label>
                <select
                  className="w-full px-3 py-2 border border-slate-300 rounded-md"
                  value={derivationType}
                  onChange={(e) => setDerivationType(e.target.value)}
                >
                  {derivationTypes.map(type => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-2">
                <Label>Address Count</Label>
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={addressCount}
                  onChange={(e) => setAddressCount(parseInt(e.target.value) || 10)}
                />
              </div>
            </div>

            <Button type="submit" disabled={loading}>
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Deriving...
                </>
              ) : (
                <>
                  <Send className="w-4 h-4 mr-2" />
                  Derive Addresses
                </>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {derivedAddresses.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Derived Addresses ({derivedAddresses.length})</CardTitle>
            <CardDescription>Public keys derived from your mnemonic</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {derivedAddresses.map((addr, idx) => (
                <div 
                  key={idx} 
                  className="flex items-center justify-between p-3 border rounded-md bg-slate-50"
                >
                  <div className="space-y-1">
                    <p className="font-mono text-sm break-all">{addr.address}</p>
                    <p className="text-xs text-slate-500">Path: {addr.path}</p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => copyAddress(addr.address)}
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function RefreshCw({ className }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M23 4v6h-6"></path>
    <path d="M1 20v-6h6"></path>
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
  </svg>
}