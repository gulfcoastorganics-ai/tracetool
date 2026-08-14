'use client'

import { useState } from 'react'
import { Check, Copy } from 'lucide-react'

interface DerivedAddress {
  path: string
  address: string
  label: string
  chain_type: string
}

interface AddressListProps {
  addresses: DerivedAddress[]
  derivationType: string
}

export function AddressList({ addresses, derivationType }: AddressListProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const copyToClipboard = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  if (!addresses || addresses.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Derived Addresses</CardTitle>
          <CardDescription>No addresses to display</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Derived Addresses ({addresses.length})</CardTitle>
        <CardDescription>Public keys derived from your mnemonic</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {addresses.map((addr, idx) => (
            <div 
              key={idx} 
              className="flex items-center justify-between p-3 border rounded-md"
            >
              <div className="space-y-1">
                <p className="font-mono text-sm">{addr.address}</p>
                <p className="text-xs text-slate-500">
                  Path: {addr.path}
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => copyToClipboard(addr.address, addr.address)}
              >
                {copiedId === addr.address ? (
                  <Check className="w-4 h-4 text-green-500" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </Button>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'