'use client'

import { useEffect, useState } from 'react'
import { 
  AlertCircle,
  CheckCircle2,
  Radio
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface NetworkStatusProps {
  className?: string
}

export function NetworkStatus({ className }: NetworkStatusProps) {
  const [apiOnline, setApiOnline] = useState(false)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    checkApiStatus()
    const interval = setInterval(checkApiStatus, 30000)
    return () => clearInterval(interval)
  }, [])

  const checkApiStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/')
      setApiOnline(response.ok)
    } catch {
      setApiOnline(false)
    } finally {
      setChecking(false)
    }
  }

  if (checking) {
    return (
      <div className={cn('flex items-center gap-2 text-sm', className)}>
        <Radio className="w-4 h-4 animate-pulse" />
        <span className="text-slate-500">Checking connection...</span>
      </div>
    )
  }

  return (
    <div className={cn('flex items-center gap-2 text-sm', className)}>
      {apiOnline ? (
        <>
          <CheckCircle2 className="w-4 h-4 text-green-500" />
          <span className="text-green-600">Connected to local API</span>
        </>
      ) : (
        <>
          <AlertCircle className="w-4 h-4 text-amber-500" />
          <span className="text-amber-600">API offline - running in local mode</span>
        </>
      )}
    </div>
  )
}