"use client"

import * as React from "react"
import { useState, useCallback } from "react"
import { ToastProvider, useToast } from "@/components/ui/toast"

type Toast = {
  id: string
  title?: React.ReactNode
  description?: React.ReactNode
  action?: React.ReactNode
  variant?: "default" | "destructive"
}

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const toast = useCallback(
    ({
      title,
      description,
      action,
      variant = "default",
      duration = 5000,
    }: {
      title?: React.ReactNode
      description?: React.ReactNode
      action?: React.ReactNode
      variant?: "default" | "destructive"
      duration?: number
    }) => {
      const id = Math.random().toString(36).slice(2, 9)
      setToasts((prev) => [...prev, { id, title, description, action, variant }])
      
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id))
      }, duration)
    },
    []
  )

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return { toast, dismiss, toasts }
}

export { ToastProvider }