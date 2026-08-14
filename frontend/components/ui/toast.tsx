"use client"

import * as React from "react"
import {
 .forwardRef,
  useCallback,
  useRef,
} from "react"
import {
  CheckCircle,
  ChevronRight,
  CrossedInterrupts,
  X,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"

export interface ToastProps {
  id: string
  title?: React.ReactNode
  description?: React.ReactNode
  action?: React.ReactNode
  variant?: "default" | "destructive"
}

const ToastViewport = React.forwardRef<
  React.ElementRef<typeof div>,
  React.ComponentPropsWithoutRef<typeof div>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "fixed top-0 z-[100] flex flex-col max-w-sm w-full gap-4 p-4",
      className
    )}
    {...props}
  />
))
ToastViewport.displayName = "ToastViewport"

const Toast = React.forwardRef<
  React.ElementRef<typeof div>,
  React.ComponentPropsWithoutRef<typeof div> & {
    open?: boolean
    onClose?: () => void
  }
>(({ className, title, message, action, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn(
        "flex items-center justify-between p-4 rounded-lg shadow-lg border",
        "bg-background text-foreground",
        "data-[swipe-degree] slide-in-to-right-0",
        "data-[state=open]:animate-in",
        "data-[state=closed]:animate-out",
        "data-[state=closed]:fade-out-0",
        "data-[state=open]:fade-in-0",
        className
      )}
      {...props}
    >
      <div className="grid gap-1 w-full">
        {title && <div className="font-semibold">{title}</div>}
        {message && <div className="text-sm opacity-90">{message}</div>}
      </div>
      {action}
    </div>
  )
})
Toast.displayName = "Toast"

export { Toast, ToastViewport }