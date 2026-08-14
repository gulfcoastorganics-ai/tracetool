"use client"

import { createContext, useContext } from 'react'
import { useTheme } from 'next-themes'

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const { theme, setTheme } = useTheme()
  
  return (
    <ThemeProviderContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeProviderContext.Provider>
  )
}

const ThemeProviderContext = createContext<{
  theme: string | undefined
  setTheme: (theme: string) => void
}>({
  theme: 'system',
  setTheme: () => null,
})

export const useTheme = () => {
  const context = useContext(ThemeProviderContext)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}