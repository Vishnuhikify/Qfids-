import { useEffect, useState, useCallback } from 'react'

/**
 * Theme manager. Reads the initial theme from <html data-theme="...">
 * (set inline before paint by index.html), persists changes to
 * localStorage, and exposes a toggle.
 */
export function useTheme() {
  const [theme, setTheme] = useState(() => {
    if (typeof document === 'undefined') return 'dark'
    return document.documentElement.getAttribute('data-theme') || 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try {
      localStorage.setItem('qfids-theme', theme)
    } catch {}
  }, [theme])

  const toggle = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
  }, [])

  return { theme, setTheme, toggle }
}
