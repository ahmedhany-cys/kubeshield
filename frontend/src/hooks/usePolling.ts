import { useEffect, useRef } from 'react'

/** Call `callback` every `interval` ms while `active` is true and the tab is visible. */
export function usePolling(callback: () => void, interval: number, active = true): void {
  const saved = useRef(callback)
  saved.current = callback
  useEffect(() => {
    if (!active) return
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') saved.current()
    }, interval)
    return () => window.clearInterval(id)
  }, [interval, active])
}
