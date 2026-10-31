import { useCallback, useEffect, useRef, useState } from 'react'

export interface ApiState<T> {
  data: T | undefined
  error: unknown
  loading: boolean
  /** True only for the first load (no data yet). */
  initialLoading: boolean
  lastUpdated: Date | null
  reload: () => void
}

export interface UseApiOptions {
  /** Poll interval in milliseconds. Polling pauses while the tab is hidden. */
  interval?: number
  /** Skip fetching entirely (e.g. until a selection exists). */
  enabled?: boolean
}

/**
 * Fetch data from the API, re-fetching when `deps` change and optionally on an interval.
 * Previous data is kept while a refresh is in flight so tables do not flicker.
 */
export function useApi<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
  options: UseApiOptions = {},
): ApiState<T> {
  const { interval, enabled = true } = options
  const [data, setData] = useState<T | undefined>(undefined)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState<boolean>(enabled)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [tick, setTick] = useState(0)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  // Reset data when the query identity changes.
  const depsKey = JSON.stringify(deps)
  const prevKey = useRef(depsKey)
  useEffect(() => {
    if (prevKey.current !== depsKey) {
      prevKey.current = depsKey
      setData(undefined)
      setError(null)
    }
  }, [depsKey])

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return
    }
    const controller = new AbortController()
    setLoading(true)
    fetcherRef
      .current(controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return
        setData(result)
        setError(null)
        setLastUpdated(new Date())
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        if (err instanceof DOMException && err.name === 'AbortError') return
        setError(err)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [depsKey, tick, enabled])

  useEffect(() => {
    if (!interval || !enabled) return
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') setTick((t) => t + 1)
    }, interval)
    return () => window.clearInterval(id)
  }, [interval, enabled])

  const reload = useCallback(() => setTick((t) => t + 1), [])

  return { data, error, loading, initialLoading: loading && data === undefined, lastUpdated, reload }
}
