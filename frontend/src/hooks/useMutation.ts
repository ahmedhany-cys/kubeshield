import { useCallback, useState } from 'react'
import { errorMessage } from '../api/client'

/** Wrap a state-changing API call with pending/error state. */
export function useMutation<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = useCallback(
    async (...args: A): Promise<R | undefined> => {
      setPending(true)
      setError(null)
      try {
        return await fn(...args)
      } catch (err) {
        setError(errorMessage(err))
        return undefined
      } finally {
        setPending(false)
      }
    },
    [fn],
  )

  return { run, pending, error, setError }
}
