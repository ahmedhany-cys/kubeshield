import { formatDateTime, relativeTime } from '../lib/format'

/** Relative time with the absolute timestamp as a tooltip. */
export function Time({ value, absolute }: { value: string | null | undefined; absolute?: boolean }) {
  if (!value) return <span className="text-subtle">—</span>
  return (
    <time dateTime={value} title={formatDateTime(value)} className="whitespace-nowrap tabular-nums">
      {absolute ? formatDateTime(value) : relativeTime(value)}
    </time>
  )
}
