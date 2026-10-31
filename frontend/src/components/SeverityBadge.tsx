import type { Severity } from '../api/types'
import { cx } from '../lib/format'
import { Badge, type Tone } from './Badge'

const KNOWN: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function severityTone(sev: string | null | undefined): Tone {
  return sev && (KNOWN as string[]).includes(sev) ? (sev as Tone) : 'neutral'
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#f05252',
  high: '#f97316',
  medium: '#f5b83d',
  low: '#4f9cf9',
  info: '#8a94a6',
}

export function SeverityBadge({ severity, className }: { severity: string | null | undefined; className?: string }) {
  if (!severity) return <span className="text-subtle">—</span>
  return (
    <Badge tone={severityTone(severity)} className={cx('uppercase tracking-wide', className)}>
      {severity}
    </Badge>
  )
}

/** Compact row of severity counts, e.g. for image scans. */
export function SeverityCounts({
  counts,
  show = ['critical', 'high', 'medium', 'low'],
}: {
  counts: Partial<Record<Severity, number>> | null | undefined
  show?: Severity[]
}) {
  return (
    <div className="flex items-center gap-1">
      {show.map((s) => {
        const n = counts?.[s] ?? 0
        return (
          <span
            key={s}
            title={`${s}: ${n}`}
            className={cx(
              'inline-flex h-5 min-w-7 items-center justify-center rounded px-1 text-[11px] font-semibold tabular-nums',
              n === 0 ? 'bg-white/[0.03] text-subtle' : '',
            )}
            style={n > 0 ? { backgroundColor: `${SEVERITY_COLORS[s]}22`, color: SEVERITY_COLORS[s] } : undefined}
          >
            {n}
          </span>
        )
      })}
    </div>
  )
}
