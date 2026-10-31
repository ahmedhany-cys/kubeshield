import type { ReactNode } from 'react'
import { formatNumber } from '../lib/format'

export interface BarItem {
  key: string
  label: ReactNode
  value: number
  color?: string
  href?: string
}

/** Horizontal proportional bars for categorical counts. */
export function BarList({ items, empty }: { items: BarItem[]; empty?: ReactNode }) {
  if (items.length === 0) return <>{empty ?? <p className="text-[12.5px] text-subtle">No data.</p>}</>
  const max = Math.max(...items.map((i) => i.value), 1)
  return (
    <ul className="space-y-2.5">
      {items.map((i) => (
        <li key={i.key} className="min-w-0">
          <div className="mb-1 flex items-baseline justify-between gap-3 text-[12.5px]">
            <span className="min-w-0 truncate text-muted">{i.label}</span>
            <span className="shrink-0 font-medium tabular-nums text-fg">{formatNumber(i.value)}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
            <div
              className="h-full rounded-full"
              style={{ width: `${Math.max(2, (i.value / max) * 100)}%`, backgroundColor: i.color ?? 'var(--color-accent)' }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}
