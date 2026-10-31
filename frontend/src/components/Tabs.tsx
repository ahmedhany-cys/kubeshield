import type { ReactNode } from 'react'
import { cx } from '../lib/format'

export interface TabDef<K extends string> {
  key: K
  label: ReactNode
  count?: number
}

export function Tabs<K extends string>({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: TabDef<K>[]
  value: K
  onChange: (k: K) => void
  className?: string
}) {
  return (
    <div className={cx('flex gap-1 overflow-x-auto border-b border-border', className)} role="tablist">
      {tabs.map((t) => {
        const active = t.key === value
        return (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.key)}
            className={cx(
              '-mb-px flex shrink-0 items-center gap-2 border-b-2 px-3 py-2 text-[13px] font-medium transition-colors',
              active ? 'border-accent text-fg' : 'border-transparent text-muted hover:text-fg',
            )}
          >
            {t.label}
            {t.count !== undefined && (
              <span
                className={cx(
                  'rounded px-1.5 py-px text-[11px] tabular-nums',
                  active ? 'bg-accent/15 text-accent' : 'bg-white/[0.05] text-subtle',
                )}
              >
                {t.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
