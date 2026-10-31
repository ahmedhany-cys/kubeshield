import type { ReactNode } from 'react'
import { cx } from '../lib/format'

export interface KV {
  label: string
  value: ReactNode
  mono?: boolean
  hidden?: boolean
}

export function KeyValueGrid({ items, columns = 2 }: { items: KV[]; columns?: 1 | 2 | 3 }) {
  const cols = columns === 1 ? 'sm:grid-cols-1' : columns === 3 ? 'sm:grid-cols-3' : 'sm:grid-cols-2'
  return (
    <dl className={cx('grid grid-cols-1 gap-x-6 gap-y-3', cols)}>
      {items
        .filter((i) => !i.hidden)
        .map((i) => (
          <div key={i.label} className="min-w-0">
            <dt className="text-[11px] font-medium uppercase tracking-wide text-subtle">{i.label}</dt>
            <dd className={cx('mt-0.5 break-words text-[13px] text-fg', i.mono && 'font-mono text-[12.5px]')}>
              {i.value === null || i.value === undefined || i.value === '' ? <span className="text-subtle">—</span> : i.value}
            </dd>
          </div>
        ))}
    </dl>
  )
}

/** Table of arbitrary key/value pairs (evidence, observed data). */
export function KeyValueTable({ data }: { data: Record<string, unknown> | null | undefined }) {
  const entries = Object.entries(data ?? {})
  if (entries.length === 0) return <p className="text-[12.5px] text-subtle">None recorded.</p>
  return (
    <div className="overflow-hidden rounded-md border border-border">
      <table className="w-full text-[12.5px]">
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k} className="border-b border-border last:border-0">
              <td className="w-[38%] bg-surface-2 px-3 py-1.5 align-top font-mono text-[11.5px] text-muted">{k}</td>
              <td className="break-all px-3 py-1.5 font-mono text-[11.5px] text-fg">
                {typeof v === 'string' ? v : JSON.stringify(v)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
