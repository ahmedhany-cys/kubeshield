import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { cx } from '../lib/format'

export function StatCard({
  label,
  value,
  sub,
  icon,
  to,
  tone,
  children,
}: {
  label: string
  value: ReactNode
  sub?: ReactNode
  icon?: ReactNode
  to?: string
  tone?: 'bad' | 'warn' | 'ok' | 'neutral'
  children?: ReactNode
}) {
  const valueTone =
    tone === 'bad' ? 'text-sev-critical' : tone === 'warn' ? 'text-sev-high' : tone === 'ok' ? 'text-ok' : 'text-fg'
  const inner = (
    <>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] font-medium text-muted">{label}</span>
        {icon && <span className="text-subtle">{icon}</span>}
      </div>
      <div className={cx('mt-2 text-[26px] font-semibold leading-none tracking-tight tabular-nums', valueTone)}>
        {value}
      </div>
      {sub && <div className="mt-2 text-[12px] text-subtle">{sub}</div>}
      {children && <div className="mt-3">{children}</div>}
    </>
  )
  const cls = 'block min-w-0 rounded-lg border border-border bg-surface p-4'
  return to ? (
    <Link to={to} className={cx(cls, 'transition-colors hover:border-border-strong hover:bg-surface-2')}>
      {inner}
    </Link>
  ) : (
    <div className={cls}>{inner}</div>
  )
}
