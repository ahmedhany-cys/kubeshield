import type { ReactNode } from 'react'
import { cx } from '../lib/format'

export function Card({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
  flush,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
  /** Remove body padding (for tables). */
  flush?: boolean
}) {
  return (
    <section className={cx('min-w-0 rounded-lg border border-border bg-surface', className)}>
      {(title || actions) && (
        <header className="flex min-h-11 flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-2">
          <div className="min-w-0">
            {title && <h2 className="truncate text-[13px] font-semibold text-fg">{title}</h2>}
            {subtitle && <p className="truncate text-[12px] text-subtle">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx(flush ? '' : 'p-4', bodyClassName)}>{children}</div>
    </section>
  )
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-[20px] font-semibold tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-[13px] text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Section({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <div className={cx('mb-5', className)}>
      <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-subtle">{title}</h3>
      {children}
    </div>
  )
}
