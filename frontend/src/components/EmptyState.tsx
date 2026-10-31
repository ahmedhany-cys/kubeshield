import type { ReactNode } from 'react'
import { Inbox } from 'lucide-react'
import { cx } from '../lib/format'

export function EmptyState({
  title,
  description,
  icon,
  action,
  compact,
}: {
  title: string
  description?: ReactNode
  icon?: ReactNode
  action?: ReactNode
  compact?: boolean
}) {
  return (
    <div className={cx('flex flex-col items-center justify-center text-center', compact ? 'px-4 py-6' : 'px-6 py-12')}>
      <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-full border border-border bg-surface-2 text-subtle">
        {icon ?? <Inbox className="h-4 w-4" />}
      </div>
      <p className="text-[13px] font-medium text-fg">{title}</p>
      {description && <p className="mt-1 max-w-md text-[12.5px] text-muted">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
