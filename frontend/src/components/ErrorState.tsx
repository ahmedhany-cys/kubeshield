import type { ReactNode } from 'react'
import { TriangleAlert, PlugZap, RotateCw, ShieldOff } from 'lucide-react'
import { ApiError, errorMessage } from '../api/client'
import { cx } from '../lib/format'
import { Button } from './Button'

export function ErrorState({ error, onRetry, compact }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const forbidden = error instanceof ApiError && error.status === 403
  return (
    <div
      className={cx(
        'flex items-start gap-3 rounded-md border border-bad/30 bg-bad/[0.06] text-[13px]',
        compact ? 'p-3' : 'p-4',
      )}
      role="alert"
    >
      {forbidden ? (
        <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-bad" />
      ) : (
        <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-bad" />
      )}
      <div className="min-w-0 flex-1">
        <p className="font-medium text-fg">{forbidden ? 'Not permitted' : 'Request failed'}</p>
        <p className="mt-0.5 break-words text-muted">{errorMessage(error)}</p>
      </div>
      {onRetry && (
        <Button size="sm" variant="ghost" icon={<RotateCw className="h-3.5 w-3.5" />} onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}

/** Integration or data source that is not available (not an error in the UI itself). */
export function UnavailableState({
  title,
  detail,
  children,
  label = 'Unavailable',
}: {
  title: string
  detail?: string | null
  children?: ReactNode
  label?: string
}) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-warn/30 bg-warn/[0.05] p-4 text-[13px]">
      <PlugZap className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
      <div className="min-w-0 flex-1">
        <p className="font-medium text-fg">
          <span className="mr-2 rounded border border-warn/40 px-1.5 py-px text-[10.5px] font-semibold uppercase tracking-wide text-warn">
            {label}
          </span>
          {title}
        </p>
        {detail && <p className="mono mt-1.5 break-words text-muted">{detail}</p>}
        {children && <div className="mt-2 text-muted">{children}</div>}
      </div>
    </div>
  )
}

export function InlineError({ message }: { message: string | null | undefined }) {
  if (!message) return null
  return (
    <p className="mt-2 flex items-start gap-1.5 text-[12.5px] text-bad" role="alert">
      <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span className="break-words">{message}</span>
    </p>
  )
}
