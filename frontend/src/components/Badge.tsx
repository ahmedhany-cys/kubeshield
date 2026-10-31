import type { ReactNode } from 'react'
import { cx } from '../lib/format'

export type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'bad' | 'critical' | 'high' | 'medium' | 'low' | 'info'

const TONES: Record<Tone, string> = {
  neutral: 'bg-white/[0.04] text-muted border-white/10',
  accent: 'bg-accent/10 text-accent border-accent/30',
  ok: 'bg-ok/10 text-ok border-ok/30',
  warn: 'bg-warn/10 text-warn border-warn/30',
  bad: 'bg-bad/10 text-bad border-bad/30',
  critical: 'bg-sev-critical/15 text-sev-critical border-sev-critical/40',
  high: 'bg-sev-high/12 text-sev-high border-sev-high/40',
  medium: 'bg-sev-medium/12 text-sev-medium border-sev-medium/40',
  low: 'bg-sev-low/12 text-sev-low border-sev-low/40',
  info: 'bg-sev-info/10 text-sev-info border-sev-info/30',
}

const DOTS: Record<Tone, string> = {
  neutral: 'bg-subtle',
  accent: 'bg-accent',
  ok: 'bg-ok',
  warn: 'bg-warn',
  bad: 'bg-bad',
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}

export function Badge({
  tone = 'neutral',
  children,
  dot,
  title,
  className,
}: {
  tone?: Tone
  children: ReactNode
  dot?: boolean
  title?: string
  className?: string
}) {
  return (
    <span
      title={title}
      className={cx(
        'inline-flex h-5 shrink-0 items-center gap-1.5 whitespace-nowrap rounded border px-1.5 text-[11px] font-medium leading-none',
        TONES[tone],
        className,
      )}
    >
      {dot && <span className={cx('h-1.5 w-1.5 rounded-full', DOTS[tone])} />}
      {children}
    </span>
  )
}

export function Dot({ tone, className }: { tone: Tone; className?: string }) {
  return <span className={cx('inline-block h-2 w-2 shrink-0 rounded-full', DOTS[tone], className)} />
}

const STATUS_TONES: Record<string, Tone> = {
  // incidents
  open: 'bad',
  investigating: 'warn',
  contained: 'accent',
  resolved: 'ok',
  false_positive: 'neutral',
  // response actions
  pending_approval: 'warn',
  approved: 'accent',
  executing: 'accent',
  succeeded: 'ok',
  failed: 'bad',
  rejected: 'neutral',
  refused: 'bad',
  alerted: 'info',
  // scans / runs
  queued: 'neutral',
  running: 'accent',
  completed: 'ok',
  error: 'bad',
  // integrations
  healthy: 'ok',
  degraded: 'warn',
  not_installed: 'neutral',
  unknown: 'neutral',
  // policy
  blocked: 'bad',
  denied: 'bad',
  allowed: 'ok',
  skipped: 'neutral',
  fail: 'bad',
  warn: 'warn',
  pass: 'ok',
  scanned: 'ok',
  invalid: 'bad',
  not_scanned: 'neutral',
  // outcomes
  detected: 'ok',
  partial: 'warn',
  missed: 'bad',
  // flows
  FORWARDED: 'ok',
  DROPPED: 'bad',
  AUDIT: 'warn',
  ERROR: 'bad',
}

const STATUS_LABELS: Record<string, string> = {
  pending_approval: 'Pending approval',
  false_positive: 'False positive',
  not_installed: 'Not installed',
  alert_only: 'Alert only',
}

export function statusTone(status: string | null | undefined): Tone {
  return (status && STATUS_TONES[status]) || 'neutral'
}

export function StatusBadge({ status, label }: { status: string | null | undefined; label?: string }) {
  if (!status) return <span className="text-subtle">—</span>
  const text = label ?? STATUS_LABELS[status] ?? status.replace(/_/g, ' ')
  return (
    <Badge tone={statusTone(status)} dot>
      <span className={status === status.toUpperCase() ? '' : 'capitalize'}>{text}</span>
    </Badge>
  )
}
