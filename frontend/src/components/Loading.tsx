import { LoaderCircle } from 'lucide-react'
import { cx } from '../lib/format'

export function Loading({ label = 'Loading…', className }: { label?: string; className?: string }) {
  return (
    <div className={cx('flex items-center justify-center gap-2 py-10 text-[13px] text-subtle', className)}>
      <LoaderCircle className="h-4 w-4 animate-spin" />
      {label}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('animate-pulse rounded bg-white/[0.04]', className)} />
}
