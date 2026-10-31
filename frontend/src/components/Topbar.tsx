import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, CircleUser, LogOut, Menu, ShieldCheck } from 'lucide-react'
import type { SystemStatus } from '../api/types'
import { useAuth } from '../hooks/useAuth'
import { cx, relativeTime } from '../lib/format'
import { Badge, Dot, type Tone } from './Badge'

function clusterHealth(status: SystemStatus | undefined, error: unknown): { tone: Tone; label: string; detail: string } {
  if (error && !status) return { tone: 'bad', label: 'Status unavailable', detail: 'Could not load /system/status' }
  if (!status) return { tone: 'neutral', label: 'Checking cluster…', detail: '' }
  if (!status.kubernetes.reachable) {
    return { tone: 'bad', label: 'Cluster unreachable', detail: status.kubernetes.error ?? 'Kubernetes API not reachable' }
  }
  const ints = status.integrations
  const healthy = ints.filter((i) => i.state === 'healthy').length
  const degraded = ints.filter((i) => i.state === 'degraded' || i.state === 'unknown').length
  const detail = ints.length
    ? `${healthy}/${ints.length} integrations healthy`
    : 'No integration inventory yet'
  if (degraded > 0) return { tone: 'warn', label: 'Cluster degraded', detail }
  return { tone: 'ok', label: 'Cluster connected', detail }
}

export function Topbar({
  status,
  statusError,
  pendingApprovals,
  onMenu,
}: {
  status: SystemStatus | undefined
  statusError: unknown
  pendingApprovals: number | undefined
  onMenu: () => void
}) {
  const { user, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const health = clusterHealth(status, statusError)

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-3 border-b border-border bg-bg/90 px-4 backdrop-blur lg:px-6">
      <button
        type="button"
        onClick={onMenu}
        className="flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-white/[0.05] hover:text-fg lg:hidden"
        aria-label="Open navigation"
      >
        <Menu className="h-4.5 w-4.5" />
      </button>

      <Link
        to="/settings#system"
        className="flex min-w-0 items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5 text-[12.5px] hover:border-border-strong"
        title={health.detail}
      >
        <span className="relative flex h-2 w-2">
          <Dot tone={health.tone} />
        </span>
        <span className="font-medium text-fg">{health.label}</span>
        {health.detail && <span className="hidden truncate text-subtle md:inline">· {health.detail}</span>}
        {status?.kubernetes.mode && <span className="hidden text-subtle xl:inline">· mode {status.kubernetes.mode}</span>}
      </Link>

      {status?.falco.last_event_ingested_at && (
        <span className="hidden text-[12px] text-subtle xl:inline" title="Last Falco event ingested">
          Falco last event {relativeTime(status.falco.last_event_ingested_at)}
        </span>
      )}

      <div className="ml-auto flex items-center gap-3">
        {pendingApprovals !== undefined && pendingApprovals > 0 && (
          <Link to="/responses?status=pending_approval" className="hidden sm:block">
            <Badge tone="warn" dot>
              {pendingApprovals} pending approval{pendingApprovals === 1 ? '' : 's'}
            </Badge>
          </Link>
        )}
        <div className="relative" ref={menuRef}>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="flex h-8 items-center gap-2 rounded-md px-2 text-[13px] text-muted hover:bg-white/[0.05] hover:text-fg"
            aria-haspopup="menu"
            aria-expanded={open}
          >
            <CircleUser className="h-4.5 w-4.5" />
            <span className="hidden font-medium text-fg sm:inline">{user?.username}</span>
            <Badge tone={user?.role === 'admin' ? 'accent' : 'neutral'} className="capitalize">
              {user?.role}
            </Badge>
            <ChevronDown className="h-3.5 w-3.5" />
          </button>
          {open && (
            <div
              role="menu"
              className="absolute right-0 mt-1.5 w-60 rounded-lg border border-border-strong bg-surface-2 p-1 shadow-2xl shadow-black/50"
            >
              <div className="px-3 py-2.5">
                <div className="text-[13px] font-medium text-fg">{user?.username}</div>
                <div className="mt-0.5 flex items-center gap-1.5 text-[12px] text-subtle">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span className="capitalize">{user?.role}</span> role
                </div>
                <p className="mt-2 text-[11.5px] leading-snug text-subtle">
                  {user?.role === 'admin'
                    ? 'Full access, including destructive responses, playbooks and settings.'
                    : user?.role === 'responder'
                      ? 'Can run simulations, scans and non-destructive responses.'
                      : 'Read-only access.'}
                </p>
              </div>
              <div className="my-1 h-px bg-border" />
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false)
                  void logout()
                }}
                className={cx('flex w-full items-center gap-2 rounded-md px-3 py-2 text-[13px] text-muted hover:bg-white/[0.05] hover:text-fg')}
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
