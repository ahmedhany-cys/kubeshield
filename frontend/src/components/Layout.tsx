import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { api } from '../api/client'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export function Layout() {
  const [navOpen, setNavOpen] = useState(false)
  const location = useLocation()
  const { user } = useAuth()
  const status = useApi((s) => api.systemStatus(s), [], { interval: 30_000, enabled: Boolean(user) })
  const pending = useApi((s) => api.responses({ status: 'pending_approval', limit: 100 }, s), [], {
    interval: 30_000,
    enabled: Boolean(user),
  })

  useEffect(() => setNavOpen(false), [location.pathname])

  return (
    <div className="flex h-full">
      <div className="hidden shrink-0 lg:block">
        <div className="sticky top-0 h-screen">
          <Sidebar version={status.data?.version} />
        </div>
      </div>
      {navOpen && (
        <div className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-black/60" onClick={() => setNavOpen(false)} />
          <div className="relative h-full w-60">
            <Sidebar version={status.data?.version} onNavigate={() => setNavOpen(false)} />
          </div>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          status={status.data}
          statusError={status.error}
          pendingApprovals={pending.data?.total}
          onMenu={() => setNavOpen(true)}
        />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 lg:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
