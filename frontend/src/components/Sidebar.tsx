import { NavLink } from 'react-router-dom'
import {
  Activity,
  Bug,
  Crosshair,
  FileCheck,
  Grid3x3,
  LayoutDashboard,
  Network,
  Server,
  Settings,
  ShieldAlert,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { cx } from '../lib/format'
import { Logo } from './Logo'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  end?: boolean
}

const GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Monitor',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
      { to: '/threats', label: 'Runtime Threats', icon: Activity },
      { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
    ],
  },
  {
    label: 'Posture',
    items: [
      { to: '/cluster', label: 'Kubernetes Cluster', icon: Server },
      { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
      { to: '/network', label: 'Network Security', icon: Network },
      { to: '/policies', label: 'Policy Violations', icon: FileCheck },
    ],
  },
  {
    label: 'Validate',
    items: [
      { to: '/simulations', label: 'Attack Simulation', icon: Crosshair },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Grid3x3 },
    ],
  },
  {
    label: 'Respond',
    items: [
      { to: '/responses', label: 'Response History', icon: Zap },
      { to: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]

export function Sidebar({ onNavigate, version }: { onNavigate?: () => void; version?: string }) {
  return (
    <nav className="flex h-full w-60 flex-col border-r border-border bg-surface" aria-label="Main">
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-border px-4">
        <Logo />
        <div className="leading-tight">
          <div className="text-[14px] font-semibold tracking-tight text-fg">KubeShield</div>
          <div className="text-[10.5px] uppercase tracking-wider text-subtle">Runtime Security</div>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto px-2 py-3">
        {GROUPS.map((g) => (
          <div key={g.label} className="mb-4">
            <div className="px-2.5 pb-1.5 text-[10.5px] font-semibold uppercase tracking-wider text-subtle">{g.label}</div>
            <ul className="space-y-0.5">
              {g.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cx(
                        'group flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] font-medium transition-colors',
                        isActive
                          ? 'bg-accent/10 text-fg shadow-[inset_2px_0_0_var(--color-accent)]'
                          : 'text-muted hover:bg-white/[0.04] hover:text-fg',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <item.icon className={cx('h-4 w-4 shrink-0', isActive ? 'text-accent' : 'text-subtle group-hover:text-muted')} />
                        <span className="truncate">{item.label}</span>
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="shrink-0 border-t border-border px-4 py-3 text-[11px] text-subtle">
        <div>KubeShield{version ? ` v${version}` : ''}</div>
        <a
          href="https://github.com/ahmedhany-cys/kubeshield"
          target="_blank"
          rel="noreferrer noopener"
          className="hover:text-muted"
        >
          github.com/ahmedhany-cys/kubeshield
        </a>
      </div>
    </nav>
  )
}
