import type { Integration } from '../api/types'
import { StatusBadge } from './Badge'

export function IntegrationList({ items }: { items: Integration[] }) {
  return (
    <ul className="divide-y divide-border">
      {items.map((i) => (
        <li key={i.key} className="flex items-start justify-between gap-3 py-2.5 first:pt-0 last:pb-0">
          <div className="min-w-0">
            <div className="truncate text-[13px] font-medium text-fg">{i.title}</div>
            <div className="truncate font-mono text-[11.5px] text-subtle">
              {i.namespace}/{i.kind}/{i.name}
            </div>
            {i.error && <div className="mt-0.5 text-[11.5px] text-bad">{i.error}</div>}
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1">
            <StatusBadge status={i.state} />
            {i.installed && i.desired !== undefined && (
              <span className="text-[11px] tabular-nums text-subtle">
                {i.ready ?? 0}/{i.desired} ready
              </span>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}
