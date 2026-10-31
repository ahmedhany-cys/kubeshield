import { Link } from 'react-router-dom'
import type { AuditEntry } from '../api/types'
import { formatDateTime, parseDate } from '../lib/format'
import { Badge, type Tone } from './Badge'
import type { Column } from './DataTable'
import { Time } from './Time'

function actionTone(action: string): Tone {
  if (/failed|refused|rejected|login_failed|deleted/.test(action)) return 'bad'
  if (/succeeded|resolved|login$/.test(action)) return 'ok'
  if (/pending|requested|changed|updated/.test(action)) return 'warn'
  return 'neutral'
}

function detailsText(details: unknown): string {
  if (details === null || details === undefined) return ''
  if (typeof details === 'object' && Object.keys(details as object).length === 0) return ''
  return JSON.stringify(details)
}

export function auditColumns(opts: { showIncident?: boolean } = {}): Column<AuditEntry>[] {
  const cols: Column<AuditEntry>[] = [
    { key: 'time', header: 'Time', render: (a) => <Time value={a.timestamp} absolute />, sortValue: (a) => parseDate(a.timestamp)?.getTime() ?? 0 },
    { key: 'actor', header: 'Actor', render: (a) => <span className="font-medium text-fg">{a.actor}</span>, sortValue: (a) => a.actor },
    { key: 'action', header: 'Action', render: (a) => <Badge tone={actionTone(a.action)}><span className="font-mono">{a.action}</span></Badge>, sortValue: (a) => a.action },
    { key: 'target', header: 'Target', render: (a) => <span className="block max-w-[280px] truncate font-mono text-[12px] text-muted" title={a.target ?? undefined}>{a.target ?? '—'}</span> },
  ]
  if (opts.showIncident) {
    cols.push({
      key: 'incident',
      header: 'Incident',
      render: (a) => (a.incident_id ? <Link className="link font-mono text-[12px]" to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()}>#{a.incident_id}</Link> : <span className="text-subtle">—</span>),
    })
  }
  cols.push(
    {
      key: 'details',
      header: 'Details',
      render: (a) => {
        const t = detailsText(a.details)
        return t ? <span className="line-clamp-2 block max-w-[380px] break-all font-mono text-[11px] text-subtle" title={t}>{t}</span> : <span className="text-subtle">—</span>
      },
    },
    { key: 'ip', header: 'Source IP', render: (a) => <span className="font-mono text-[11.5px] text-subtle">{a.source_ip ?? '—'}</span> },
  )
  return cols
}

/** Compact vertical audit trail for an incident. */
export function AuditTrail({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0) return <p className="text-[12.5px] text-subtle">No audit entries for this incident yet.</p>
  return (
    <ol className="relative space-y-3 border-l border-border pl-4">
      {entries.map((a) => {
        const t = detailsText(a.details)
        return (
          <li key={a.id} className="relative">
            <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full border border-border-strong bg-surface-3" />
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px]">
              <Badge tone={actionTone(a.action)}><span className="font-mono">{a.action}</span></Badge>
              <span className="font-medium text-fg">{a.actor}</span>
              <span className="text-subtle" title={formatDateTime(a.timestamp)}>{formatDateTime(a.timestamp)}</span>
            </div>
            {a.target && <div className="mt-0.5 font-mono text-[11.5px] text-muted">{a.target}</div>}
            {t && <div className="mt-0.5 break-all font-mono text-[11px] text-subtle">{t}</div>}
          </li>
        )
      })}
    </ol>
  )
}
