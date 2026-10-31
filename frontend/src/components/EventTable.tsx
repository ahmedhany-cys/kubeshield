import type { SecurityEvent } from '../api/types'
import { SEVERITIES } from '../api/types'
import { parseDate } from '../lib/format'
import { Badge } from './Badge'
import type { Column } from './DataTable'
import { SeverityBadge } from './SeverityBadge'
import { Time } from './Time'

const sevRank = (s: string) => {
  const i = (SEVERITIES as string[]).indexOf(s)
  return i === -1 ? 9 : 4 - i
}

export function eventColumns(opts: { compact?: boolean } = {}): Column<SecurityEvent>[] {
  const cols: Column<SecurityEvent>[] = [
    {
      key: 'severity',
      header: 'Severity',
      render: (e) => <SeverityBadge severity={e.severity} />,
      sortValue: (e) => sevRank(e.severity),
      className: 'w-24',
    },
    {
      key: 'detection',
      header: 'Detection',
      render: (e) => (
        <div className="min-w-0 max-w-[420px]">
          <div className="truncate font-medium text-fg">{e.detection ?? e.rule}</div>
          <div className="truncate text-[12px] text-subtle" title={e.message ?? undefined}>
            {e.rule_id && <span className="mr-1.5 font-mono">{e.rule_id}</span>}
            {e.message}
          </div>
        </div>
      ),
      sortValue: (e) => e.detection ?? e.rule,
    },
    {
      key: 'workload',
      header: 'Namespace / Pod',
      render: (e) => (
        <div className="min-w-0 max-w-[260px]">
          <div className="truncate text-fg">{e.namespace ?? <span className="text-subtle">—</span>}</div>
          <div className="truncate font-mono text-[11.5px] text-subtle">{e.pod ?? ''}</div>
        </div>
      ),
      sortValue: (e) => `${e.namespace ?? ''}/${e.pod ?? ''}`,
    },
    {
      key: 'source',
      header: 'Source',
      render: (e) => <Badge>{e.source}</Badge>,
      sortValue: (e) => e.source,
    },
  ]
  if (!opts.compact) {
    cols.push({
      key: 'incident',
      header: 'Incident',
      render: (e) => (e.incident_id ? <span className="font-mono text-[12px] text-accent">#{e.incident_id}</span> : <span className="text-subtle">—</span>),
      sortValue: (e) => e.incident_id ?? -1,
    })
  }
  cols.push({
    key: 'timestamp',
    header: 'Time',
    render: (e) => <Time value={e.timestamp} />,
    sortValue: (e) => parseDate(e.timestamp)?.getTime() ?? 0,
    align: 'right',
  })
  return cols
}
