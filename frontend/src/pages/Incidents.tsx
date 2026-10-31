import { useCallback } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import type { Incident, IncidentStatus, Severity } from '../api/types'
import { INCIDENT_STATUSES, SEVERITIES } from '../api/types'
import { StatusBadge } from '../components/Badge'
import { Card, PageHeader } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { ChipGroup, SearchInput } from '../components/Form'
import { SeverityBadge } from '../components/SeverityBadge'
import { TechniqueTags } from '../components/Techniques'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { formatNumber, humanize, parseDate } from '../lib/format'

const PAGE = 50
const sevRank = (s: string) => 4 - (SEVERITIES as string[]).indexOf(s)

const columns: Column<Incident>[] = [
  { key: 'id', header: 'ID', render: (i) => <span className="font-mono text-[12px] text-subtle">#{i.id}</span>, sortValue: (i) => i.id, className: 'w-16' },
  { key: 'severity', header: 'Severity', render: (i) => <SeverityBadge severity={i.severity} />, sortValue: (i) => sevRank(i.severity), className: 'w-24' },
  {
    key: 'title',
    header: 'Incident',
    render: (i) => (
      <div className="min-w-0 max-w-[460px]">
        <Link to={`/incidents/${i.id}`} className="block truncate font-medium text-fg hover:text-accent" onClick={(e) => e.stopPropagation()}>
          {i.title}
        </Link>
        <div className="truncate font-mono text-[11.5px] text-subtle">
          {i.namespace ?? '—'}/{i.pod ?? '—'}
          {i.workload ? ` · ${i.workload}` : ''}
        </div>
      </div>
    ),
    sortValue: (i) => i.title,
  },
  { key: 'status', header: 'Status', render: (i) => <StatusBadge status={i.status} />, sortValue: (i) => i.status },
  { key: 'events', header: 'Events', render: (i) => formatNumber(i.event_count), sortValue: (i) => i.event_count, align: 'right' },
  { key: 'techniques', header: 'Techniques', render: (i) => <TechniqueTags ids={i.techniques} /> },
  { key: 'first', header: 'First seen', render: (i) => <Time value={i.first_seen} />, sortValue: (i) => parseDate(i.first_seen)?.getTime() ?? 0, align: 'right' },
  { key: 'last', header: 'Last seen', render: (i) => <Time value={i.last_seen} />, sortValue: (i) => parseDate(i.last_seen)?.getTime() ?? 0, align: 'right' },
]

export default function IncidentsPage() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const status = params.getAll('status').filter((s): s is IncidentStatus => (INCIDENT_STATUSES as string[]).includes(s))
  const severity = params.getAll('severity').filter((s): s is Severity => (SEVERITIES as string[]).includes(s))
  const q = params.get('q') ?? ''
  const offset = Number(params.get('offset') ?? 0) || 0

  const update = useCallback(
    (changes: Record<string, string | string[] | null>, resetOffset = true) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          for (const [k, v] of Object.entries(changes)) {
            next.delete(k)
            if (Array.isArray(v)) v.forEach((x) => next.append(k, x))
            else if (v) next.set(k, v)
          }
          if (resetOffset) next.delete('offset')
          return next
        },
        { replace: true },
      ),
    [setParams],
  )
  const onSearch = useCallback((v: string) => update({ q: v || null }), [update])

  const query = { status, severity, q: q || undefined, limit: PAGE, offset }
  const incidents = useApi((s) => api.incidents(query, s), [query], { interval: 20_000 })
  const filtered = status.length > 0 || severity.length > 0 || Boolean(q)

  return (
    <div>
      <PageHeader
        title="Incidents"
        description="Security events correlated per workload within the incident window. Open an incident to investigate, respond and record decisions."
      />
      {incidents.error ? <div className="mb-4"><ErrorState error={incidents.error} onRetry={incidents.reload} /></div> : null}
      <Card flush title={<span>Incidents {incidents.data && <span className="font-normal text-subtle">· {formatNumber(incidents.data.total)} matching</span>}</span>}>
        <div className="flex flex-col gap-2 border-b border-border px-3 py-2.5">
          <SearchInput value={q} onChange={onSearch} debounce={350} placeholder="Search title, pod, namespace…" className="w-full sm:w-80" />
          <div className="flex flex-wrap items-center gap-3">
            <ChipGroup label="Status" options={INCIDENT_STATUSES} value={status} onChange={(v) => update({ status: v })} render={(s) => humanize(s)} />
            <span className="hidden h-5 w-px bg-border sm:block" />
            <ChipGroup label="Severity" options={SEVERITIES} value={severity} onChange={(v) => update({ severity: v })} />
          </div>
        </div>
        <DataTable
          columns={columns}
          rows={incidents.data?.items}
          rowKey={(i) => i.id}
          loading={incidents.initialLoading}
          onRowClick={(i) => navigate(`/incidents/${i.id}`)}
          pagination={
            incidents.data
              ? { total: incidents.data.total, offset, limit: PAGE, onChange: (o) => update({ offset: o ? String(o) : null }, false) }
              : undefined
          }
          empty={
            filtered ? (
              <EmptyState title="No incidents match these filters" />
            ) : (
              <EmptyState
                title="No incidents yet"
                description={
                  <>
                    Incidents open when security events at or above the configured severity arrive. Run an{' '}
                    <Link to="/simulations" className="link">attack simulation</Link> to exercise the pipeline.
                  </>
                }
              />
            )
          }
        />
      </Card>
    </div>
  )
}
