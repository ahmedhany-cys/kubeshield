import { useCallback, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { RefreshCw, X } from 'lucide-react'
import { api } from '../api/client'
import { SEVERITIES, type Severity } from '../api/types'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { Card, PageHeader } from '../components/Card'
import { DataTable } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { EventDrawer } from '../components/EventDrawer'
import { eventColumns } from '../components/EventTable'
import { ChipGroup, SearchInput, Select } from '../components/Form'
import { useApi } from '../hooks/useApi'
import { formatNumber } from '../lib/format'

const PAGE = 50
const SOURCES = ['falco', 'hubble', 'kyverno']
const WINDOWS = [
  { value: '1', label: 'Last hour' },
  { value: '24', label: 'Last 24 hours' },
  { value: '168', label: 'Last 7 days' },
  { value: '720', label: 'Last 30 days' },
]

export default function ThreatsPage() {
  const [params, setParams] = useSearchParams()
  const severity = params.getAll('severity').filter((s): s is Severity => (SEVERITIES as string[]).includes(s))
  const source = params.get('source') ?? ''
  const namespace = params.get('namespace') ?? ''
  const ruleId = params.get('rule_id') ?? ''
  const q = params.get('q') ?? ''
  const since = params.get('since') ?? ''
  const offset = Number(params.get('offset') ?? 0) || 0
  const eventId = params.get('event')

  const update = useCallback(
    (changes: Record<string, string | string[] | null>, resetOffset = true) => {
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
      )
    },
    [setParams],
  )

  const query = {
    severity,
    source: source || undefined,
    namespace: namespace || undefined,
    rule_id: ruleId || undefined,
    q: q || undefined,
    since_hours: since ? Number(since) : undefined,
    limit: PAGE,
    offset,
  }
  const events = useApi((s) => api.events(query, s), [query], { interval: 30_000 })
  const cluster = useApi((s) => api.cluster(s), [])
  const nsOptions = useMemo(() => {
    const c = cluster.data
    const names = c && c.available ? c.namespaces.map((n) => n.name) : []
    if (namespace && !names.includes(namespace)) names.unshift(namespace)
    return names.sort()
  }, [cluster.data, namespace])

  const filtersActive = severity.length > 0 || source || namespace || ruleId || q || since
  const onSearch = useCallback((v: string) => update({ q: v || null }), [update])

  return (
    <div>
      <PageHeader
        title="Runtime threats"
        description="Security events received from Falco (syscalls), Cilium Hubble (network drops) and Kyverno (admission). Select an event to investigate."
        actions={
          <Button size="sm" variant="ghost" icon={<RefreshCw className="h-3.5 w-3.5" />} onClick={events.reload} loading={events.loading}>
            Refresh
          </Button>
        }
      />
      {events.error ? (
        <div className="mb-4">
          <ErrorState error={events.error} onRetry={events.reload} />
        </div>
      ) : null}
      <Card
        flush
        title={
          <span>
            Security events{' '}
            {events.data && <span className="font-normal text-subtle">· {formatNumber(events.data.total)} matching</span>}
          </span>
        }
      >
        <div className="flex flex-col gap-2 border-b border-border px-3 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput
              value={q}
              onChange={onSearch}
              debounce={350}
              placeholder="Search message, rule, pod, namespace…"
              className="w-full sm:w-80"
            />
            <Select value={source} onChange={(v) => update({ source: v || null })} options={SOURCES} placeholder="All sources" label="Source" />
            <Select value={namespace} onChange={(v) => update({ namespace: v || null })} options={nsOptions} placeholder="All namespaces" label="Namespace" />
            <Select value={since} onChange={(v) => update({ since: v || null })} options={WINDOWS} placeholder="Any time" label="Time window" />
            {ruleId && (
              <Badge tone="accent">
                rule {ruleId}
                <button type="button" onClick={() => update({ rule_id: null })} aria-label="Clear rule filter">
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            )}
            {filtersActive && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => update({ severity: null, source: null, namespace: null, rule_id: null, q: null, since: null })}
              >
                Clear filters
              </Button>
            )}
          </div>
          <ChipGroup
            label="Severity"
            options={SEVERITIES}
            value={severity}
            onChange={(v) => update({ severity: v })}
          />
        </div>
        <DataTable
          columns={eventColumns()}
          rows={events.data?.items}
          rowKey={(e) => e.id}
          loading={events.initialLoading}
          onRowClick={(e) => update({ event: e.id }, false)}
          selectedKey={eventId}
          pagination={
            events.data
              ? { total: events.data.total, offset, limit: PAGE, onChange: (o) => update({ offset: o ? String(o) : null }, false) }
              : undefined
          }
          empty={
            filtersActive ? (
              <EmptyState title="No events match these filters" description="Adjust or clear the filters above." />
            ) : (
              <EmptyState
                title="No runtime events yet"
                description={
                  <>
                    Run an <Link to="/simulations" className="link">attack simulation</Link> to generate real Falco, Hubble and Kyverno telemetry.
                  </>
                }
              />
            )
          }
        />
      </Card>
      <EventDrawer eventId={eventId} onClose={() => update({ event: null }, false)} />
    </div>
  )
}
