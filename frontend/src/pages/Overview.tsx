import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Bug, FileCheck, RefreshCw, Server, ShieldAlert, Siren } from 'lucide-react'
import { api } from '../api/client'
import { SEVERITIES, type Severity } from '../api/types'
import { BarList } from '../components/BarList'
import { Button } from '../components/Button'
import { Card, PageHeader } from '../components/Card'
import { DataTable } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, UnavailableState } from '../components/ErrorState'
import { EventDrawer } from '../components/EventDrawer'
import { eventColumns } from '../components/EventTable'
import { IntegrationList } from '../components/IntegrationList'
import { Loading } from '../components/Loading'
import { SEVERITY_COLORS } from '../components/SeverityBadge'
import { StatCard } from '../components/StatCard'
import { useApi } from '../hooks/useApi'
import { axisTick, gridStroke, PALETTE, tooltipItemStyle, tooltipLabelStyle, tooltipStyle } from '../lib/chart'
import { formatHour, formatNumber, humanize, relativeTime } from '../lib/format'

const RESPONSE_COLORS: Record<string, string> = {
  succeeded: '#34c38f',
  failed: '#f05252',
  refused: '#f05252',
  pending_approval: '#f5b83d',
  approved: '#3ba7ff',
  executing: '#3ba7ff',
  rejected: '#5f6b80',
  alerted: '#8a94a6',
}

function SeverityChips({ counts }: { counts: Partial<Record<Severity, number>> }) {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11.5px]">
      {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
        <span key={s} className="flex items-center gap-1 text-subtle">
          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[s] }} />
          <span className="tabular-nums text-muted">{counts[s] ?? 0}</span> {s}
        </span>
      ))}
    </div>
  )
}

export default function OverviewPage() {
  const { data, error, initialLoading, reload, loading, lastUpdated } = useApi((s) => api.overview(s), [], {
    interval: 15_000,
  })
  const [eventId, setEventId] = useState<string | null>(null)

  if (initialLoading) return <Loading />
  if (!data) return <ErrorState error={error} onRetry={reload} />

  const ev = data.events_24h
  const highCrit = (ev.by_severity.critical ?? 0) + (ev.by_severity.high ?? 0)
  const activity = data.activity.map((b) => ({ ...b, label: formatHour(b.hour) }))
  const activityTotal = data.activity.reduce((n, b) => n + SEVERITIES.reduce((m, s) => m + (b[s] ?? 0), 0), 0)
  const sources = Object.entries(ev.by_source).sort((a, b) => b[1] - a[1])
  const responses = Object.entries(data.responses).sort((a, b) => b[1] - a[1])
  const responseTotal = responses.reduce((n, [, v]) => n + v, 0)
  const posture = data.posture.open_by_severity
  const postureTotal = SEVERITIES.reduce((n, s) => n + (posture[s] ?? 0), 0)
  const cluster = data.cluster

  return (
    <div>
      <PageHeader
        title="Security overview"
        description="Live posture of the protected cluster. Refreshes every 15 seconds."
        actions={
          <>
            {lastUpdated && <span className="text-[12px] text-subtle">Updated {relativeTime(lastUpdated.toISOString())}</span>}
            <Button size="sm" variant="ghost" icon={<RefreshCw className="h-3.5 w-3.5" />} onClick={reload} loading={loading}>
              Refresh
            </Button>
          </>
        }
      />
      {error ? (
        <div className="mb-4">
          <ErrorState error={error} compact onRetry={reload} />
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard
          label="Open incidents"
          value={formatNumber(data.incidents.open_total)}
          icon={<ShieldAlert className="h-4 w-4" />}
          tone={(data.incidents.open_by_severity.critical ?? 0) > 0 ? 'bad' : data.incidents.open_total > 0 ? 'warn' : 'neutral'}
          to="/incidents"
        >
          <SeverityChips counts={data.incidents.open_by_severity} />
        </StatCard>
        <StatCard
          label="High / critical events (24h)"
          value={formatNumber(highCrit)}
          icon={<Siren className="h-4 w-4" />}
          tone={highCrit > 0 ? 'warn' : 'neutral'}
          sub={`${formatNumber(ev.total)} events in the last 24 hours`}
          to="/threats"
        />
        <StatCard
          label="Vulnerable images"
          value={
            <>
              {formatNumber(data.images.vulnerable)}
              <span className="ml-1 text-[14px] font-normal text-subtle">/ {formatNumber(data.images.scanned)}</span>
            </>
          }
          icon={<Bug className="h-4 w-4" />}
          tone={data.images.vulnerable > 0 ? 'warn' : 'neutral'}
          sub={
            data.images.scanned === 0
              ? 'No successful image scans yet'
              : `${formatNumber(data.images.critical)} critical CVEs across latest scans`
          }
          to="/vulnerabilities"
        />
        <StatCard
          label="Open policy violations"
          value={formatNumber(data.policy.open_violations)}
          icon={<FileCheck className="h-4 w-4" />}
          tone={data.policy.open_violations > 0 ? 'warn' : 'neutral'}
          sub={`${formatNumber(data.policy.blocked_admissions)} admissions blocked`}
          to="/policies"
        />
        <StatCard
          label="Nodes ready"
          value={
            cluster.available ? (
              <>
                {formatNumber(cluster.nodes_ready)}
                <span className="ml-1 text-[14px] font-normal text-subtle">/ {formatNumber(cluster.counts.nodes ?? 0)}</span>
              </>
            ) : (
              <span className="text-[18px] text-warn">Unavailable</span>
            )
          }
          icon={<Server className="h-4 w-4" />}
          tone={cluster.available && cluster.nodes_ready < (cluster.counts.nodes ?? 0) ? 'warn' : 'neutral'}
          sub={
            cluster.available
              ? `Kubernetes ${cluster.kubernetes_version ?? 'version unknown'} · snapshot ${relativeTime(cluster.snapshot_at)}`
              : 'No cluster inventory snapshot yet'
          }
          to="/cluster"
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Detection activity"
          subtitle="Security events per hour over the last 24 hours, by severity"
        >
          {activityTotal === 0 ? (
            <EmptyState
              title="No runtime events in the last 24 hours"
              description={
                <>
                  Run an <Link to="/simulations" className="link">attack simulation</Link> to generate validated telemetry.
                </>
              }
            />
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activity} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid stroke={gridStroke} vertical={false} />
                  <XAxis dataKey="label" tick={axisTick} tickLine={false} axisLine={false} interval={2} />
                  <YAxis tick={axisTick} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={tooltipStyle} labelStyle={tooltipLabelStyle} itemStyle={tooltipItemStyle} />
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ paddingTop: 8 }} />
                  {[...SEVERITIES].reverse().map((s) => (
                    <Area
                      key={s}
                      type="monotone"
                      dataKey={s}
                      name={s}
                      stackId="sev"
                      stroke={SEVERITY_COLORS[s]}
                      fill={SEVERITY_COLORS[s]}
                      fillOpacity={0.22}
                      strokeWidth={1.5}
                      isAnimationActive={false}
                    />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card title="Events by source" subtitle="Last 24 hours">
          <BarList
            items={sources.map(([k, v], i) => ({ key: k, label: k, value: v, color: PALETTE[i % PALETTE.length] }))}
            empty={<EmptyState compact title="No events from any source" description="Falco, Hubble and Kyverno events appear here once received." />}
          />
          <div className="mt-5 border-t border-border pt-4">
            <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-subtle">Top detections (24h)</div>
            <BarList
              items={data.top_rules.map((r) => ({ key: r.rule, label: r.rule, value: r.count, color: '#3ba7ff' }))}
              empty={<p className="text-[12.5px] text-subtle">No detections in the last 24 hours.</p>}
            />
          </div>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Response actions" subtitle={`${formatNumber(responseTotal)} actions recorded (all time)`} actions={<Link to="/responses" className="link text-[12px]">View history</Link>}>
          <BarList
            items={responses.map(([k, v]) => ({ key: k, label: humanize(k), value: v, color: RESPONSE_COLORS[k] ?? '#94a0b4' }))}
            empty={<EmptyState compact title="No response actions yet" description="Playbooks and analysts create actions when incidents open." />}
          />
        </Card>
        <Card title="Open posture findings" subtitle={`${formatNumber(postureTotal)} open misconfigurations`} actions={<Link to="/cluster?tab=posture" className="link text-[12px]">Review</Link>}>
          <BarList
            items={SEVERITIES.filter((s) => (posture[s] ?? 0) > 0).map((s) => ({
              key: s,
              label: <span className="capitalize">{s}</span>,
              value: posture[s] ?? 0,
              color: SEVERITY_COLORS[s],
            }))}
            empty={<EmptyState compact title="No open posture findings" description="Findings are produced by each cluster inventory scan." />}
          />
        </Card>
        <Card title="Integration health" subtitle={cluster.available ? `From inventory snapshot ${relativeTime(cluster.snapshot_at)}` : undefined}>
          {!cluster.available ? (
            <UnavailableState title="Cluster inventory unavailable" detail="No successful inventory snapshot has been recorded yet." />
          ) : cluster.integrations.length === 0 ? (
            <EmptyState compact title="No integrations reported" />
          ) : (
            <IntegrationList items={cluster.integrations} />
          )}
        </Card>
      </div>

      <Card
        className="mt-4"
        title="Recent security events"
        actions={<Link to="/threats" className="link text-[12px]">All runtime threats</Link>}
        flush
      >
        <DataTable
          columns={eventColumns({ compact: true })}
          rows={data.recent_events}
          rowKey={(e) => e.id}
          onRowClick={(e) => setEventId(e.id)}
          empty={
            <EmptyState
              title="No runtime events yet"
              description={
                <>
                  Run an <Link to="/simulations" className="link">attack simulation</Link> to exercise the detections.
                </>
              }
            />
          }
        />
      </Card>
      <EventDrawer eventId={eventId} onClose={() => setEventId(null)} />
    </div>
  )
}
