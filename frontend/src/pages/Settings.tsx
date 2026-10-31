import { useEffect, useState, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ShieldAlert, TriangleAlert } from 'lucide-react'
import { api } from '../api/client'
import type { Detection, RuntimeSettings, Severity } from '../api/types'
import { SEVERITIES } from '../api/types'
import { Badge, StatusBadge } from '../components/Badge'
import { Button } from '../components/Button'
import { Card, PageHeader } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, InlineError, UnavailableState } from '../components/ErrorState'
import { Select, Toggle } from '../components/Form'
import { IntegrationList } from '../components/IntegrationList'
import { JsonView } from '../components/JsonView'
import { KeyValueGrid } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { Modal } from '../components/Modal'
import { SeverityBadge } from '../components/SeverityBadge'
import { TechniqueTags } from '../components/Techniques'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { formatDateTime, formatNumber, relativeTime } from '../lib/format'

interface SettingDef {
  key: keyof RuntimeSettings & string
  title: string
  description: ReactNode
  danger?: boolean
}

const SETTING_DEFS: SettingDef[] = [
  {
    key: 'response.auto_enabled',
    title: 'Automatic response',
    description: 'Allow playbooks in "Automatic" mode to execute without analyst approval. When off, automatic playbooks fall back to requiring approval.',
    danger: true,
  },
  {
    key: 'response.auto_destructive_enabled',
    title: 'Automatic destructive response',
    description: 'Allow destructive actions (delete pod, scale deployment to zero) to execute automatically. Off by default; requires automatic response to also be enabled.',
    danger: true,
  },
  {
    key: 'incidents.min_severity',
    title: 'Incident threshold',
    description: 'Minimum event severity that opens or updates an incident.',
  },
  {
    key: 'simulation.enabled',
    title: 'Attack simulation',
    description: 'Allow responders to run controlled attack scenarios against the lab namespaces.',
  },
  {
    key: 'scanner.scan_workload_images',
    title: 'Scan workload images',
    description: 'Automatically queue Trivy scans for images running in the cluster after each inventory snapshot.',
  },
]

export default function SettingsPage() {
  const { can } = useAuth()
  const isAdmin = can('admin')
  const location = useLocation()
  const settings = useApi((s) => api.settings(s), [])
  const status = useApi((s) => api.systemStatus(s), [], { interval: 15_000 })
  const detections = useApi((s) => api.detections(s), [])
  const put = useMutation(api.putSetting)
  const [runtime, setRuntime] = useState<RuntimeSettings | null>(null)
  const [confirm, setConfirm] = useState<{ key: string; value: boolean } | null>(null)

  useEffect(() => {
    if (settings.data) setRuntime(settings.data.runtime)
  }, [settings.data])

  useEffect(() => {
    if (location.hash === '#system' && status.data) document.getElementById('system')?.scrollIntoView({ block: 'start' })
  }, [location.hash, status.data])

  const apply = async (key: string, value: boolean | string) => {
    const r = await put.run(key, value)
    if (r) setRuntime(r)
  }
  const onToggle = (def: SettingDef, value: boolean) => {
    if (def.danger && value) setConfirm({ key: def.key, value })
    else void apply(def.key, value)
  }

  const detectionColumns: Column<Detection>[] = [
    {
      key: 'name',
      header: 'Detection',
      render: (d) => (
        <div className="min-w-0 max-w-[360px]">
          <div className="font-medium text-fg">{d.name}</div>
          <div className="line-clamp-2 text-[12px] text-subtle" title={d.description}>{d.description}</div>
        </div>
      ),
      sortValue: (d) => d.name,
    },
    { key: 'id', header: 'ID', render: (d) => <span className="font-mono text-[12px]">{d.id}</span>, sortValue: (d) => d.id },
    {
      key: 'source',
      header: 'Source',
      render: (d) => (
        <div>
          <Badge>{d.source}</Badge>
          <div className="mt-0.5 max-w-[200px] truncate font-mono text-[11px] text-subtle" title={d.source_rule}>{d.source_rule}</div>
        </div>
      ),
      sortValue: (d) => d.source,
    },
    { key: 'severity', header: 'Severity', render: (d) => <SeverityBadge severity={d.severity} />, sortValue: (d) => 4 - SEVERITIES.indexOf(d.severity) },
    { key: 'techniques', header: 'Techniques', render: (d) => <TechniqueTags ids={d.techniques} /> },
    {
      key: 'validated',
      header: 'Validation',
      render: (d) =>
        d.validated ? (
          <div>
            <Badge tone="ok" dot>validated</Badge>
            <div className="mt-0.5 text-[11px] text-subtle">
              <Link className="link" to={`/simulations?run=${encodeURIComponent(d.validated.run_id)}`}>{relativeTime(d.validated.at)}</Link>
            </div>
          </div>
        ) : (
          <div>
            <Badge tone="accent">implemented</Badge>
            {d.scenario && <div className="mt-0.5 font-mono text-[11px] text-subtle">{d.scenario}</div>}
          </div>
        ),
      sortValue: (d) => (d.validated ? 1 : 0),
    },
    {
      key: 'events',
      header: 'Events',
      render: (d) => (d.event_count ? <Link className="link tabular-nums" to={`/threats?rule_id=${encodeURIComponent(d.id)}`}>{formatNumber(d.event_count)}</Link> : <span className="text-subtle">0</span>),
      sortValue: (d) => d.event_count,
      align: 'right',
    },
  ]

  const st = status.data
  const s = settings.data

  return (
    <div>
      <PageHeader title="Settings" description="Runtime behaviour, static deployment configuration, platform health and the detection catalog." />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Runtime settings" subtitle={isAdmin ? 'Changes take effect immediately and are recorded in the audit log' : 'Read-only: changing settings requires the admin role'}>
          {settings.initialLoading && <Loading />}
          {settings.error && !s ? <ErrorState error={settings.error} onRetry={settings.reload} /> : null}
          {runtime && (
            <>
              {(runtime['response.auto_enabled'] || runtime['response.auto_destructive_enabled']) && (
                <div className="mb-4 flex items-start gap-2 rounded-md border border-warn/35 bg-warn/[0.06] px-3 py-2.5 text-[12.5px] text-warn">
                  <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>
                    {runtime['response.auto_destructive_enabled'] && runtime['response.auto_enabled']
                      ? 'Automatic destructive response is ON: playbooks may delete pods or scale deployments to zero without human approval.'
                      : runtime['response.auto_enabled']
                        ? 'Automatic response is ON: non-destructive playbook actions (e.g. pod isolation) run without approval. Destructive actions still require approval.'
                        : 'Automatic destructive response is enabled but has no effect while automatic response is off.'}
                  </span>
                </div>
              )}
              <ul className="divide-y divide-border">
                {SETTING_DEFS.map((def) => {
                  const value = runtime[def.key]
                  return (
                    <li key={def.key} className="flex items-start justify-between gap-4 py-3 first:pt-0 last:pb-0">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[13px] font-medium text-fg">{def.title}</span>
                          {def.danger && <Badge tone="warn">off by default</Badge>}
                        </div>
                        <p className="mt-0.5 text-[12.5px] text-muted">{def.description}</p>
                        <span className="font-mono text-[11px] text-subtle">{def.key}</span>
                      </div>
                      <div className="shrink-0 pt-0.5">
                        {typeof value === 'boolean' ? (
                          <Toggle checked={value} onChange={(v) => onToggle(def, v)} disabled={!isAdmin || put.pending} label={def.title} />
                        ) : (
                          <Select
                            value={String(value)}
                            onChange={(v) => void apply(def.key, v as Severity)}
                            options={SEVERITIES}
                            disabled={!isAdmin || put.pending}
                            label={def.title}
                          />
                        )}
                      </div>
                    </li>
                  )
                })}
              </ul>
              <InlineError message={put.error} />
            </>
          )}
        </Card>

        <Card title="Static configuration" subtitle="Set by environment variables at deployment time">
          {s ? (
            <KeyValueGrid
              columns={1}
              items={[
                { label: 'Kubernetes mode', value: s.static.kube_mode, mono: true },
                { label: 'Lab namespace label', value: `${s.static.lab_label}=true`, mono: true },
                { label: 'Pre-deployment namespace', value: s.static.preflight_namespace, mono: true },
                { label: 'Hubble Relay address', value: s.static.hubble_relay_address ?? 'not configured', mono: true },
                { label: 'Incident correlation window', value: `${s.static.incident_window_minutes} minutes` },
                { label: 'Session lifetime', value: `${s.static.session_ttl_minutes} minutes` },
              ]}
            />
          ) : settings.initialLoading ? (
            <Loading />
          ) : null}
        </Card>
      </div>

      <div id="system" className="scroll-mt-20">
        <h2 className="mb-3 mt-8 text-[15px] font-semibold text-fg">System status</h2>
        {status.initialLoading && <Loading />}
        {status.error && !st ? <ErrorState error={status.error} onRetry={status.reload} /> : null}
        {st && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <Card title="Kubernetes API" actions={<StatusBadge status={st.kubernetes.reachable ? 'healthy' : 'error'} label={st.kubernetes.reachable ? 'Reachable' : 'Unreachable'} />}>
              <KeyValueGrid
                columns={1}
                items={[
                  { label: 'Mode', value: st.kubernetes.mode, mono: true },
                  { label: 'KubeShield version', value: st.version, mono: true },
                ]}
              />
              {st.kubernetes.error && <div className="mt-3"><UnavailableState title="Kubernetes API error" detail={st.kubernetes.error} /></div>}
            </Card>
            <Card title="Telemetry sources">
              <ul className="space-y-3 text-[13px]">
                <li className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-fg">Falco</div>
                    <div className="text-[12px] text-subtle">
                      {st.falco.last_event_ingested_at ? `Last event ingested ${relativeTime(st.falco.last_event_ingested_at)} (${formatDateTime(st.falco.last_event_ingested_at)})` : 'No Falco events ingested yet'}
                    </div>
                  </div>
                  <StatusBadge status={st.falco.last_event_ingested_at ? 'healthy' : 'unknown'} label={st.falco.last_event_ingested_at ? 'Receiving' : 'No events'} />
                </li>
                <li className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-medium text-fg">Cilium Hubble Relay</div>
                    <div className="truncate font-mono text-[11.5px] text-subtle">{st.hubble.address ?? 'not configured'}</div>
                    <div className="text-[12px] text-subtle">{formatNumber(st.hubble.flows_seen)} flows seen · {formatNumber(st.hubble.flows_stored)} stored{st.hubble.last_flow_at ? ` · last ${relativeTime(st.hubble.last_flow_at)}` : ''}</div>
                    {st.hubble.last_error && <div className="mt-0.5 break-words font-mono text-[11.5px] text-bad">{st.hubble.last_error}</div>}
                  </div>
                  <StatusBadge status={st.hubble.connected ? 'healthy' : 'error'} label={st.hubble.connected ? 'Connected' : 'Not connected'} />
                </li>
                <li className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-fg">Trivy scanner</div>
                    <div className="text-[12px] text-subtle">{st.trivy.available ? `Version ${st.trivy.version ?? 'unknown'}` : 'Binary not available to the backend'}</div>
                  </div>
                  <StatusBadge status={st.trivy.available ? 'healthy' : 'not_installed'} label={st.trivy.available ? 'Available' : 'Unavailable'} />
                </li>
              </ul>
            </Card>
            <Card title="Background workers">
              {Object.keys(st.workers).length === 0 ? (
                <EmptyState compact title="No workers running" description="Background workers start with the API server process." />
              ) : (
                <ul className="space-y-3">
                  {Object.entries(st.workers).map(([name, w]) => (
                    <li key={name} className="text-[13px]">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono font-medium text-fg">{name}</span>
                        <StatusBadge status={!w.running ? 'error' : w.last_error ? 'degraded' : 'healthy'} label={!w.running ? 'Stopped' : w.last_error ? 'Erroring' : 'Running'} />
                      </div>
                      <div className="text-[12px] text-subtle">Last run {w.last_run ? relativeTime(w.last_run) : 'never'}</div>
                      {w.last_error && <div className="mt-0.5 break-words font-mono text-[11.5px] text-bad">{w.last_error}</div>}
                      {w.last_result !== null && w.last_result !== undefined && <div className="mt-1.5"><JsonView value={w.last_result} title="Last result" /></div>}
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card className="lg:col-span-2 xl:col-span-3" title="Cluster integrations" subtitle="From the latest inventory snapshot">
              {st.integrations.length === 0 ? (
                <UnavailableState title="No integration inventory" detail="No successful cluster inventory snapshot has been recorded yet." />
              ) : (
                <div className="grid grid-cols-1 gap-x-8 md:grid-cols-2">
                  <IntegrationList items={st.integrations.slice(0, Math.ceil(st.integrations.length / 2))} />
                  <IntegrationList items={st.integrations.slice(Math.ceil(st.integrations.length / 2))} />
                </div>
              )}
            </Card>
          </div>
        )}
      </div>

      <h2 className="mb-3 mt-8 flex items-center gap-2 text-[15px] font-semibold text-fg">
        <ShieldAlert className="h-4 w-4 text-subtle" /> Detection catalog
      </h2>
      <Card flush subtitle='"Validated" means a recorded simulation run confirmed the detection end to end; "implemented" means the rule ships but has not yet been validated.'>
        {detections.error && !detections.data ? <div className="p-3"><ErrorState error={detections.error} onRetry={detections.reload} compact /></div> : null}
        <DataTable
          columns={detectionColumns}
          rows={detections.data}
          rowKey={(d) => d.id}
          loading={detections.initialLoading}
          searchText={(d) => `${d.id} ${d.name} ${d.source} ${d.source_rule} ${d.techniques.join(' ')}`}
          searchPlaceholder="Search detections…"
          initialSort={{ key: 'id', dir: 'asc' }}
          empty={<EmptyState compact title="No detections in the catalog" />}
        />
      </Card>

      <Modal
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        title="Enable automatic response?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(null)}>Cancel</Button>
            <Button
              variant="danger"
              loading={put.pending}
              onClick={async () => {
                if (confirm) await apply(confirm.key, confirm.value)
                setConfirm(null)
              }}
            >
              Enable
            </Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">
          {confirm?.key === 'response.auto_destructive_enabled'
            ? 'Destructive actions (delete pod, scale to zero) will execute without human approval for playbooks in Automatic mode, provided automatic response is also enabled.'
            : 'Playbooks in Automatic mode will execute response actions against the cluster without analyst approval.'}
        </p>
        <p className="mt-2 text-[12.5px] text-subtle">This change is recorded in the audit log.</p>
      </Modal>
    </div>
  )
}
