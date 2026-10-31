import { useMemo, useState } from 'react'
import { ArrowRight, Eye, ShieldCheck } from 'lucide-react'
import { api } from '../api/client'
import type { CiliumPolicy, K8sNetworkPolicy, NetworkFlow, NetworkSummary } from '../api/types'
import { Badge, StatusBadge } from '../components/Badge'
import { Card, PageHeader } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, UnavailableState } from '../components/ErrorState'
import { Select } from '../components/Form'
import { KeyValueGrid } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { StatCard } from '../components/StatCard'
import { Tabs } from '../components/Tabs'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { cx, formatDateTime, formatNumber, parseDate, relativeTime } from '../lib/format'

function Provenance({ children, icon }: { children: string; icon?: 'eye' | 'shield' }) {
  const Icon = icon === 'shield' ? ShieldCheck : Eye
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-subtle">
      <Icon className="h-3 w-3" />
      {children}
    </span>
  )
}

const flowColumns: Column<NetworkFlow>[] = [
  { key: 'time', header: 'Time', render: (f) => <Time value={f.timestamp} />, sortValue: (f) => parseDate(f.timestamp)?.getTime() ?? 0 },
  { key: 'verdict', header: 'Verdict', render: (f) => <StatusBadge status={f.verdict} />, sortValue: (f) => f.verdict },
  {
    key: 'src',
    header: 'Source',
    render: (f) => (
      <div className="min-w-0 max-w-[240px]">
        <div className="truncate font-mono text-[12px] text-fg">{f.src_pod ?? f.src_ip ?? '—'}</div>
        <div className="truncate text-[11.5px] text-subtle">{f.src_namespace ?? 'external'}</div>
      </div>
    ),
    sortValue: (f) => `${f.src_namespace}/${f.src_pod}`,
  },
  { key: 'arrow', header: '', render: () => <ArrowRight className="h-3.5 w-3.5 text-subtle" /> },
  {
    key: 'dst',
    header: 'Destination',
    render: (f) => (
      <div className="min-w-0 max-w-[260px]">
        <div className="truncate font-mono text-[12px] text-fg">
          {f.dst_service ?? f.dst_pod ?? f.dst_ip ?? '—'}
          {f.dst_port !== null && <span className="text-subtle">:{f.dst_port}</span>}
        </div>
        <div className="truncate text-[11.5px] text-subtle">{f.dst_namespace ?? 'external'}{f.dst_service && f.dst_pod ? ` · ${f.dst_pod}` : ''}</div>
      </div>
    ),
    sortValue: (f) => `${f.dst_namespace}/${f.dst_pod}`,
  },
  { key: 'proto', header: 'Proto', render: (f) => <span className="font-mono text-[12px]">{f.protocol ?? '—'}</span> },
  { key: 'dir', header: 'Direction', render: (f) => f.direction ?? '—' },
  { key: 'drop', header: 'Drop reason', render: (f) => (f.drop_reason ? <span className="font-mono text-[11.5px] text-bad">{f.drop_reason}</span> : <span className="text-subtle">—</span>) },
  { key: 'node', header: 'Node', render: (f) => <span className="font-mono text-[11.5px] text-subtle">{f.node ?? '—'}</span> },
]

const k8sColumns: Column<K8sNetworkPolicy>[] = [
  {
    key: 'name',
    header: 'Policy',
    render: (p) => (
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-[12.5px] text-fg">{p.name}</span>
        {p.name.startsWith('ks-quarantine-') && <Badge tone="accent">KubeShield quarantine</Badge>}
        {p.ingress_rules === 0 && p.egress_rules === 0 && <Badge tone="warn">deny-all</Badge>}
      </div>
    ),
    sortValue: (p) => p.name,
  },
  { key: 'ns', header: 'Namespace', render: (p) => <span className="font-mono text-[12px]">{p.namespace}</span>, sortValue: (p) => p.namespace },
  {
    key: 'selector',
    header: 'Pod selector',
    render: (p) => {
      const entries = Object.entries(p.pod_selector)
      return entries.length ? (
        <div className="flex flex-wrap gap-1">{entries.map(([k, v]) => <Badge key={k}><span className="font-mono">{k}={v}</span></Badge>)}</div>
      ) : (
        <span className="text-[12px] text-subtle">all pods</span>
      )
    },
  },
  { key: 'types', header: 'Types', render: (p) => p.policy_types.join(', ') || '—' },
  { key: 'ing', header: 'Ingress rules', render: (p) => p.ingress_rules, sortValue: (p) => p.ingress_rules, align: 'right' },
  { key: 'eg', header: 'Egress rules', render: (p) => p.egress_rules, sortValue: (p) => p.egress_rules, align: 'right' },
]

const ciliumColumns: Column<CiliumPolicy>[] = [
  {
    key: 'name',
    header: 'Policy',
    render: (p) => (
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-[12.5px] text-fg">{p.name}</span>
        {p.managed_by_kubeshield && <Badge tone="accent">managed by KubeShield</Badge>}
        {p.deny && <Badge tone="bad">deny rules</Badge>}
      </div>
    ),
    sortValue: (p) => p.name,
  },
  { key: 'ns', header: 'Namespace', render: (p) => <span className="font-mono text-[12px]">{p.namespace}</span>, sortValue: (p) => p.namespace },
  { key: 'desc', header: 'Description', render: (p) => <span className="text-[12.5px] text-muted">{p.description ?? '—'}</span> },
]

function FlowMatrix({ summary }: { summary: NetworkSummary }) {
  const { names, cells } = useMemo(() => {
    const set = new Set<string>()
    const cells = new Map<string, { fwd: number; drop: number; other: number }>()
    for (const e of summary.edges) {
      set.add(e.src)
      set.add(e.dst)
      const key = `${e.src}\u0000${e.dst}`
      const c = cells.get(key) ?? { fwd: 0, drop: 0, other: 0 }
      if (e.verdict === 'FORWARDED') c.fwd += e.count
      else if (e.verdict === 'DROPPED') c.drop += e.count
      else c.other += e.count
      cells.set(key, c)
    }
    return { names: [...set].sort(), cells }
  }, [summary.edges])

  if (names.length === 0) {
    return <EmptyState compact title="No flows observed in the last 24 hours" description="Flows between lab namespaces appear once Hubble Relay streams them." />
  }
  return (
    <div className="overflow-x-auto">
      <table className="border-collapse text-[12px]">
        <thead>
          <tr>
            <th className="sticky left-0 z-10 bg-surface px-2 py-1.5 text-left text-[10.5px] font-medium uppercase tracking-wide text-subtle">src ↓ / dst →</th>
            {names.map((n) => (
              <th key={n} className="px-2 py-1.5 text-left font-mono text-[11px] font-normal text-muted">
                <span className="block max-w-[120px] truncate" title={n}>{n}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {names.map((src) => (
            <tr key={src}>
              <th className="sticky left-0 z-10 bg-surface px-2 py-1 text-left font-mono text-[11px] font-normal text-muted">
                <span className="block max-w-[160px] truncate" title={src}>{src}</span>
              </th>
              {names.map((dst) => {
                const c = cells.get(`${src}\u0000${dst}`)
                return (
                  <td key={dst} className="p-0.5">
                    <div
                      className={cx(
                        'flex h-10 min-w-[84px] flex-col items-center justify-center rounded border text-[11px] tabular-nums',
                        !c ? 'border-border/50 bg-transparent text-subtle/50' : c.drop > 0 ? 'border-bad/40 bg-bad/10' : 'border-ok/30 bg-ok/[0.07]',
                      )}
                      title={c ? `${src} → ${dst}: ${c.fwd} forwarded, ${c.drop} dropped${c.other ? `, ${c.other} other` : ''}` : `${src} → ${dst}: no flows`}
                    >
                      {c ? (
                        <>
                          <span className="text-ok">{formatNumber(c.fwd)} fwd</span>
                          <span className={c.drop ? 'text-bad' : 'text-subtle'}>{formatNumber(c.drop)} drop</span>
                        </>
                      ) : (
                        '·'
                      )}
                    </div>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

type PolicyTab = 'k8s' | 'cilium'

export default function NetworkPage() {
  const summary = useApi((s) => api.networkSummary(s), [], { interval: 30_000 })
  const [verdict, setVerdict] = useState('')
  const [namespace, setNamespace] = useState('')
  const flows = useApi((s) => api.flows({ verdict: verdict || undefined, namespace: namespace || undefined, limit: 500 }, s), [verdict, namespace], { interval: 15_000 })
  const [policyTab, setPolicyTab] = useState<PolicyTab>('k8s')

  const s = summary.data
  const hubble = s?.hubble ?? flows.data?.hubble
  const nsNames = useMemo(() => (s?.namespaces ?? []).map((n) => n.name).sort(), [s])
  const verdictNames = useMemo(() => Object.keys(s?.verdicts ?? {}).sort(), [s])
  const edges = useMemo(() => [...(s?.edges ?? [])].sort((a, b) => b.count - a.count), [s])

  return (
    <div>
      <PageHeader
        title="Network security"
        description="Pod-to-pod connections observed on the eBPF datapath by Cilium Hubble, and the Kubernetes / Cilium network policies that govern them."
      />
      {summary.initialLoading && <Loading />}
      {summary.error && !s ? <ErrorState error={summary.error} onRetry={summary.reload} /> : null}

      {hubble && (
        <Card
          className="mb-4"
          title="Cilium Hubble"
          subtitle={s?.observation_source}
          actions={<StatusBadge status={hubble.connected ? 'healthy' : 'error'} label={hubble.connected ? 'Connected' : 'Not connected'} />}
        >
          {!hubble.connected && (
            <div className="mb-4">
              <UnavailableState
                title="Hubble Relay is not connected — flow data below may be stale or empty"
                detail={hubble.last_error ?? (hubble.address ? null : 'No Hubble Relay address configured (KUBESHIELD_HUBBLE_RELAY_ADDRESS).')}
              />
            </div>
          )}
          <KeyValueGrid
            columns={3}
            items={[
              { label: 'Relay address', value: hubble.address, mono: true },
              { label: 'Last flow', value: hubble.last_flow_at ? `${relativeTime(hubble.last_flow_at)} (${formatDateTime(hubble.last_flow_at)})` : null },
              { label: 'Flows seen / stored', value: `${formatNumber(hubble.flows_seen)} / ${formatNumber(hubble.flows_stored)}` },
            ]}
          />
        </Card>
      )}

      {s && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            {verdictNames.length === 0 ? (
              <div className="col-span-full">
                <Card><EmptyState compact title={`No flows recorded in the last ${s.window_hours} hours`} /></Card>
              </div>
            ) : (
              verdictNames.map((v) => (
                <StatCard key={v} label={`${v} (${s.window_hours}h)`} value={formatNumber(s.verdicts[v])} tone={v === 'DROPPED' ? 'bad' : v === 'FORWARDED' ? 'ok' : 'neutral'} sub="Observed by Cilium Hubble" />
              ))
            )}
          </div>

          <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-5">
            <Card className="xl:col-span-3" title="Namespace flow matrix" subtitle={`Last ${s.window_hours} hours`} actions={<Provenance>Observed by Cilium Hubble</Provenance>}>
              <FlowMatrix summary={s} />
            </Card>
            <Card className="xl:col-span-2" title="Namespace edges" flush actions={<Provenance>Observed by Cilium Hubble</Provenance>}>
              <DataTable
                dense
                pageSize={12}
                rows={edges}
                rowKey={(e) => `${e.src}|${e.dst}|${e.verdict}`}
                columns={[
                  { key: 'src', header: 'From', render: (e) => <span className="font-mono text-[12px]">{e.src}</span>, sortValue: (e) => e.src },
                  { key: 'dst', header: 'To', render: (e) => <span className="font-mono text-[12px]">{e.dst}</span>, sortValue: (e) => e.dst },
                  { key: 'verdict', header: 'Verdict', render: (e) => <StatusBadge status={e.verdict} /> },
                  { key: 'count', header: 'Flows', render: (e) => formatNumber(e.count), sortValue: (e) => e.count, align: 'right' },
                ]}
                empty={<EmptyState compact title="No namespace edges" />}
              />
            </Card>
          </div>
        </>
      )}

      <Card
        className="mb-4"
        title="Recent flows"
        subtitle="Connection attempts and every drop involving lab namespaces"
        actions={<Provenance>Observed by Cilium Hubble</Provenance>}
        flush
      >
        {flows.error ? <div className="p-3"><ErrorState error={flows.error} onRetry={flows.reload} compact /></div> : null}
        <DataTable
          columns={flowColumns}
          rows={flows.data?.items}
          rowKey={(f) => String(f.id)}
          loading={flows.initialLoading}
          dense
          rowClassName={(f) => (f.verdict === 'DROPPED' ? 'bg-bad/[0.05]' : undefined)}
          searchText={(f) => `${f.src_pod} ${f.src_ip} ${f.dst_pod} ${f.dst_ip} ${f.dst_service} ${f.dst_port} ${f.drop_reason}`}
          searchPlaceholder="Search pods, IPs, ports…"
          toolbar={
            <>
              <Select value={verdict} onChange={setVerdict} options={verdictNames.length ? verdictNames : ['FORWARDED', 'DROPPED']} placeholder="All verdicts" label="Verdict" />
              <Select value={namespace} onChange={setNamespace} options={nsNames} placeholder="All namespaces" label="Namespace" />
            </>
          }
          pageSize={50}
          empty={
            <EmptyState
              title="No flows recorded"
              description={hubble?.connected ? 'No matching flows yet. Run the "Unauthorized pod communication" simulation to generate a dropped flow.' : 'Hubble Relay is not connected, so no flows are being received.'}
            />
          }
        />
      </Card>

      {s && (
        <Card
          title="Network policies"
          actions={
            <Provenance icon="shield">
              {policyTab === 'k8s' ? 'Kubernetes NetworkPolicy objects' : 'CiliumNetworkPolicy custom resources'}
            </Provenance>
          }
          flush
        >
          {s.error ? (
            <div className="p-4"><UnavailableState title="Could not list network policies from the cluster" detail={s.error} /></div>
          ) : (
            <>
              <Tabs<PolicyTab>
                className="px-3"
                value={policyTab}
                onChange={setPolicyTab}
                tabs={[
                  { key: 'k8s', label: 'Kubernetes NetworkPolicies', count: s.network_policies.length },
                  { key: 'cilium', label: 'CiliumNetworkPolicies', count: s.cilium_policies.length },
                ]}
              />
              {policyTab === 'k8s' ? (
                <DataTable columns={k8sColumns} rows={s.network_policies} rowKey={(p) => `${p.namespace}/${p.name}`} searchText={(p) => `${p.namespace} ${p.name}`} searchPlaceholder="Search policies…" empty={<EmptyState compact title="No Kubernetes NetworkPolicies in the cluster" />} />
              ) : (
                <DataTable columns={ciliumColumns} rows={s.cilium_policies} rowKey={(p) => `${p.namespace}/${p.name}`} searchText={(p) => `${p.namespace} ${p.name} ${p.description ?? ''}`} searchPlaceholder="Search policies…" empty={<EmptyState compact title="No CiliumNetworkPolicies" description="Either Cilium is not installed or no policies exist." />} />
              )}
            </>
          )}
        </Card>
      )}
    </div>
  )
}
