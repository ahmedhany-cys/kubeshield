import { useCallback, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { api } from '../api/client'
import type { ClusterNamespace, ClusterNode, ClusterPod, PostureFinding } from '../api/types'
import { SEVERITIES, type Severity } from '../api/types'
import { Badge, StatusBadge } from '../components/Badge'
import { Button } from '../components/Button'
import { Card, PageHeader, Section } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, InlineError, UnavailableState } from '../components/ErrorState'
import { ChipGroup, SearchInput, Select } from '../components/Form'
import { IntegrationList } from '../components/IntegrationList'
import { KeyValueGrid, KeyValueTable } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatCard } from '../components/StatCard'
import { Tabs } from '../components/Tabs'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { formatDateTime, formatNumber, humanize, parseDate, relativeTime } from '../lib/format'

type TabKey = 'overview' | 'namespaces' | 'pods' | 'posture'
const sevRank = (s: string) => 4 - (SEVERITIES as string[]).indexOf(s)

const nodeColumns: Column<ClusterNode>[] = [
  { key: 'name', header: 'Node', render: (n) => <span className="font-mono text-[12.5px] text-fg">{n.name}</span>, sortValue: (n) => n.name },
  { key: 'ready', header: 'Status', render: (n) => <Badge tone={n.ready ? 'ok' : 'bad'} dot>{n.ready ? 'Ready' : 'NotReady'}</Badge>, sortValue: (n) => (n.ready ? 1 : 0) },
  { key: 'roles', header: 'Roles', render: (n) => (n.roles.length ? n.roles.join(', ') : <span className="text-subtle">worker</span>) },
  { key: 'kubelet', header: 'Kubelet', render: (n) => <span className="font-mono text-[12px]">{n.kubelet ?? '—'}</span> },
  { key: 'os', header: 'OS / kernel', render: (n) => <div className="text-[12px]"><div>{n.os ?? '—'}</div><div className="font-mono text-subtle">{n.kernel}</div></div> },
  { key: 'runtime', header: 'Runtime', render: (n) => <span className="font-mono text-[12px]">{n.runtime ?? '—'}</span> },
  { key: 'capacity', header: 'Capacity', render: (n) => <span className="text-[12px] tabular-nums">{n.cpu ?? '—'} CPU · {n.memory ?? '—'}</span> },
  { key: 'arch', header: 'Arch', render: (n) => n.arch ?? '—' },
]

const nsColumns: Column<ClusterNamespace>[] = [
  {
    key: 'name',
    header: 'Namespace',
    render: (n) => (
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-[12.5px] text-fg">{n.name}</span>
        {n.lab && <Badge tone="accent">lab</Badge>}
        {n.platform && <Badge>platform</Badge>}
      </div>
    ),
    sortValue: (n) => n.name,
  },
  {
    key: 'mode',
    header: 'Policy mode',
    render: (n) => (n.policy_mode ? <Badge tone={n.policy_mode === 'enforce' ? 'ok' : 'warn'}>{n.policy_mode}</Badge> : <span className="text-subtle">—</span>),
    sortValue: (n) => n.policy_mode ?? '',
  },
  { key: 'pods', header: 'Pods', render: (n) => formatNumber(n.pods), sortValue: (n) => n.pods, align: 'right' },
  { key: 'np', header: 'NetworkPolicies', render: (n) => formatNumber(n.network_policies), sortValue: (n) => n.network_policies, align: 'right' },
  { key: 'cnp', header: 'Cilium policies', render: (n) => formatNumber(n.cilium_policies), sortValue: (n) => n.cilium_policies, align: 'right' },
  { key: 'phase', header: 'Phase', render: (n) => n.phase ?? '—' },
]

const podColumns: Column<ClusterPod>[] = [
  {
    key: 'name',
    header: 'Pod',
    render: (p) => (
      <div className="min-w-0 max-w-[340px]">
        <div className="truncate font-mono text-[12.5px] text-fg">{p.name}</div>
        <div className="truncate text-[11.5px] text-subtle">{p.namespace}{p.owner ? ` · ${p.owner}` : ''}</div>
      </div>
    ),
    sortValue: (p) => `${p.namespace}/${p.name}`,
  },
  {
    key: 'phase',
    header: 'Status',
    render: (p) => (
      <Badge tone={p.phase === 'Running' && p.ready ? 'ok' : p.phase === 'Running' ? 'warn' : p.phase === 'Failed' ? 'bad' : 'neutral'} dot>
        {p.phase ?? 'Unknown'}{p.phase === 'Running' && !p.ready ? ' (not ready)' : ''}
      </Badge>
    ),
    sortValue: (p) => p.phase ?? '',
  },
  {
    key: 'flags',
    header: 'Security flags',
    render: (p) => {
      const flags = [
        p.privileged && <Badge key="priv" tone="critical">privileged</Badge>,
        p.host_network && <Badge key="hn" tone="high">hostNetwork</Badge>,
        p.host_pid && <Badge key="hp" tone="critical">hostPID</Badge>,
        p.quarantined && <Badge key="q" tone="accent" title={`kubeshield.io/quarantine=${p.quarantined}`}>quarantined</Badge>,
      ].filter(Boolean)
      return flags.length ? <div className="flex flex-wrap gap-1">{flags}</div> : <span className="text-subtle">—</span>
    },
    sortValue: (p) => Number(p.privileged) * 4 + Number(p.host_pid) * 2 + Number(p.host_network) + (p.quarantined ? 8 : 0),
  },
  {
    key: 'images',
    header: 'Images',
    render: (p) => (
      <div className="max-w-[300px] space-y-0.5">
        {p.images.map((i) => (
          <div key={i} className="truncate font-mono text-[11.5px] text-muted" title={i}>{i}</div>
        ))}
      </div>
    ),
  },
  { key: 'node', header: 'Node', render: (p) => <span className="font-mono text-[12px]">{p.node ?? '—'}</span>, sortValue: (p) => p.node ?? '' },
  { key: 'restarts', header: 'Restarts', render: (p) => formatNumber(p.restarts), sortValue: (p) => p.restarts, align: 'right' },
  { key: 'created', header: 'Age', render: (p) => <Time value={p.created} />, sortValue: (p) => parseDate(p.created)?.getTime() ?? 0, align: 'right' },
]

export default function ClusterPage() {
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as TabKey) || 'overview'
  const setTab = (t: TabKey) => setParams((p) => { const n = new URLSearchParams(p); n.set('tab', t); return n }, { replace: true })
  const { can } = useAuth()
  const cluster = useApi((s) => api.cluster(s), [], { interval: 60_000 })
  const findingsCount = useApi((s) => api.postureFindings({ status: 'open' }, s), [])
  const refresh = useMutation(api.refreshCluster)
  const [podFilter, setPodFilter] = useState<'all' | 'workload' | 'flagged'>('workload')

  const onRefresh = async () => {
    const r = await refresh.run()
    if (r) {
      cluster.reload()
      findingsCount.reload()
    }
  }

  const c = cluster.data
  const header = (
    <PageHeader
      title="Kubernetes cluster"
      description="Inventory snapshot of nodes, namespaces and pods with integration health and security posture findings."
      actions={
        <>
          {c?.available && <span className="text-[12px] text-subtle">Snapshot {relativeTime(c.snapshot_at)}</span>}
          {can('responder') && (
            <Button size="sm" icon={<RefreshCw className="h-3.5 w-3.5" />} onClick={onRefresh} loading={refresh.pending}>
              Refresh inventory
            </Button>
          )}
        </>
      }
    />
  )

  if (cluster.initialLoading) return <>{header}<Loading /></>
  if (!c) return <>{header}<ErrorState error={cluster.error} onRetry={cluster.reload} /></>

  return (
    <div>
      {header}
      <InlineError message={refresh.error} />
      {!c.available ? (
        <UnavailableState title="Cluster inventory unavailable" detail={c.error}>
          KubeShield has not recorded a successful inventory snapshot. Check the Kubernetes connection on the Settings page.
        </UnavailableState>
      ) : (
        <>
          {c.last_error && (
            <div className="mb-4">
              <UnavailableState label="Stale" title="Latest inventory refresh failed; showing the last good snapshot" detail={c.last_error} />
            </div>
          )}
          <Tabs<TabKey>
            className="mb-4"
            value={tab}
            onChange={setTab}
            tabs={[
              { key: 'overview', label: 'Overview' },
              { key: 'namespaces', label: 'Namespaces', count: c.namespaces.length },
              { key: 'pods', label: 'Pods', count: c.pods.length },
              { key: 'posture', label: 'Posture findings', count: findingsCount.data?.total },
            ]}
          />
          {tab === 'overview' && (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                <StatCard label="Kubernetes" value={<span className="text-[18px]">{c.kubernetes_version ?? '—'}</span>} sub={c.platform ?? undefined} />
                <StatCard label="Nodes ready" value={`${c.nodes.filter((n) => n.ready).length}/${c.nodes.length}`} />
                <StatCard label="Namespaces" value={formatNumber(c.counts.namespaces)} sub={`${formatNumber(c.counts.lab_namespaces)} lab namespaces`} />
                <StatCard label="Pods" value={formatNumber(c.counts.pods)} sub={`${formatNumber(c.counts.deployments)} deployments · ${formatNumber(c.counts.daemonsets)} daemonsets`} />
                <StatCard label="Privileged workload pods" value={formatNumber(c.counts.privileged_pods)} tone={(c.counts.privileged_pods ?? 0) > 0 ? 'bad' : 'neutral'} sub="Excludes platform namespaces" />
                <StatCard label="Network policies" value={formatNumber((c.counts.network_policies ?? 0) + (c.counts.cilium_network_policies ?? 0))} sub={`${formatNumber(c.counts.network_policies)} Kubernetes · ${formatNumber(c.counts.cilium_network_policies)} Cilium`} />
              </div>
              <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
                <Card className="xl:col-span-2" title="Nodes" flush>
                  <DataTable columns={nodeColumns} rows={c.nodes} rowKey={(n) => n.name} empty={<EmptyState compact title="No nodes reported" />} />
                </Card>
                <Card title="Security integrations" subtitle="Workload readiness in the cluster">
                  {c.integrations.length ? <IntegrationList items={c.integrations} /> : <EmptyState compact title="No integrations reported" />}
                </Card>
              </div>
            </>
          )}
          {tab === 'namespaces' && (
            <Card flush>
              <DataTable
                columns={nsColumns}
                rows={c.namespaces}
                rowKey={(n) => n.name}
                searchText={(n) => `${n.name} ${n.policy_mode ?? ''}`}
                searchPlaceholder="Search namespaces…"
                initialSort={{ key: 'name', dir: 'asc' }}
                pageSize={50}
              />
            </Card>
          )}
          {tab === 'pods' && (
            <Card flush>
              <DataTable
                columns={podColumns}
                rows={c.pods.filter((p) =>
                  podFilter === 'all' ? true : podFilter === 'workload' ? !p.platform : p.privileged || p.host_network || p.host_pid || p.quarantined,
                )}
                rowKey={(p) => `${p.namespace}/${p.name}`}
                searchText={(p) => `${p.namespace} ${p.name} ${p.images.join(' ')} ${p.node ?? ''} ${p.owner ?? ''}`}
                searchPlaceholder="Search pods, images, nodes…"
                toolbar={
                  <Select
                    value={podFilter}
                    onChange={(v) => setPodFilter(v as typeof podFilter)}
                    options={[
                      { value: 'workload', label: 'Workload namespaces' },
                      { value: 'all', label: 'All namespaces' },
                      { value: 'flagged', label: 'Flagged or quarantined' },
                    ]}
                    label="Pod filter"
                  />
                }
                pageSize={50}
              />
            </Card>
          )}
          {tab === 'posture' && <PostureFindings />}
        </>
      )}
    </div>
  )
}

function PostureFindings() {
  const [severity, setSeverity] = useState<Severity[]>([])
  const [category, setCategory] = useState('')
  const [status, setStatus] = useState('open')
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<PostureFinding | null>(null)
  const query = { status, severity, category: category || undefined, q: q || undefined }
  const findings = useApi((s) => api.postureFindings(query, s), [query])
  const onSearch = useCallback((v: string) => setQ(v), [])
  const categories = Object.keys(findings.data?.by_category ?? {}).sort()
  if (category && !categories.includes(category)) categories.push(category)

  const columns: Column<PostureFinding>[] = [
    { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} />, sortValue: (f) => sevRank(f.severity), className: 'w-24' },
    {
      key: 'title',
      header: 'Finding',
      render: (f) => (
        <div className="min-w-0 max-w-[440px]">
          <div className="truncate font-medium text-fg">{f.title}</div>
          <div className="truncate font-mono text-[11.5px] text-subtle">{f.check_id}</div>
        </div>
      ),
      sortValue: (f) => f.title,
    },
    { key: 'category', header: 'Category', render: (f) => <Badge>{f.category}</Badge>, sortValue: (f) => f.category },
    {
      key: 'resource',
      header: 'Resource',
      render: (f) => (
        <div className="min-w-0 max-w-[300px]">
          <div className="truncate font-mono text-[12px] text-fg">{f.resource_kind}/{f.resource_name}</div>
          <div className="truncate text-[11.5px] text-subtle">{f.namespace ?? 'cluster-scoped'}{f.container ? ` · ${f.container}` : ''}</div>
        </div>
      ),
      sortValue: (f) => `${f.namespace}/${f.resource_name}`,
    },
    { key: 'last_seen', header: 'Last seen', render: (f) => <Time value={f.last_seen} />, sortValue: (f) => parseDate(f.last_seen)?.getTime() ?? 0, align: 'right' },
  ]

  return (
    <>
      {findings.error ? <div className="mb-3"><ErrorState error={findings.error} onRetry={findings.reload} /></div> : null}
      <Card flush>
        <div className="flex flex-col gap-2 border-b border-border px-3 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={q} onChange={onSearch} debounce={300} placeholder="Search title or resource…" className="w-full sm:w-72" />
            <Select value={category} onChange={setCategory} options={categories.map((c) => ({ value: c, label: `${c} (${findings.data?.by_category[c] ?? 0})` }))} placeholder="All categories" label="Category" />
            <Select value={status} onChange={setStatus} options={[{ value: 'open', label: 'Open' }, { value: 'resolved', label: 'Resolved' }]} label="Status" />
          </div>
          <ChipGroup label="Severity" options={SEVERITIES} value={severity} onChange={setSeverity} />
        </div>
        <DataTable
          columns={columns}
          rows={findings.data?.items}
          rowKey={(f) => f.id}
          loading={findings.initialLoading}
          onRowClick={setSelected}
          selectedKey={selected?.id}
          empty={
            <EmptyState
              title={status === 'open' ? 'No open posture findings' : 'No resolved findings'}
              description="Findings are produced from each inventory snapshot (workload security context, RBAC and network isolation checks)."
            />
          }
        />
      </Card>
      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.title}
        subtitle={
          selected && (
            <span className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={selected.severity} />
              <Badge>{selected.category}</Badge>
              <span className="font-mono">{selected.check_id}</span>
              <StatusBadge status={selected.status} />
            </span>
          )
        }
      >
        {selected && (
          <>
            <Section title="Resource">
              <KeyValueGrid
                items={[
                  { label: 'Kind', value: selected.resource_kind },
                  { label: 'Namespace', value: selected.namespace ?? 'cluster-scoped', mono: true },
                  { label: 'Name', value: selected.resource_name, mono: true },
                  { label: 'Container', value: selected.container, mono: true, hidden: !selected.container },
                  { label: 'First seen', value: formatDateTime(selected.first_seen) },
                  { label: 'Last seen', value: formatDateTime(selected.last_seen) },
                  { label: 'Resolved', value: formatDateTime(selected.resolved_at), hidden: !selected.resolved_at },
                ]}
              />
            </Section>
            <Section title="Why it matters">
              <p className="text-[13px] leading-relaxed text-fg">{selected.explanation ?? '—'}</p>
            </Section>
            <Section title="Evidence">
              <KeyValueTable data={selected.evidence} />
            </Section>
            <Section title="Remediation">
              <p className="rounded-md border border-ok/25 bg-ok/[0.05] px-3 py-2.5 text-[13px] leading-relaxed text-fg">
                {selected.remediation ?? '—'}
              </p>
            </Section>
            <p className="text-[11.5px] text-subtle">Category: {humanize(selected.category)}</p>
          </>
        )}
      </Drawer>
    </>
  )
}
