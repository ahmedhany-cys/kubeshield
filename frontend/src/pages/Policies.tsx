import { useMemo, useState } from 'react'
import { api } from '../api/client'
import type { KyvernoPolicy, PolicyViolation } from '../api/types'
import { SEVERITIES, type Severity } from '../api/types'
import { Badge, StatusBadge } from '../components/Badge'
import { Card, PageHeader, Section } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, UnavailableState } from '../components/ErrorState'
import { ChipGroup, Select } from '../components/Form'
import { JsonView } from '../components/JsonView'
import { KeyValueGrid } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatCard } from '../components/StatCard'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { formatDateTime, formatNumber, parseDate } from '../lib/format'

const sevRank = (s: string) => 4 - (SEVERITIES as string[]).indexOf(s)

const policyColumns: Column<KyvernoPolicy>[] = [
  {
    key: 'title',
    header: 'Policy',
    render: (p) => (
      <div className="min-w-0 max-w-[380px]">
        <div className="truncate font-medium text-fg">{p.title}</div>
        <div className="truncate font-mono text-[11.5px] text-subtle">{p.name}</div>
      </div>
    ),
    sortValue: (p) => p.title,
  },
  { key: 'control', header: 'Control', render: (p) => (p.control ? <span className="font-mono text-[12px]">{p.control}</span> : <span className="text-subtle">—</span>), sortValue: (p) => p.control ?? '' },
  { key: 'severity', header: 'Severity', render: (p) => <SeverityBadge severity={p.severity} />, sortValue: (p) => sevRank(p.severity) },
  { key: 'mode', header: 'Mode', render: (p) => <Badge tone={p.mode === 'enforce' ? 'ok' : 'warn'}>{p.mode}</Badge>, sortValue: (p) => p.mode },
  {
    key: 'ready',
    header: 'Ready',
    render: (p) => (p.ready === null ? <span className="text-subtle">unknown</span> : <Badge tone={p.ready ? 'ok' : 'bad'} dot>{p.ready ? 'Ready' : 'Not ready'}</Badge>),
    sortValue: (p) => (p.ready ? 1 : 0),
  },
  { key: 'open', header: 'Open violations', render: (p) => <span className={p.open_violations ? 'text-sev-high' : 'text-subtle'}>{formatNumber(p.open_violations)}</span>, sortValue: (p) => p.open_violations, align: 'right' },
  { key: 'denials', header: 'Admission denials', render: (p) => <span className={p.admission_denials ? 'text-sev-critical' : 'text-subtle'}>{formatNumber(p.admission_denials)}</span>, sortValue: (p) => p.admission_denials, align: 'right' },
  { key: 'remediation', header: 'Remediation', render: (p) => <span className="line-clamp-2 max-w-[320px] text-[12px] text-muted" title={p.remediation}>{p.remediation || '—'}</span> },
]

const violationColumns: Column<PolicyViolation>[] = [
  { key: 'severity', header: 'Severity', render: (v) => <SeverityBadge severity={v.severity} />, sortValue: (v) => sevRank(v.severity) },
  {
    key: 'policy',
    header: 'Policy',
    render: (v) => (
      <div className="min-w-0 max-w-[260px]">
        <div className="truncate font-mono text-[12px] text-fg">{v.policy}</div>
        {v.control && <div className="truncate text-[11.5px] text-subtle">{v.control}</div>}
      </div>
    ),
    sortValue: (v) => v.policy,
  },
  { key: 'source', header: 'Source', render: (v) => <Badge tone={v.source === 'admission' ? 'bad' : 'neutral'}>{v.source === 'admission' ? 'admission' : 'policy report'}</Badge>, sortValue: (v) => v.source },
  { key: 'result', header: 'Result', render: (v) => <StatusBadge status={v.result} />, sortValue: (v) => v.result },
  {
    key: 'resource',
    header: 'Resource',
    render: (v) => (
      <div className="min-w-0 max-w-[280px]">
        <div className="truncate font-mono text-[12px] text-fg">{v.resource_kind}/{v.resource_name}</div>
        <div className="truncate text-[11.5px] text-subtle">{v.namespace ?? 'cluster-scoped'}</div>
      </div>
    ),
    sortValue: (v) => `${v.namespace}/${v.resource_name}`,
  },
  { key: 'message', header: 'Message', render: (v) => <span className="line-clamp-2 max-w-[360px] text-[12px] text-muted" title={v.message ?? undefined}>{v.message ?? '—'}</span> },
  { key: 'status', header: 'Status', render: (v) => <StatusBadge status={v.status} />, sortValue: (v) => v.status },
  { key: 'last', header: 'Last seen', render: (v) => <Time value={v.last_seen} />, sortValue: (v) => parseDate(v.last_seen)?.getTime() ?? 0, align: 'right' },
]

export default function PoliciesPage() {
  const policies = useApi((s) => api.policies(s), [], { interval: 60_000 })
  const [source, setSource] = useState('')
  const [status, setStatus] = useState('')
  const [namespace, setNamespace] = useState('')
  const [severity, setSeverity] = useState<Severity[]>([])
  const [selected, setSelected] = useState<PolicyViolation | null>(null)
  const [selectedPolicy, setSelectedPolicy] = useState<KyvernoPolicy | null>(null)
  const query = { source: source || undefined, status: status || undefined, namespace: namespace || undefined, severity, limit: 1000 }
  const violations = useApi((s) => api.violations(query, s), [query], { interval: 30_000 })
  const allViolations = useApi((s) => api.violations({ limit: 1000 }, s), [])

  const namespaces = useMemo(
    () => [...new Set((allViolations.data?.items ?? []).map((v) => v.namespace).filter((n): n is string => Boolean(n)))].sort(),
    [allViolations.data],
  )
  const p = policies.data
  const enforce = p?.policies.filter((x) => x.mode === 'enforce').length ?? 0
  const openTotal = p?.policies.reduce((n, x) => n + x.open_violations, 0) ?? 0
  const deniedTotal = p?.policies.reduce((n, x) => n + x.admission_denials, 0) ?? 0

  return (
    <div>
      <PageHeader
        title="Policy violations"
        description="Kyverno validating policies, background PolicyReport results and admission requests blocked in enforce mode."
      />
      {policies.initialLoading && <Loading />}
      {policies.error && !p ? <ErrorState error={policies.error} onRetry={policies.reload} /> : null}
      {p && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="Policies" value={p.available ? formatNumber(p.policies.length) : '—'} sub={p.available ? `${enforce} enforce · ${p.policies.length - enforce} audit` : 'Kyverno unavailable'} />
            <StatCard label="Open violations" value={formatNumber(openTotal)} tone={openTotal > 0 ? 'warn' : 'neutral'} sub="Across all policies" />
            <StatCard label="Admission denials" value={formatNumber(deniedTotal)} tone={deniedTotal > 0 ? 'bad' : 'neutral'} sub="Requests blocked at admission" />
            <StatCard label="Policies not ready" value={formatNumber(p.policies.filter((x) => x.ready === false).length)} />
          </div>
          <Card className="mb-4" title="Kyverno policies" flush>
            {!p.available ? (
              <div className="p-4"><UnavailableState title="Kyverno policies could not be listed" detail={p.error} /></div>
            ) : (
              <DataTable
                columns={policyColumns}
                rows={p.policies}
                rowKey={(x) => x.name}
                searchText={(x) => `${x.title} ${x.name} ${x.control ?? ''}`}
                searchPlaceholder="Search policies…"
                onRowClick={setSelectedPolicy}
                selectedKey={selectedPolicy?.name}
                empty={<EmptyState compact title="No Kyverno validating policies installed" />}
              />
            )}
          </Card>
        </>
      )}
      <Card title="Violations" flush>
        <div className="flex flex-col gap-2 border-b border-border px-3 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <Select value={source} onChange={setSource} options={[{ value: 'report', label: 'Policy report' }, { value: 'admission', label: 'Admission (blocked)' }]} placeholder="All sources" label="Source" />
            <Select value={status} onChange={setStatus} options={[{ value: 'open', label: 'Open' }, { value: 'resolved', label: 'Resolved' }, { value: 'blocked', label: 'Blocked' }]} placeholder="Any status" label="Status" />
            <Select value={namespace} onChange={setNamespace} options={namespaces} placeholder="All namespaces" label="Namespace" />
          </div>
          <ChipGroup label="Severity" options={SEVERITIES} value={severity} onChange={setSeverity} />
        </div>
        {violations.error ? <div className="p-3"><ErrorState error={violations.error} onRetry={violations.reload} compact /></div> : null}
        <DataTable
          columns={violationColumns}
          rows={violations.data?.items}
          rowKey={(v) => v.id}
          loading={violations.initialLoading}
          searchText={(v) => `${v.policy} ${v.resource_name ?? ''} ${v.namespace ?? ''} ${v.message ?? ''}`}
          searchPlaceholder="Search policy, resource, message…"
          onRowClick={setSelected}
          selectedKey={selected?.id}
          pageSize={50}
          empty={<EmptyState title="No policy violations" description="Violations appear from Kyverno PolicyReports (audit) and denied admission requests (enforce)." />}
        />
      </Card>

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.resource_kind}/${selected.resource_name}` : ''}
        subtitle={selected && <span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={selected.severity} /><span className="font-mono">{selected.policy}</span><StatusBadge status={selected.status} /></span>}
      >
        {selected && (
          <>
            <Section title="Violation">
              <KeyValueGrid
                items={[
                  { label: 'Source', value: selected.source === 'admission' ? 'Admission request denied' : 'Background PolicyReport' },
                  { label: 'Result', value: selected.result },
                  { label: 'Policy mode', value: selected.mode },
                  { label: 'Control', value: selected.control, mono: true },
                  { label: 'Namespace', value: selected.namespace ?? 'cluster-scoped', mono: true },
                  { label: 'Resource', value: `${selected.resource_kind}/${selected.resource_name}`, mono: true },
                  { label: 'First seen', value: formatDateTime(selected.first_seen) },
                  { label: 'Last seen', value: formatDateTime(selected.last_seen) },
                ]}
              />
            </Section>
            <Section title="Message">
              <p className="whitespace-pre-wrap rounded-md border border-border bg-surface-2 px-3 py-2.5 font-mono text-[12px] text-muted">{selected.message ?? '—'}</p>
            </Section>
            <Section title="Remediation">
              <p className="rounded-md border border-ok/25 bg-ok/[0.05] px-3 py-2.5 text-[13px] leading-relaxed text-fg">{selected.remediation || '—'}</p>
            </Section>
          </>
        )}
      </Drawer>

      <Drawer
        open={Boolean(selectedPolicy)}
        onClose={() => setSelectedPolicy(null)}
        title={selectedPolicy?.title}
        subtitle={selectedPolicy && <span className="font-mono">{selectedPolicy.name}</span>}
      >
        {selectedPolicy && (
          <>
            <Section title="Policy">
              <KeyValueGrid
                items={[
                  { label: 'Control', value: selectedPolicy.control, mono: true },
                  { label: 'Severity', value: <SeverityBadge severity={selectedPolicy.severity} /> },
                  { label: 'Mode', value: selectedPolicy.mode },
                  { label: 'Validation actions', value: selectedPolicy.validation_actions.join(', ') },
                  { label: 'Background scans', value: selectedPolicy.background ? 'Enabled' : 'Disabled' },
                  { label: 'Ready', value: selectedPolicy.ready === null ? 'unknown' : selectedPolicy.ready ? 'Yes' : 'No' },
                  { label: 'Status message', value: selectedPolicy.message, hidden: !selectedPolicy.message },
                  { label: 'Managed by KubeShield', value: selectedPolicy.managed_by_kubeshield ? 'Yes' : 'No' },
                ]}
              />
            </Section>
            <Section title="Validation rules">
              {selectedPolicy.rules.filter(Boolean).length ? (
                <ul className="list-disc space-y-1 pl-5 text-[13px] text-fg">
                  {selectedPolicy.rules.filter(Boolean).map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              ) : (
                <p className="text-[12.5px] text-subtle">No rule messages defined.</p>
              )}
            </Section>
            <Section title="Remediation">
              <p className="text-[13px] leading-relaxed text-fg">{selectedPolicy.remediation || '—'}</p>
            </Section>
            <Section title="Namespace selector">
              <JsonView value={selectedPolicy.namespace_selector} title="matchConstraints.namespaceSelector" defaultOpen />
            </Section>
          </>
        )}
      </Drawer>
    </div>
  )
}
