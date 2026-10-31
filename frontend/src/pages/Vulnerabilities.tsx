import { useCallback, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ExternalLink, Play, ScanLine } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { ImageFinding, ImageScan, PreflightResult, SbomComponent, Vulnerability } from '../api/types'
import { SEVERITIES, type Severity } from '../api/types'
import { Badge, StatusBadge } from '../components/Badge'
import { Button } from '../components/Button'
import { Card, PageHeader, Section } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, InlineError, UnavailableState } from '../components/ErrorState'
import { ChipGroup, SearchInput } from '../components/Form'
import { KeyValueGrid, KeyValueTable } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { SeverityBadge, SeverityCounts } from '../components/SeverityBadge'
import { Tabs } from '../components/Tabs'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { formatDateTime, formatDuration, formatNumber, parseDate } from '../lib/format'

type TabKey = 'images' | 'scans' | 'preflight'
const sevRank = (s: string) => 4 - (SEVERITIES as string[]).indexOf(s)

export default function VulnerabilitiesPage() {
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as TabKey) || 'images'
  const selectedScan = params.get('scan')
  const setParam = (k: string, v: string | null) =>
    setParams((p) => {
      const n = new URLSearchParams(p)
      if (v) n.set(k, v)
      else n.delete(k)
      return n
    }, { replace: true })
  const { can } = useAuth()

  const images = useApi((s) => api.images(s), [], { interval: 15_000 })
  const data = images.data

  const imageColumns: Column<ImageScan>[] = [
    {
      key: 'image',
      header: 'Image',
      render: (s) => (
        <div className="min-w-0 max-w-[380px]">
          <div className="truncate font-mono text-[12.5px] text-fg" title={s.image}>{s.image}</div>
          <div className="truncate text-[11.5px] text-subtle">{s.os_family ?? 'OS unknown'}</div>
        </div>
      ),
      sortValue: (s) => s.image,
    },
    {
      key: 'counts',
      header: 'Crit · High · Med · Low',
      render: (s) => <SeverityCounts counts={s.counts} />,
      sortValue: (s) => (s.counts?.critical ?? 0) * 1e6 + (s.counts?.high ?? 0) * 1e3 + (s.counts?.medium ?? 0),
    },
    { key: 'secrets', header: 'Secrets', render: (s) => <span className={s.secret_count ? 'text-sev-critical' : 'text-subtle'}>{s.secret_count ?? '—'}</span>, sortValue: (s) => s.secret_count ?? 0, align: 'right' },
    { key: 'misconfig', header: 'Misconfigs', render: (s) => <span className={s.misconfig_count ? 'text-sev-medium' : 'text-subtle'}>{s.misconfig_count ?? '—'}</span>, sortValue: (s) => s.misconfig_count ?? 0, align: 'right' },
    { key: 'sbom', header: 'SBOM', render: (s) => (s.sbom_components !== null ? formatNumber(s.sbom_components) : <span className="text-subtle">—</span>), sortValue: (s) => s.sbom_components ?? -1, align: 'right' },
    {
      key: 'workloads',
      header: 'Workloads',
      render: (s) =>
        s.workloads && s.workloads.length ? (
          <span title={s.workloads.join('\n')} className="text-[12px]">
            <span className="font-mono">{s.workloads[0]}</span>
            {s.workloads.length > 1 && <span className="text-subtle"> +{s.workloads.length - 1}</span>}
          </span>
        ) : (
          <span className="text-subtle">—</span>
        ),
      sortValue: (s) => s.workloads?.length ?? 0,
    },
    { key: 'scanned', header: 'Scanned', render: (s) => <Time value={s.finished_at} />, sortValue: (s) => parseDate(s.finished_at)?.getTime() ?? 0, align: 'right' },
  ]

  const scanColumns: Column<ImageScan>[] = [
    { key: 'image', header: 'Image', render: (s) => <span className="font-mono text-[12.5px] text-fg">{s.image}</span>, sortValue: (s) => s.image },
    { key: 'status', header: 'Status', render: (s) => <StatusBadge status={s.status} /> , sortValue: (s) => s.status },
    { key: 'trigger', header: 'Trigger', render: (s) => <Badge>{s.trigger ?? '—'}</Badge> },
    { key: 'by', header: 'Requested by', render: (s) => s.requested_by ?? '—' },
    { key: 'result', header: 'Result', render: (s) => (s.status === 'succeeded' ? <SeverityCounts counts={s.counts} /> : s.error ? <span className="line-clamp-2 max-w-[360px] text-[12px] text-bad" title={s.error}>{s.error}</span> : <span className="text-subtle">—</span>) },
    { key: 'duration', header: 'Duration', render: (s) => formatDuration(s.started_at, s.finished_at), align: 'right' },
    { key: 'started', header: 'Started', render: (s) => <Time value={s.started_at} />, sortValue: (s) => parseDate(s.started_at)?.getTime() ?? 0, align: 'right' },
  ]

  return (
    <div>
      <PageHeader
        title="Container vulnerabilities"
        description="Trivy image scans (CVEs, embedded secrets, misconfigurations, SBOM) and a pre-deployment gate for manifests."
      />
      {images.error && !data ? <ErrorState error={images.error} onRetry={images.reload} /> : null}
      {images.initialLoading && <Loading />}
      {data && (
        <>
          <div className="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
            <Card title="Scanner">
              {data.scanner.available ? (
                <div className="flex items-center gap-2 text-[13px]">
                  <Badge tone="ok" dot>Available</Badge>
                  <span className="text-muted">Trivy {data.scanner.version ?? '(version unknown)'}</span>
                </div>
              ) : (
                <UnavailableState title="Trivy scanner not available" detail="The trivy binary could not be executed by the backend. New scans and pre-deployment checks will fail until it is installed." />
              )}
            </Card>
            <div className="lg:col-span-2">{can('responder') && <ScanForm disabled={!data.scanner.available} onQueued={() => { images.reload(); setParam('tab', 'scans') }} />}</div>
          </div>
          <Tabs<TabKey>
            className="mb-4"
            value={tab}
            onChange={(t) => setParam('tab', t)}
            tabs={[
              { key: 'images', label: 'Images', count: data.images.length },
              { key: 'scans', label: 'Recent scans', count: data.recent_scans.length },
              { key: 'preflight', label: 'Pre-deployment check' },
            ]}
          />
          {tab === 'images' && (
            <Card flush subtitle="Latest successful scan per image, sorted by critical then high findings">
              <DataTable
                columns={imageColumns}
                rows={data.images}
                rowKey={(s) => s.id}
                searchText={(s) => `${s.image} ${s.os_family ?? ''} ${(s.workloads ?? []).join(' ')}`}
                searchPlaceholder="Search images or workloads…"
                onRowClick={(s) => setParam('scan', s.id)}
                selectedKey={selectedScan}
                empty={
                  <EmptyState
                    title="No images scanned yet"
                    description={data.scanner.available ? 'Workload images are scanned automatically after each inventory snapshot, or scan one manually above.' : 'Install Trivy to enable image scanning.'}
                  />
                }
              />
            </Card>
          )}
          {tab === 'scans' && (
            <Card flush>
              <DataTable
                columns={scanColumns}
                rows={data.recent_scans}
                rowKey={(s) => s.id}
                onRowClick={(s) => setParam('scan', s.id)}
                empty={<EmptyState title="No scans recorded" />}
              />
            </Card>
          )}
          {tab === 'preflight' && <Preflight canRun={can('responder')} />}
        </>
      )}
      <ScanDrawer scanId={selectedScan} onClose={() => setParam('scan', null)} />
    </div>
  )
}

function ScanForm({ onQueued, disabled }: { onQueued: () => void; disabled: boolean }) {
  const [image, setImage] = useState('')
  const [queued, setQueued] = useState<ImageScan | null>(null)
  const m = useMutation(api.requestScan)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const r = await m.run(image.trim())
    if (r) {
      setQueued(r)
      setImage('')
      onQueued()
    }
  }
  return (
    <Card title="Scan an image" subtitle="Queue a Trivy vulnerability, secret and SBOM scan">
      <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row">
        <input
          className="input h-8 flex-1 font-mono"
          placeholder="registry/repository:tag"
          value={image}
          onChange={(e) => setImage(e.target.value)}
          minLength={3}
          maxLength={512}
          required
          aria-label="Image reference"
        />
        <Button type="submit" variant="primary" icon={<ScanLine className="h-3.5 w-3.5" />} loading={m.pending} disabled={disabled || image.trim().length < 3}>
          Scan image
        </Button>
      </form>
      <InlineError message={m.error} />
      {queued && !m.error && (
        <p className="mt-2 text-[12.5px] text-muted">
          Scan <span className="font-mono">{queued.id}</span> for <span className="font-mono">{queued.image}</span> is {queued.status}.
        </p>
      )}
    </Card>
  )
}

type DetailTab = 'vulns' | 'findings' | 'sbom'

function ScanDrawer({ scanId, onClose }: { scanId: string | null; onClose: () => void }) {
  const [tab, setTab] = useState<DetailTab>('vulns')
  const [inFlight, setInFlight] = useState(false)
  const scan = useApi((s) => api.imageScan(scanId!, s), [scanId], { enabled: Boolean(scanId), interval: inFlight ? 5_000 : undefined })
  const d = scan.data
  const nowInFlight = d?.status === 'queued' || d?.status === 'running'
  if (nowInFlight !== inFlight) setInFlight(nowInFlight)
  return (
    <Drawer
      open={Boolean(scanId)}
      onClose={onClose}
      width="max-w-5xl"
      title={<span className="font-mono text-[14px]">{d?.image ?? 'Image scan'}</span>}
      subtitle={
        d && (
          <span className="flex flex-wrap items-center gap-2">
            <StatusBadge status={d.status} />
            <SeverityCounts counts={d.counts} show={['critical', 'high', 'medium', 'low', 'info']} />
            <span>scanned {formatDateTime(d.finished_at)}</span>
          </span>
        )
      }
    >
      {scan.initialLoading && <Loading />}
      {scan.error ? <ErrorState error={scan.error} onRetry={scan.reload} /> : null}
      {d && (
        <>
          {d.error && (
            <div className="mb-4">
              <UnavailableState label={d.status === 'failed' ? 'Scan failed' : 'Error'} title="Trivy reported an error for this scan" detail={d.error} />
            </div>
          )}
          {(d.status === 'queued' || d.status === 'running') && (
            <p className="mb-4 rounded-md border border-accent/30 bg-accent/[0.06] px-3 py-2 text-[12.5px] text-fg">Scan is {d.status}; results appear when it completes.</p>
          )}
          <Section title="Image">
            <KeyValueGrid
              columns={3}
              items={[
                { label: 'Digest', value: d.digest, mono: true },
                { label: 'OS', value: d.os_family },
                { label: 'Scanner', value: d.scanner_version ? `Trivy ${d.scanner_version}` : null },
                { label: 'Trigger', value: d.trigger },
                { label: 'Requested by', value: d.requested_by },
                { label: 'Duration', value: formatDuration(d.started_at, d.finished_at) },
                { label: 'Workloads', value: d.workloads?.length ? d.workloads.join(', ') : null, mono: true },
              ]}
            />
          </Section>
          <Tabs<DetailTab>
            className="mb-3"
            value={tab}
            onChange={setTab}
            tabs={[
              { key: 'vulns', label: 'Vulnerabilities', count: SEVERITIES.reduce((n, s) => n + (d.counts?.[s] ?? 0), 0) },
              { key: 'findings', label: 'Secrets & misconfigurations', count: d.findings.length },
              { key: 'sbom', label: 'SBOM', count: d.sbom_components ?? undefined },
            ]}
          />
          {tab === 'vulns' && <VulnTable scanId={d.id} />}
          {tab === 'findings' && <FindingsTable findings={d.findings} />}
          {tab === 'sbom' && <SbomTable scanId={d.id} />}
        </>
      )}
    </Drawer>
  )
}

function VulnTable({ scanId }: { scanId: string }) {
  const [severity, setSeverity] = useState<Severity[]>([])
  const [fixable, setFixable] = useState(false)
  const [q, setQ] = useState('')
  const onSearch = useCallback((v: string) => setQ(v), [])
  const query = { severity, fixable: fixable || undefined, q: q || undefined, limit: 2000 }
  const vulns = useApi((s) => api.scanVulnerabilities(scanId, query, s), [scanId, query])
  const columns: Column<Vulnerability>[] = [
    {
      key: 'id',
      header: 'Vulnerability',
      render: (v) => (
        <div className="min-w-0 max-w-[360px]">
          <div className="flex items-center gap-1.5">
            {v.primary_url ? (
              <a href={v.primary_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-mono text-[12.5px] text-accent hover:underline">
                {v.vuln_id}
                <ExternalLink className="h-3 w-3" />
              </a>
            ) : (
              <span className="font-mono text-[12.5px] text-fg">{v.vuln_id}</span>
            )}
          </div>
          <div className="line-clamp-2 text-[12px] text-muted" title={v.title ?? undefined}>{v.title ?? '—'}</div>
        </div>
      ),
      sortValue: (v) => v.vuln_id,
    },
    { key: 'severity', header: 'Severity', render: (v) => <SeverityBadge severity={v.severity} />, sortValue: (v) => sevRank(v.severity) },
    { key: 'cvss', header: 'CVSS', render: (v) => (v.cvss_score !== null ? v.cvss_score.toFixed(1) : <span className="text-subtle">—</span>), sortValue: (v) => v.cvss_score ?? -1, align: 'right' },
    {
      key: 'pkg',
      header: 'Package',
      render: (v) => (
        <div className="min-w-0 max-w-[220px]">
          <div className="truncate font-mono text-[12px] text-fg">{v.pkg_name}</div>
          <div className="truncate text-[11px] text-subtle">{v.pkg_type ?? ''}</div>
        </div>
      ),
      sortValue: (v) => v.pkg_name,
    },
    { key: 'installed', header: 'Installed', render: (v) => <span className="font-mono text-[12px]">{v.installed_version ?? '—'}</span> },
    { key: 'fixed', header: 'Fixed in', render: (v) => (v.fixed_version ? <span className="font-mono text-[12px] text-ok">{v.fixed_version}</span> : <span className="text-[12px] text-subtle">no fix</span>) },
    { key: 'remediation', header: 'Remediation', render: (v) => <span className="line-clamp-2 max-w-[280px] text-[12px] text-muted" title={v.remediation}>{v.remediation}</span> },
  ]
  return (
    <div className="rounded-lg border border-border">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2.5">
        <SearchInput value={q} onChange={onSearch} debounce={300} placeholder="Search CVE or package…" className="w-full sm:w-64" />
        <ChipGroup label="Severity" options={SEVERITIES} value={severity} onChange={setSeverity} />
        <label className="flex items-center gap-1.5 text-[12.5px] text-muted">
          <input type="checkbox" checked={fixable} onChange={(e) => setFixable(e.target.checked)} className="accent-[var(--color-accent)]" />
          Fixable only
        </label>
      </div>
      {vulns.error ? <div className="p-3"><ErrorState error={vulns.error} onRetry={vulns.reload} compact /></div> : null}
      <DataTable
        columns={columns}
        rows={vulns.data?.items}
        rowKey={(v) => `${v.vuln_id}|${v.pkg_name}|${v.installed_version}|${v.target}`}
        loading={vulns.initialLoading}
        dense
        empty={<EmptyState compact title="No vulnerabilities match" description="Trivy reported no vulnerabilities for this selection." />}
      />
    </div>
  )
}

function FindingsTable({ findings }: { findings: ImageFinding[] }) {
  const columns: Column<ImageFinding>[] = [
    { key: 'kind', header: 'Type', render: (f) => <Badge tone={f.kind === 'secret' ? 'critical' : 'medium'}>{f.kind}</Badge>, sortValue: (f) => f.kind },
    { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} />, sortValue: (f) => sevRank(f.severity) },
    {
      key: 'title',
      header: 'Finding',
      render: (f) => (
        <div className="min-w-0 max-w-[420px]">
          <div className="font-medium text-fg">{f.title}</div>
          <div className="font-mono text-[11.5px] text-subtle">{f.rule_id}</div>
        </div>
      ),
    },
    { key: 'target', header: 'Target', render: (f) => <span className="font-mono text-[12px]">{f.target ?? '—'}</span> },
    { key: 'details', header: 'Details', render: (f) => <div className="max-w-[360px]"><KeyValueTable data={f.details} /></div> },
  ]
  return (
    <div className="rounded-lg border border-border">
      <p className="border-b border-border px-3 py-2 text-[12px] text-subtle">Secret values are never stored by KubeShield; only the rule, file and line range are kept.</p>
      <DataTable columns={columns} rows={findings} rowKey={(f) => `${f.kind}|${f.rule_id}|${f.target}|${JSON.stringify(f.details)}`} empty={<EmptyState compact title="No secrets or misconfigurations found" />} />
    </div>
  )
}

function SbomTable({ scanId }: { scanId: string }) {
  const sbom = useApi((s) => api.scanSbom(scanId, s), [scanId])
  if (sbom.initialLoading) return <Loading />
  if (sbom.error) {
    if (sbom.error instanceof ApiError && sbom.error.status === 404) {
      return <UnavailableState title="SBOM not available for this scan" detail="Trivy did not produce a CycloneDX SBOM for this image." />
    }
    return <ErrorState error={sbom.error} onRetry={sbom.reload} />
  }
  const d = sbom.data
  if (!d) return null
  const columns: Column<SbomComponent>[] = [
    { key: 'name', header: 'Component', render: (c) => <span className="font-mono text-[12px] text-fg">{c.name ?? '—'}</span>, sortValue: (c) => c.name ?? '' },
    { key: 'version', header: 'Version', render: (c) => <span className="font-mono text-[12px]">{c.version ?? '—'}</span> },
    { key: 'type', header: 'Type', render: (c) => <Badge>{c.type ?? '—'}</Badge>, sortValue: (c) => c.type ?? '' },
    { key: 'purl', header: 'Package URL', render: (c) => <span className="block max-w-[420px] truncate font-mono text-[11.5px] text-subtle" title={c.purl ?? undefined}>{c.purl ?? '—'}</span> },
  ]
  return (
    <div className="rounded-lg border border-border">
      <div className="border-b border-border px-3 py-2 text-[12px] text-subtle">
        {d.format} · {formatNumber(d.component_count)} components{d.truncated ? ` (showing first ${formatNumber(d.components.length)})` : ''}
      </div>
      <DataTable
        columns={columns}
        rows={d.components}
        rowKey={(c) => `${c.purl ?? ''}|${c.name}|${c.version}`}
        searchText={(c) => `${c.name ?? ''} ${c.version ?? ''} ${c.purl ?? ''}`}
        searchPlaceholder="Search components…"
        dense
        pageSize={50}
        empty={<EmptyState compact title="SBOM contains no components" />}
      />
    </div>
  )
}

function Preflight({ canRun }: { canRun: boolean }) {
  const [manifest, setManifest] = useState('')
  const [scanImages, setScanImages] = useState(true)
  const [result, setResult] = useState<PreflightResult | null>(null)
  const m = useMutation(api.preflight)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const r = await m.run(manifest, scanImages)
    if (r) setResult(r)
  }
  const verdictTone = result?.verdict === 'pass' ? 'ok' : result?.verdict === 'warn' ? 'warn' : 'bad'

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Card title="Pre-deployment check" subtitle="Server-side dry run through the admission controllers, Trivy config scan and image scan status">
        <form onSubmit={submit}>
          <textarea
            className="textarea h-80 w-full"
            spellCheck={false}
            placeholder={'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\nspec:\n  ...'}
            value={manifest}
            onChange={(e) => setManifest(e.target.value)}
            aria-label="Kubernetes manifest YAML"
            maxLength={256000}
            disabled={!canRun}
          />
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <label className="flex items-center gap-1.5 text-[12.5px] text-muted">
              <input type="checkbox" checked={scanImages} onChange={(e) => setScanImages(e.target.checked)} className="accent-[var(--color-accent)]" disabled={!canRun} />
              Queue scans for images without a scan
            </label>
            {canRun ? (
              <Button type="submit" variant="primary" icon={<Play className="h-3.5 w-3.5" />} loading={m.pending} disabled={manifest.trim().length < 10}>
                Evaluate manifest
              </Button>
            ) : (
              <span className="text-[12px] text-subtle">Requires the responder role.</span>
            )}
          </div>
          <InlineError message={m.error} />
        </form>
      </Card>
      <Card title="Result">
        {!result ? (
          <EmptyState compact title="No evaluation yet" description="Paste 1–20 Kubernetes objects (Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob, ReplicaSet) and evaluate." />
        ) : (
          <div>
            <div className="mb-4 flex items-center gap-3">
              <Badge tone={verdictTone} className="h-7 px-3 text-[13px] uppercase">{result.verdict}</Badge>
              <span className="text-[12.5px] text-muted">
                Evaluated in namespace <span className="font-mono">{result.namespace}</span> (dry run, nothing was created)
              </span>
            </div>
            <Section title="Admission (Kyverno and API server)">
              <div className="space-y-2">
                {result.resources.map((r, i) => (
                  <div key={`${r.kind}/${r.name}/${i}`} className="rounded-md border border-border bg-surface-2 px-3 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[12.5px] text-fg">{r.kind ?? '?'}/{r.name}</span>
                      <StatusBadge status={r.admission} />
                    </div>
                    {r.message && <p className="mt-1.5 whitespace-pre-wrap break-words font-mono text-[11.5px] text-muted">{r.message}</p>}
                  </div>
                ))}
              </div>
            </Section>
            <Section title="Trivy configuration findings">
              {result.config_findings.error ? (
                <UnavailableState title="Trivy config scan failed" detail={result.config_findings.error} />
              ) : result.config_findings.findings.length === 0 ? (
                <p className="text-[12.5px] text-subtle">No failed configuration checks.</p>
              ) : (
                <div className="space-y-2">
                  {result.config_findings.findings.map((f, i) => (
                    <div key={`${f.id}-${i}`} className="rounded-md border border-border bg-surface-2 px-3 py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-mono text-[11.5px] text-subtle">{f.id}</span>
                        <span className="text-[13px] font-medium text-fg">{f.title}</span>
                      </div>
                      {f.message && <p className="mt-1 text-[12px] text-muted">{f.message}</p>}
                      {f.resolution && <p className="mt-1 text-[12px] text-ok">Fix: {f.resolution}</p>}
                    </div>
                  ))}
                </div>
              )}
            </Section>
            <Section title="Images">
              {result.images.length === 0 ? (
                <p className="text-[12.5px] text-subtle">No container images found in the evaluated objects.</p>
              ) : (
                <div className="space-y-2">
                  {result.images.map((img) => (
                    <div key={img.image} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-surface-2 px-3 py-2">
                      <span className="min-w-0 truncate font-mono text-[12px] text-fg">{img.image}</span>
                      <div className="flex items-center gap-2">
                        {img.counts && <SeverityCounts counts={img.counts} />}
                        <StatusBadge status={img.status} label={img.status === 'not_scanned' ? 'Not scanned' : undefined} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Section>
          </div>
        )}
      </Card>
    </div>
  )
}
