import { useCallback, useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Check, Pencil, Plus, Trash, TriangleAlert, X } from 'lucide-react'
import { api } from '../api/client'
import type { ActionSpec, Detection, Playbook, PlaybookInput, PlaybookMode, ResponseAction } from '../api/types'
import { ACTION_STATUSES, SEVERITIES, type Severity } from '../api/types'
import { auditColumns } from '../components/AuditList'
import { Badge, StatusBadge } from '../components/Badge'
import { Button } from '../components/Button'
import { Card, PageHeader } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, InlineError } from '../components/ErrorState'
import { Field, SearchInput, Select, Toggle } from '../components/Form'
import { Modal } from '../components/Modal'
import { ResponseActionCard } from '../components/ResponseActionCard'
import { SeverityBadge } from '../components/SeverityBadge'
import { Tabs } from '../components/Tabs'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { humanize, parseDate } from '../lib/format'

type TabKey = 'actions' | 'playbooks' | 'audit'
const MODES: { value: PlaybookMode; label: string }[] = [
  { value: 'alert_only', label: 'Alert only' },
  { value: 'approval', label: 'Require approval' },
  { value: 'auto', label: 'Automatic' },
]

export default function ResponsesPage() {
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as TabKey) || 'actions'
  const setParam = (k: string, v: string | null) =>
    setParams((p) => {
      const n = new URLSearchParams(p)
      if (v) n.set(k, v)
      else n.delete(k)
      return n
    }, { replace: true })
  const catalog = useApi((s) => api.actionCatalog(s), [])

  return (
    <div>
      <PageHeader
        title="Response history"
        description="Every response action with its approval decision, execution result and post-action verification; response playbooks; and the platform audit log."
      />
      <Tabs<TabKey>
        className="mb-4"
        value={tab}
        onChange={(t) => setParam('tab', t === 'actions' ? null : t)}
        tabs={[
          { key: 'actions', label: 'Response actions' },
          { key: 'playbooks', label: 'Playbooks' },
          { key: 'audit', label: 'Audit log' },
        ]}
      />
      {tab === 'actions' && <ActionsTab catalog={catalog.data} status={params.get('status') ?? ''} setStatus={(s) => setParam('status', s || null)} />}
      {tab === 'playbooks' && <PlaybooksTab catalog={catalog.data} />}
      {tab === 'audit' && <AuditTab />}
    </div>
  )
}

function ActionsTab({ catalog, status, setStatus }: { catalog: ActionSpec[] | undefined; status: string; setStatus: (s: string) => void }) {
  const actions = useApi((s) => api.responses({ status: status || undefined, limit: 500 }, s), [status], { interval: 10_000 })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = actions.data?.items.find((a) => a.id === selectedId) ?? null
  const title = (t: string) => catalog?.find((c) => c.type === t)?.title ?? humanize(t)

  const columns: Column<ResponseAction>[] = [
    {
      key: 'action',
      header: 'Action',
      render: (a) => (
        <div className="min-w-0 max-w-[320px]">
          <div className="truncate font-medium text-fg">{title(a.action_type)}</div>
          <div className="truncate font-mono text-[11.5px] text-subtle">{a.target.kind}/{a.target.namespace}/{a.target.name}</div>
        </div>
      ),
      sortValue: (a) => a.action_type,
    },
    { key: 'status', header: 'Status', render: (a) => <StatusBadge status={a.status} />, sortValue: (a) => a.status },
    { key: 'mode', header: 'Mode', render: (a) => <Badge>{humanize(a.mode)}</Badge>, sortValue: (a) => a.mode },
    {
      key: 'verification',
      header: 'Verification',
      render: (a) =>
        a.verification && Array.isArray(a.verification.checks) ? (
          <span className={`inline-flex items-center gap-1 text-[12px] ${a.verification.verified ? 'text-ok' : 'text-bad'}`}>
            {a.verification.verified ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
            {a.verification.checks.filter((c) => c.passed).length}/{a.verification.checks.length} checks
          </span>
        ) : (
          <span className="text-subtle">—</span>
        ),
    },
    {
      key: 'error',
      header: 'Error',
      render: (a) => (a.error ? <span className="flex max-w-[260px] items-start gap-1 text-[12px] text-bad" title={a.error}><TriangleAlert className="mt-0.5 h-3 w-3 shrink-0" /><span className="line-clamp-2">{a.error}</span></span> : <span className="text-subtle">—</span>),
    },
    {
      key: 'incident',
      header: 'Incident',
      render: (a) => (a.incident_id ? <Link className="link font-mono text-[12px]" to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()}>#{a.incident_id}</Link> : <span className="text-subtle">manual</span>),
      sortValue: (a) => a.incident_id ?? -1,
    },
    { key: 'by', header: 'Requested by', render: (a) => a.requested_by ?? '—', sortValue: (a) => a.requested_by ?? '' },
    { key: 'requested', header: 'Requested', render: (a) => <Time value={a.requested_at} />, sortValue: (a) => parseDate(a.requested_at)?.getTime() ?? 0, align: 'right' },
  ]

  return (
    <>
      {actions.error ? <div className="mb-3"><ErrorState error={actions.error} onRetry={actions.reload} /></div> : null}
      <Card flush>
        <DataTable
          columns={columns}
          rows={actions.data?.items}
          rowKey={(a) => a.id}
          loading={actions.initialLoading}
          searchText={(a) => `${a.action_type} ${a.target.namespace} ${a.target.name} ${a.requested_by} ${a.reason ?? ''}`}
          searchPlaceholder="Search actions, targets…"
          toolbar={<Select value={status} onChange={setStatus} options={ACTION_STATUSES.map((s) => ({ value: s, label: humanize(s) }))} placeholder="All statuses" label="Status" />}
          onRowClick={(a) => setSelectedId(a.id)}
          selectedKey={selectedId}
          pageSize={50}
          empty={<EmptyState title={status ? `No ${humanize(status).toLowerCase()} actions` : 'No response actions yet'} description="Actions are created by playbooks when incidents open, or manually from an incident." />}
        />
      </Card>
      <Drawer open={Boolean(selected)} onClose={() => setSelectedId(null)} title={selected ? title(selected.action_type) : ''} subtitle={selected && <span className="font-mono">{selected.id}</span>}>
        {selected && <ResponseActionCard action={selected} catalog={catalog} onChanged={actions.reload} showIncident />}
      </Drawer>
    </>
  )
}

async function deletePlaybook(id: number): Promise<true> {
  await api.deletePlaybook(id)
  return true
}

function emptyPlaybook(): PlaybookInput {
  return { name: '', description: '', enabled: true, match_rule_ids: [], min_severity: 'high', action_type: 'alert_only', mode: 'approval' }
}

function toInput(p: Playbook): PlaybookInput {
  return { name: p.name, description: p.description, enabled: p.enabled, match_rule_ids: [...p.match_rule_ids], min_severity: p.min_severity, action_type: p.action_type, mode: p.mode }
}

function PlaybooksTab({ catalog }: { catalog: ActionSpec[] | undefined }) {
  const { can } = useAuth()
  const isAdmin = can('admin')
  const playbooks = useApi((s) => api.playbooks(s), [])
  const detections = useApi((s) => api.detections(s), [])
  const settings = useApi((s) => api.settings(s), [])
  const [editing, setEditing] = useState<{ id: number | null; body: PlaybookInput } | null>(null)
  const [deleting, setDeleting] = useState<Playbook | null>(null)
  const update = useMutation(api.updatePlaybook)
  const del = useMutation(deletePlaybook)
  const title = (t: string) => catalog?.find((c) => c.type === t)?.title ?? humanize(t)
  const autoEnabled = settings.data?.runtime['response.auto_enabled']

  const toggle = async (p: Playbook, enabled: boolean) => {
    const r = await update.run(p.id, { ...toInput(p), enabled })
    if (r) playbooks.reload()
  }
  const setMode = async (p: Playbook, mode: PlaybookMode) => {
    const r = await update.run(p.id, { ...toInput(p), mode })
    if (r) playbooks.reload()
  }
  const confirmDelete = async () => {
    if (!deleting) return
    const ok = await del.run(deleting.id)
    if (ok) {
      setDeleting(null)
      playbooks.reload()
    }
  }

  const columns: Column<Playbook>[] = [
    {
      key: 'enabled',
      header: 'Enabled',
      render: (p) => <Toggle checked={p.enabled} onChange={(v) => void toggle(p, v)} disabled={!isAdmin || update.pending} label={`Enable ${p.name}`} />,
      sortValue: (p) => (p.enabled ? 1 : 0),
      className: 'w-20',
    },
    {
      key: 'name',
      header: 'Playbook',
      render: (p) => (
        <div className="min-w-0 max-w-[360px]">
          <div className="truncate font-medium text-fg">{p.name}</div>
          <div className="line-clamp-2 text-[12px] text-subtle">{p.description || '—'}</div>
        </div>
      ),
      sortValue: (p) => p.name,
    },
    {
      key: 'match',
      header: 'Matches',
      render: (p) => (
        <div className="flex max-w-[220px] flex-wrap gap-1">
          {p.match_rule_ids.length ? p.match_rule_ids.map((r) => <Badge key={r}><span className="font-mono">{r}</span></Badge>) : <span className="text-[12px] text-subtle">any rule</span>}
        </div>
      ),
    },
    { key: 'sev', header: 'Min severity', render: (p) => <SeverityBadge severity={p.min_severity} /> },
    { key: 'action', header: 'Action', render: (p) => <span className="text-[12.5px]">{title(p.action_type)}{catalog?.find((c) => c.type === p.action_type)?.destructive && <Badge tone="bad" className="ml-1.5">destructive</Badge>}</span> },
    {
      key: 'mode',
      header: 'Mode',
      render: (p) =>
        isAdmin ? (
          <Select value={p.mode} onChange={(v) => void setMode(p, v as PlaybookMode)} options={MODES} label={`Mode for ${p.name}`} disabled={update.pending} />
        ) : (
          <Badge>{MODES.find((m) => m.value === p.mode)?.label ?? p.mode}</Badge>
        ),
    },
    { key: 'updated', header: 'Updated', render: (p) => <Time value={p.updated_at} />, sortValue: (p) => parseDate(p.updated_at)?.getTime() ?? 0, align: 'right' },
  ]
  if (isAdmin) {
    columns.push({
      key: 'ops',
      header: '',
      render: (p) => (
        <div className="flex justify-end gap-1">
          <Button size="sm" variant="ghost" icon={<Pencil className="h-3.5 w-3.5" />} onClick={() => setEditing({ id: p.id, body: toInput(p) })} aria-label={`Edit ${p.name}`} />
          <Button size="sm" variant="ghost" icon={<Trash className="h-3.5 w-3.5" />} onClick={() => setDeleting(p)} aria-label={`Delete ${p.name}`} />
        </div>
      ),
      align: 'right',
    })
  }

  return (
    <>
      {autoEnabled === false && (
        <p className="mb-3 rounded-md border border-border bg-surface px-3 py-2 text-[12.5px] text-muted">
          Automatic response is globally disabled: playbooks in <span className="font-medium text-fg">Automatic</span> mode currently fall back to requiring approval. Destructive actions never run automatically unless separately enabled in <Link className="link" to="/settings">Settings</Link>.
        </p>
      )}
      <InlineError message={update.error} />
      {playbooks.error ? <ErrorState error={playbooks.error} onRetry={playbooks.reload} /> : null}
      <Card
        flush
        title="Response playbooks"
        subtitle="Evaluated for every new security event that opens or updates an incident"
        actions={isAdmin && <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />} onClick={() => setEditing({ id: null, body: emptyPlaybook() })}>New playbook</Button>}
      >
        <DataTable columns={columns} rows={playbooks.data} rowKey={(p) => p.id} loading={playbooks.initialLoading} empty={<EmptyState title="No playbooks configured" description={isAdmin ? 'Create one to automate alerting or response.' : undefined} />} />
      </Card>
      {editing && (
        <PlaybookForm
          key={editing.id ?? 'new'}
          id={editing.id}
          initial={editing.body}
          catalog={catalog ?? []}
          detections={detections.data ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            playbooks.reload()
          }}
        />
      )}
      <Modal
        open={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        title="Delete playbook"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleting(null)}>Cancel</Button>
            <Button variant="danger" loading={del.pending} onClick={confirmDelete}>Delete</Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">Delete playbook <span className="font-medium text-fg">{deleting?.name}</span>? Existing response actions are kept.</p>
        <InlineError message={del.error} />
      </Modal>
    </>
  )
}

function PlaybookForm({
  id,
  initial,
  catalog,
  detections,
  onClose,
  onSaved,
}: {
  id: number | null
  initial: PlaybookInput
  catalog: ActionSpec[]
  detections: Detection[]
  onClose: () => void
  onSaved: () => void
}) {
  const [body, setBody] = useState<PlaybookInput>(initial)
  const save = useMutation(useCallback((b: PlaybookInput) => (id === null ? api.createPlaybook(b) : api.updatePlaybook(id, b)), [id]))
  const actionOptions = catalog.filter((c) => c.type !== 'release_isolation')
  const spec = catalog.find((c) => c.type === body.action_type)
  const set = <K extends keyof PlaybookInput>(k: K, v: PlaybookInput[K]) => setBody((b) => ({ ...b, [k]: v }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const r = await save.run({ ...body, name: body.name.trim(), description: body.description.trim() })
    if (r) onSaved()
  }
  const toggleRule = (rid: string) =>
    set('match_rule_ids', body.match_rule_ids.includes(rid) ? body.match_rule_ids.filter((r) => r !== rid) : [...body.match_rule_ids, rid])

  return (
    <Modal
      open
      onClose={onClose}
      title={id === null ? 'New playbook' : `Edit playbook`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="playbook-form" loading={save.pending} disabled={body.name.trim().length < 3}>
            {id === null ? 'Create playbook' : 'Save changes'}
          </Button>
        </>
      }
    >
      <form id="playbook-form" onSubmit={submit} className="space-y-3">
        <Field label="Name">
          <input className="input w-full" value={body.name} onChange={(e) => set('name', e.target.value)} minLength={3} maxLength={128} required />
        </Field>
        <Field label="Description">
          <textarea className="textarea h-16 w-full font-sans" value={body.description} onChange={(e) => set('description', e.target.value)} maxLength={1000} />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Action">
            <select className="input w-full" value={body.action_type} onChange={(e) => set('action_type', e.target.value)}>
              {actionOptions.map((c) => (
                <option key={c.type} value={c.type}>{c.title}{c.destructive ? ' (destructive)' : ''}</option>
              ))}
            </select>
          </Field>
          <Field label="Mode">
            <select className="input w-full" value={body.mode} onChange={(e) => set('mode', e.target.value as PlaybookMode)}>
              {MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </Field>
          <Field label="Minimum severity">
            <select className="input w-full" value={body.min_severity} onChange={(e) => set('min_severity', e.target.value as Severity)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </Field>
          <Field label="Enabled">
            <div className="flex h-8 items-center"><Toggle checked={body.enabled} onChange={(v) => set('enabled', v)} label="Enabled" /></div>
          </Field>
        </div>
        {spec?.destructive && body.mode === 'auto' && (
          <p className="rounded-md border border-warn/30 bg-warn/[0.05] px-3 py-2 text-[12px] text-warn">
            Destructive actions only run automatically when both automatic response and automatic destructive response are enabled in Settings; otherwise they require approval.
          </p>
        )}
        <div>
          <span className="label">Match detections (none selected = any rule)</span>
          <div className="max-h-48 space-y-1 overflow-y-auto rounded-md border border-border p-2">
            {detections.length === 0 && <p className="text-[12px] text-subtle">Detection catalog unavailable.</p>}
            {detections.map((d) => (
              <label key={d.id} className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[12.5px] hover:bg-white/[0.03]">
                <input type="checkbox" checked={body.match_rule_ids.includes(d.id)} onChange={() => toggleRule(d.id)} className="accent-[var(--color-accent)]" />
                <span className="font-mono text-[11.5px] text-subtle">{d.id}</span>
                <span className="text-fg">{d.name}</span>
              </label>
            ))}
            {body.match_rule_ids.filter((r) => !detections.some((d) => d.id === r)).map((r) => (
              <label key={r} className="flex items-center gap-2 px-1.5 py-1 text-[12.5px]">
                <input type="checkbox" checked onChange={() => toggleRule(r)} className="accent-[var(--color-accent)]" />
                <span className="font-mono text-[11.5px] text-subtle">{r}</span>
                <span className="text-subtle">(not in catalog)</span>
              </label>
            ))}
          </div>
        </div>
        <InlineError message={save.error} />
      </form>
    </Modal>
  )
}

function AuditTab() {
  const [action, setAction] = useState('')
  const [limit, setLimit] = useState('200')
  const onSearch = useCallback((v: string) => setAction(v), [])
  const audit = useApi((s) => api.audit({ action: action || undefined, limit: Number(limit) }, s), [action, limit], { interval: 30_000 })
  const columns = useMemo(() => auditColumns({ showIncident: true }), [])
  return (
    <>
      {audit.error ? <div className="mb-3"><ErrorState error={audit.error} onRetry={audit.reload} /></div> : null}
      <Card flush title="Audit log" subtitle="Append-only record of logins, decisions, configuration changes and automated actions">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2.5">
          <SearchInput value={action} onChange={onSearch} debounce={350} placeholder="Action prefix, e.g. response. or auth." className="w-full sm:w-72" />
          <Select value={limit} onChange={setLimit} options={['200', '500', '1000'].map((v) => ({ value: v, label: `Latest ${v}` }))} label="Limit" />
        </div>
        <DataTable columns={columns} rows={audit.data} rowKey={(a) => String(a.id)} loading={audit.initialLoading} pageSize={50} dense empty={<EmptyState title="No audit entries" />} />
      </Card>
    </>
  )
}
