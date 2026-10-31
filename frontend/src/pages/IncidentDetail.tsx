import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Zap } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { ActionSpec, IncidentDetail, IncidentStatus } from '../api/types'
import { INCIDENT_STATUSES } from '../api/types'
import { AuditTrail } from '../components/AuditList'
import { Badge, StatusBadge } from '../components/Badge'
import { Button } from '../components/Button'
import { Card } from '../components/Card'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, InlineError } from '../components/ErrorState'
import { EventDrawer } from '../components/EventDrawer'
import { Field, Select } from '../components/Form'
import { KeyValueGrid } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { Modal } from '../components/Modal'
import { ResponseActionCard } from '../components/ResponseActionCard'
import { SeverityBadge, SEVERITY_COLORS } from '../components/SeverityBadge'
import { TechniqueTags } from '../components/Techniques'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { formatDateTime, humanize } from '../lib/format'

const K8S_NAME = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/

export default function IncidentDetailPage() {
  const { id } = useParams()
  const [active, setActive] = useState(false)
  const incident = useApi((s) => api.incident(id!, s), [id], { interval: active ? 4_000 : 20_000 })
  const catalog = useApi((s) => api.actionCatalog(s), [])
  const [eventId, setEventId] = useState<string | null>(null)
  const { can } = useAuth()

  const inc = incident.data
  useEffect(() => {
    setActive(Boolean(inc?.actions.some((a) => a.status === 'approved' || a.status === 'executing')))
  }, [inc])

  if (incident.initialLoading) return <Loading />
  if (!inc) {
    if (incident.error instanceof ApiError && incident.error.status === 404) {
      return <EmptyState title={`Incident #${id} not found`} action={<Link to="/incidents" className="link text-[13px]">Back to incidents</Link>} />
    }
    return <ErrorState error={incident.error} onRetry={incident.reload} />
  }

  return (
    <div>
      <Link to="/incidents" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="h-3.5 w-3.5" /> Incidents
      </Link>

      <div className="mb-5 rounded-lg border border-border bg-surface p-5" style={{ boxShadow: `inset 3px 0 0 ${SEVERITY_COLORS[inc.severity] ?? '#5f6b80'}` }}>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[12px] text-subtle">#{inc.id}</span>
              <SeverityBadge severity={inc.severity} />
              <StatusBadge status={inc.status} />
            </div>
            <h1 className="text-[19px] font-semibold tracking-tight text-fg">{inc.title}</h1>
            {inc.summary && <p className="mt-1.5 max-w-3xl text-[13px] text-muted">{inc.summary}</p>}
          </div>
          {can('responder') && <StatusChanger incidentId={inc.id} current={inc.status} onChanged={incident.reload} />}
        </div>
        <div className="mt-5">
          <KeyValueGrid
            columns={3}
            items={[
              { label: 'Namespace', value: inc.namespace, mono: true },
              { label: 'Pod', value: inc.pod, mono: true },
              { label: 'Workload', value: inc.workload, mono: true },
              { label: 'First seen', value: formatDateTime(inc.first_seen) },
              { label: 'Last seen', value: formatDateTime(inc.last_seen) },
              { label: 'Events', value: inc.event_count },
              { label: 'Resolved', value: formatDateTime(inc.resolved_at), hidden: !inc.resolved_at },
              { label: 'Rules', value: inc.rules?.length ? <div className="flex flex-wrap gap-1">{inc.rules.map((r) => <Badge key={r}>{r}</Badge>)}</div> : null },
              { label: 'MITRE ATT&CK', value: <TechniqueTags ids={inc.techniques} /> },
            ]}
          />
        </div>
      </div>
      {incident.error ? <div className="mb-4"><ErrorState error={incident.error} compact onRetry={incident.reload} /></div> : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Event timeline" subtitle={`${inc.events.length} correlated events, oldest first`}>
            {inc.events.length === 0 ? (
              <EmptyState compact title="No events linked to this incident" />
            ) : (
              <ol className="relative space-y-1 border-l border-border pl-5">
                {inc.events.map((e) => (
                  <li key={e.id} className="relative">
                    <span
                      className="absolute -left-[25px] top-3 h-2.5 w-2.5 rounded-full ring-4 ring-surface"
                      style={{ backgroundColor: SEVERITY_COLORS[e.severity] ?? '#5f6b80' }}
                    />
                    <button
                      type="button"
                      onClick={() => setEventId(e.id)}
                      className="w-full rounded-md px-3 py-2 text-left hover:bg-white/[0.03]"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[12px] tabular-nums text-subtle">{formatDateTime(e.timestamp)}</span>
                        <SeverityBadge severity={e.severity} />
                        <Badge>{e.source}</Badge>
                        <span className="font-medium text-fg">{e.detection ?? e.rule}</span>
                      </div>
                      <div className="mt-1 line-clamp-2 font-mono text-[11.5px] text-muted">{e.message}</div>
                      {e.process?.cmdline && (
                        <div className="mt-1 truncate font-mono text-[11.5px] text-subtle">
                          <span className="text-muted">{e.process.name ?? 'process'}</span> $ {e.process.cmdline}
                        </div>
                      )}
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </Card>

          <Card title="Response actions" subtitle="Playbook-generated and manual actions with verification against the cluster">
            {inc.actions.length === 0 ? (
              <EmptyState compact title="No response actions for this incident" description={can('responder') ? 'Use the Respond panel to request one.' : undefined} />
            ) : (
              <div className="space-y-3">
                {inc.actions.map((a) => (
                  <ResponseActionCard key={a.id} action={a} catalog={catalog.data} onChanged={incident.reload} />
                ))}
              </div>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          {can('responder') && <RespondForm incident={inc} catalog={catalog.data} onCreated={incident.reload} />}
          <Card title="Audit trail" subtitle="Every decision and change recorded for this incident">
            <AuditTrail entries={inc.audit_trail} />
          </Card>
        </div>
      </div>
      <EventDrawer eventId={eventId} onClose={() => setEventId(null)} />
    </div>
  )
}

function StatusChanger({ incidentId, current, onChanged }: { incidentId: number; current: IncidentStatus; onChanged: () => void }) {
  const [status, setStatus] = useState<IncidentStatus>(current)
  const [note, setNote] = useState('')
  const [open, setOpen] = useState(false)
  const m = useMutation(api.setIncidentStatus)
  useEffect(() => setStatus(current), [current])

  const submit = async () => {
    const r = await m.run(incidentId, status, note.trim() || undefined)
    if (r) {
      setOpen(false)
      setNote('')
      onChanged()
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Select
        value={status}
        onChange={(v) => setStatus(v as IncidentStatus)}
        options={INCIDENT_STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
        label="Incident status"
      />
      <Button variant="primary" size="md" disabled={status === current} onClick={() => setOpen(true)}>
        Update status
      </Button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Change incident status"
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" loading={m.pending} onClick={submit}>Save</Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">
          <StatusBadge status={current} /> <span className="mx-1">→</span> <StatusBadge status={status} />
        </p>
        <label className="mt-4 block">
          <span className="label">Note (recorded in the audit trail)</span>
          <textarea className="textarea h-24 w-full font-sans" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
        </label>
        <InlineError message={m.error} />
      </Modal>
    </div>
  )
}

function defaultTarget(spec: ActionSpec | undefined, inc: Pick<IncidentDetail, 'pod' | 'namespace'>): string {
  if (!spec) return inc.pod ?? ''
  if (spec.target_kind === 'Namespace') return inc.namespace ?? ''
  // For Deployment targets the backend resolves the owning Deployment from the pod name.
  return inc.pod ?? ''
}

function RespondForm({ incident, catalog, onCreated }: { incident: IncidentDetail; catalog: ActionSpec[] | undefined; onCreated: () => void }) {
  const { can } = useAuth()
  const isAdmin = can('admin')
  const [type, setType] = useState('')
  const [namespace, setNamespace] = useState(incident.namespace ?? '')
  const [name, setName] = useState(incident.pod ?? '')
  const [reason, setReason] = useState('')
  const [confirm, setConfirm] = useState(false)
  const m = useMutation(api.createResponse)
  const spec = useMemo(() => catalog?.find((c) => c.type === type), [catalog, type])

  useEffect(() => {
    if (!type && catalog?.length) setType(catalog.find((c) => c.type === 'isolate_pod')?.type ?? catalog[0].type)
  }, [catalog, type])
  const { pod: incPod, namespace: incNs } = incident
  useEffect(() => {
    setName(defaultTarget(spec, { pod: incPod, namespace: incNs }))
  }, [spec, incPod, incNs])

  const valid = K8S_NAME.test(namespace) && K8S_NAME.test(name) && Boolean(spec) && (!spec?.destructive || isAdmin)

  const execute = async () => {
    const r = await m.run({ action_type: type, namespace, name, incident_id: incident.id, reason: reason.trim() })
    if (r) {
      setConfirm(false)
      setReason('')
      onCreated()
    }
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (valid) setConfirm(true)
  }

  return (
    <Card title={<span className="flex items-center gap-2"><Zap className="h-4 w-4 text-accent" /> Respond</span>} subtitle="Manual actions execute immediately and are verified">
      {!catalog ? (
        <Loading />
      ) : (
        <form onSubmit={submit} className="space-y-3">
          <Field label="Action">
            <select className="input w-full" value={type} onChange={(e) => setType(e.target.value)} aria-label="Action type">
              {catalog.map((c) => (
                <option key={c.type} value={c.type} disabled={c.destructive && !isAdmin}>
                  {c.title}{c.destructive ? (isAdmin ? ' (destructive)' : ' (admin only)') : ''}
                </option>
              ))}
            </select>
          </Field>
          {spec && <p className="text-[12px] text-muted">{spec.description}</p>}
          <div className="grid grid-cols-2 gap-2">
            <Field label="Namespace">
              <input className="input w-full font-mono" value={namespace} onChange={(e) => setNamespace(e.target.value.trim())} maxLength={63} required />
            </Field>
            <Field label={spec?.target_kind === 'Deployment' ? 'Pod or Deployment' : (spec?.target_kind ?? 'Target')}>
              <input className="input w-full font-mono" value={name} onChange={(e) => setName(e.target.value.trim())} maxLength={253} required />
            </Field>
          </div>
          {spec?.target_kind === 'Deployment' && <p className="text-[11.5px] text-subtle">A pod name is resolved to its owning Deployment by the backend.</p>}
          {(namespace && !K8S_NAME.test(namespace)) || (name && !K8S_NAME.test(name)) ? (
            <p className="text-[12px] text-bad">Namespace and name must be valid Kubernetes names.</p>
          ) : null}
          <Field label="Reason">
            <textarea className="textarea h-16 w-full font-sans" maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this action needed?" />
          </Field>
          <Button type="submit" variant={spec?.destructive ? 'danger' : 'primary'} className="w-full" disabled={!valid}>
            Request {spec?.title.toLowerCase() ?? 'action'}
          </Button>
          <InlineError message={m.error} />
        </form>
      )}
      <Modal
        open={confirm}
        onClose={() => setConfirm(false)}
        title={`Confirm: ${spec?.title ?? type}`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(false)}>Cancel</Button>
            <Button variant={spec?.destructive ? 'danger' : 'primary'} loading={m.pending} onClick={execute}>
              Execute now
            </Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">
          {spec?.description} Target: <span className="font-mono text-fg">{spec?.target_kind}/{namespace}/{name}</span>
        </p>
        {spec?.destructive && (
          <p className="mt-3 rounded-md border border-bad/30 bg-bad/[0.06] px-3 py-2 text-[12.5px] text-bad">
            This action is destructive and cannot be undone from KubeShield.
          </p>
        )}
        <InlineError message={m.error} />
      </Modal>
    </Card>
  )
}
