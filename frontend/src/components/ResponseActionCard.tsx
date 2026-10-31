import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Check, CircleCheck, CircleX, TriangleAlert, X } from 'lucide-react'
import { api } from '../api/client'
import type { ActionSpec, ResponseAction } from '../api/types'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { formatDateTime, humanize, stringify } from '../lib/format'
import { Badge, StatusBadge } from './Badge'
import { Button } from './Button'
import { InlineError } from './ErrorState'
import { JsonView } from './JsonView'
import { Modal } from './Modal'

export function VerificationChecks({ action }: { action: ResponseAction }) {
  const v = action.verification
  if (!v || !Array.isArray(v.checks)) return null
  return (
    <div className="rounded-md border border-border bg-bg/40">
      <div className="flex items-center gap-2 border-b border-border px-3 py-1.5 text-[12px]">
        {v.verified ? <CircleCheck className="h-3.5 w-3.5 text-ok" /> : <CircleX className="h-3.5 w-3.5 text-bad" />}
        <span className={v.verified ? 'text-ok' : 'text-bad'}>
          {v.verified ? 'Verified against live cluster state' : 'Verification failed'}
        </span>
      </div>
      <ul className="divide-y divide-border/70">
        {v.checks.map((c, i) => (
          <li key={i} className="flex items-start gap-2 px-3 py-1.5 text-[12px]">
            {c.passed ? <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ok" /> : <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-bad" />}
            <span className="min-w-0 flex-1 text-fg">{c.check}</span>
            {c.observed !== undefined && (
              <span className="max-w-[50%] break-all text-right font-mono text-[11px] text-subtle" title="Observed">
                {stringify(c.observed)}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

export function ResponseActionCard({
  action,
  catalog,
  onChanged,
  showIncident,
}: {
  action: ResponseAction
  catalog?: ActionSpec[]
  onChanged?: () => void
  showIncident?: boolean
}) {
  const { can } = useAuth()
  const spec = catalog?.find((c) => c.type === action.action_type)
  const destructive = spec?.destructive ?? (action.action_type === 'delete_pod' || action.action_type === 'scale_to_zero')
  const canDecide = action.status === 'pending_approval' && can('responder')
  const canApprove = canDecide && (!destructive || can('admin'))
  const [deciding, setDeciding] = useState<null | boolean>(null)
  const [note, setNote] = useState('')
  const decide = useMutation(api.decideResponse)

  const submit = async () => {
    if (deciding === null) return
    const r = await decide.run(action.id, deciding, note.trim() || undefined)
    if (r) {
      setDeciding(null)
      setNote('')
      onChanged?.()
    }
  }

  return (
    <div className="rounded-lg border border-border bg-surface-2/50 p-3.5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13.5px] font-semibold text-fg">{spec?.title ?? humanize(action.action_type)}</span>
            {destructive && <Badge tone="bad">destructive</Badge>}
            <Badge>{humanize(action.mode)}</Badge>
          </div>
          <div className="mt-0.5 font-mono text-[12px] text-muted">
            {action.target.kind}/{action.target.namespace}/{action.target.name}
          </div>
        </div>
        <StatusBadge status={action.status} />
      </div>

      {action.reason && <p className="mt-2 text-[12.5px] leading-relaxed text-muted">{action.reason}</p>}

      <dl className="mt-2.5 grid grid-cols-1 gap-x-4 gap-y-1 text-[11.5px] sm:grid-cols-2">
        <div><dt className="inline text-subtle">Requested: </dt><dd className="inline text-muted">{formatDateTime(action.requested_at)} by {action.requested_by ?? '—'}</dd></div>
        {action.decided_at && <div><dt className="inline text-subtle">Decided: </dt><dd className="inline text-muted">{formatDateTime(action.decided_at)} by {action.decided_by ?? '—'}</dd></div>}
        {action.executed_at && <div><dt className="inline text-subtle">Executed: </dt><dd className="inline text-muted">{formatDateTime(action.executed_at)}</dd></div>}
        {action.completed_at && <div><dt className="inline text-subtle">Completed: </dt><dd className="inline text-muted">{formatDateTime(action.completed_at)}</dd></div>}
        {action.playbook_id !== null && <div><dt className="inline text-subtle">Playbook: </dt><dd className="inline text-muted">#{action.playbook_id}</dd></div>}
        {showIncident && action.incident_id !== null && (
          <div><dt className="inline text-subtle">Incident: </dt><dd className="inline"><Link className="link" to={`/incidents/${action.incident_id}`}>#{action.incident_id}</Link></dd></div>
        )}
      </dl>

      {action.error && (
        <div className="mt-2.5 flex items-start gap-2 rounded-md border border-bad/30 bg-bad/[0.06] px-3 py-2 text-[12px] text-bad">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span className="break-words">{action.error}</span>
        </div>
      )}

      {typeof action.result?.caveat === 'string' && (
        <p className="mt-2.5 rounded-md border border-warn/30 bg-warn/[0.05] px-3 py-2 text-[12px] text-warn">{action.result.caveat}</p>
      )}

      {action.verification && <div className="mt-2.5"><VerificationChecks action={action} /></div>}
      {action.result && <div className="mt-2.5"><JsonView value={action.result} title="Execution result" /></div>}

      {canDecide && (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <Button size="sm" variant="primary" icon={<Check className="h-3.5 w-3.5" />} onClick={() => setDeciding(true)} disabled={!canApprove}>
            Approve
          </Button>
          <Button size="sm" variant="secondary" icon={<X className="h-3.5 w-3.5" />} onClick={() => setDeciding(false)}>
            Reject
          </Button>
          {!canApprove && <span className="text-[11.5px] text-subtle">Approving destructive actions requires the admin role.</span>}
        </div>
      )}

      <Modal
        open={deciding !== null}
        onClose={() => setDeciding(null)}
        title={deciding ? 'Approve response action' : 'Reject response action'}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeciding(null)}>Cancel</Button>
            <Button variant={deciding ? (destructive ? 'danger' : 'primary') : 'secondary'} loading={decide.pending} onClick={submit}>
              {deciding ? 'Approve and execute' : 'Reject'}
            </Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">
          {deciding ? 'The action will be executed against ' : 'The action will not be executed against '}
          <span className="font-mono text-fg">{action.target.kind}/{action.target.namespace}/{action.target.name}</span>
          {deciding && ' and verified against the live cluster state.'}
        </p>
        {deciding && destructive && (
          <p className="mt-3 rounded-md border border-bad/30 bg-bad/[0.06] px-3 py-2 text-[12.5px] text-bad">
            This is a destructive action: {spec?.description ?? humanize(action.action_type)}
          </p>
        )}
        <label className="mt-4 block">
          <span className="label">Note (recorded in the audit log)</span>
          <textarea className="textarea h-20 w-full font-sans" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
        </label>
        <InlineError message={decide.error} />
      </Modal>
    </div>
  )
}
