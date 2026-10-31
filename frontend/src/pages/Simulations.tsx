import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Check, Crosshair, LoaderCircle, Play, X } from 'lucide-react'
import { api } from '../api/client'
import type { RunOutcome, Scenario, SimulationRun, SimulationStep } from '../api/types'
import { Badge, type Tone } from '../components/Badge'
import { Button } from '../components/Button'
import { Card, PageHeader, Section } from '../components/Card'
import { DataTable, type Column } from '../components/DataTable'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { ErrorState, InlineError, UnavailableState } from '../components/ErrorState'
import { CodeBlock, JsonView } from '../components/JsonView'
import { KeyValueGrid } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { TechniqueTags } from '../components/Techniques'
import { Time } from '../components/Time'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../hooks/useAuth'
import { useMutation } from '../hooks/useMutation'
import { formatDateTime, formatDuration, humanize, parseDate, stringify } from '../lib/format'

const OUTCOME_TONES: Record<RunOutcome, Tone> = {
  detected: 'ok',
  blocked: 'ok',
  partial: 'warn',
  missed: 'bad',
  error: 'bad',
}

export function OutcomeBadge({ run }: { run: SimulationRun | null | undefined }) {
  if (!run) return <span className="text-[12px] text-subtle">Never run</span>
  if (run.status === 'running') {
    return (
      <Badge tone="accent">
        <LoaderCircle className="h-3 w-3 animate-spin" /> running
      </Badge>
    )
  }
  const outcome = run.outcome ?? 'error'
  return (
    <Badge tone={OUTCOME_TONES[outcome as RunOutcome] ?? 'neutral'} dot className="uppercase tracking-wide">
      {outcome}
    </Badge>
  )
}

export default function SimulationsPage() {
  const [params, setParams] = useSearchParams()
  const runId = params.get('run')
  const setRun = (id: string | null) =>
    setParams((p) => {
      const n = new URLSearchParams(p)
      if (id) n.set('run', id)
      else n.delete('run')
      return n
    }, { replace: true })
  const { can } = useAuth()
  const [running, setRunning] = useState(false)
  const scenarios = useApi((s) => api.scenarios(s), [], { interval: running ? 3_000 : 30_000 })
  const runs = useApi((s) => api.runs(s), [], { interval: running ? 3_000 : 30_000 })
  const settings = useApi((s) => api.settings(s), [])
  const start = useMutation(api.startRun)
  const [startingId, setStartingId] = useState<string | null>(null)

  const anyRunning = Boolean(runs.data?.some((r) => r.status === 'running'))
  if (anyRunning !== running) setRunning(anyRunning)

  const scenarioTitles = useMemo(() => Object.fromEntries((scenarios.data ?? []).map((s) => [s.id, s.title])), [scenarios.data])
  const simEnabled = settings.data ? settings.data.runtime['simulation.enabled'] !== false : true

  const onRun = async (sc: Scenario) => {
    setStartingId(sc.id)
    const r = await start.run(sc.id)
    setStartingId(null)
    if (r) {
      setRunning(true)
      scenarios.reload()
      runs.reload()
      setRun(r.id)
    }
  }

  const runColumns: Column<SimulationRun>[] = [
    {
      key: 'scenario',
      header: 'Scenario',
      render: (r) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-fg">{scenarioTitles[r.scenario_id] ?? r.scenario_id}</div>
          <div className="truncate font-mono text-[11.5px] text-subtle">{r.id}</div>
        </div>
      ),
      sortValue: (r) => r.scenario_id,
    },
    { key: 'outcome', header: 'Outcome', render: (r) => <OutcomeBadge run={r} />, sortValue: (r) => r.outcome ?? '' },
    {
      key: 'checks',
      header: 'Checks',
      render: (r) => (r.checks?.length ? <span className="tabular-nums">{r.checks.filter((c) => c.passed).length}/{r.checks.length} passed</span> : <span className="text-subtle">—</span>),
    },
    { key: 'by', header: 'Requested by', render: (r) => r.requested_by ?? '—' },
    { key: 'duration', header: 'Duration', render: (r) => (r.status === 'running' ? 'in progress' : formatDuration(r.started_at, r.finished_at)), align: 'right' },
    { key: 'started', header: 'Started', render: (r) => <Time value={r.started_at} />, sortValue: (r) => parseDate(r.started_at)?.getTime() ?? 0, align: 'right' },
  ]

  return (
    <div>
      <PageHeader
        title="Attack simulation"
        description="Controlled attacks executed against the isolated lab namespaces. A scenario only reports “detected” when the expected telemetry actually reached KubeShield."
      />
      {!simEnabled && (
        <div className="mb-4">
          <UnavailableState label="Disabled" title="Attack simulation is disabled in settings" detail={null}>
            An administrator can enable it on the <Link className="link" to="/settings">Settings</Link> page.
          </UnavailableState>
        </div>
      )}
      <InlineError message={start.error} />
      {scenarios.initialLoading && <Loading />}
      {scenarios.error && !scenarios.data ? <ErrorState error={scenarios.error} onRetry={scenarios.reload} /> : null}
      {scenarios.data && (
        <div className="mb-6 mt-2 grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {scenarios.data.map((sc) => (
            <ScenarioCard
              key={sc.id}
              scenario={sc}
              canRun={can('responder') && simEnabled}
              busy={anyRunning}
              starting={startingId === sc.id}
              onRun={() => onRun(sc)}
              onOpenRun={setRun}
            />
          ))}
        </div>
      )}
      <Card title="Run history" flush>
        {runs.error && !runs.data ? <div className="p-3"><ErrorState error={runs.error} onRetry={runs.reload} compact /></div> : null}
        <DataTable
          columns={runColumns}
          rows={runs.data}
          rowKey={(r) => r.id}
          loading={runs.initialLoading}
          onRowClick={(r) => setRun(r.id)}
          selectedKey={runId}
          empty={<EmptyState title="No simulation runs yet" description={can('responder') ? 'Run a scenario above to validate the detection pipeline end to end.' : 'A responder or admin can run scenarios.'} icon={<Crosshair className="h-4 w-4" />} />}
        />
      </Card>
      <RunDrawer runId={runId} title={runId ? scenarioTitles[runs.data?.find((r) => r.id === runId)?.scenario_id ?? ''] : undefined} onClose={() => setRun(null)} />
    </div>
  )
}

function ScenarioCard({
  scenario: sc,
  canRun,
  busy,
  starting,
  onRun,
  onOpenRun,
}: {
  scenario: Scenario
  canRun: boolean
  busy: boolean
  starting: boolean
  onRun: () => void
  onOpenRun: (id: string) => void
}) {
  return (
    <div className="flex min-w-0 flex-col rounded-lg border border-border bg-surface">
      <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-[14px] font-semibold text-fg">{sc.title}</h3>
            <Badge>{sc.kind}</Badge>
          </div>
          <p className="mt-1 text-[12.5px] text-muted">{sc.description}</p>
        </div>
        {canRun && (
          <Button size="sm" variant="primary" icon={<Play className="h-3.5 w-3.5" />} onClick={onRun} loading={starting} disabled={busy && !starting} title={busy ? 'Another simulation is running' : undefined}>
            Run
          </Button>
        )}
      </div>
      <div className="flex-1 space-y-3 px-4 py-3 text-[12.5px]">
        <KeyValueGrid
          items={[
            { label: 'Objective', value: sc.objective },
            { label: 'Target', value: sc.target, mono: true },
          ]}
        />
        <div>
          <div className="label">Procedure</div>
          <CodeBlock>{sc.procedure.join('\n')}</CodeBlock>
        </div>
        <KeyValueGrid
          columns={1}
          items={[
            { label: 'Expected telemetry', value: sc.expected_telemetry },
            {
              label: 'Expected detections',
              value: sc.expected_detections.length ? (
                <div className="flex flex-wrap gap-1">
                  {sc.expected_detections.map((d) => (
                    <Link key={d} to={`/threats?rule_id=${encodeURIComponent(d)}`} className="font-mono text-[11.5px]">
                      <Badge tone="accent">{d}</Badge>
                    </Link>
                  ))}
                </div>
              ) : (
                <span className="text-subtle">Validated by checks (no runtime detection)</span>
              ),
            },
            { label: 'Expected response', value: sc.expected_response },
            { label: 'Techniques', value: <TechniqueTags ids={sc.techniques} /> },
          ]}
        />
      </div>
      <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-2.5">
        <div className="flex items-center gap-2 text-[12px] text-subtle">
          Last run: <OutcomeBadge run={sc.last_run} />
          {sc.last_run && <Time value={sc.last_run.started_at} />}
        </div>
        {sc.last_run && (
          <button type="button" className="link text-[12px]" onClick={() => onOpenRun(sc.last_run!.id)}>
            View run
          </button>
        )}
      </div>
    </div>
  )
}

const STEP_KNOWN = new Set(['at', 'title', 'command', 'exit_code', 'stdout', 'stderr'])

function StepView({ step, index }: { step: SimulationStep; index: number }) {
  const extra = Object.fromEntries(Object.entries(step).filter(([k]) => !STEP_KNOWN.has(k)))
  return (
    <li className="rounded-md border border-border bg-surface-2/50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex h-5 w-5 items-center justify-center rounded-full bg-surface-3 text-[11px] text-muted">{index + 1}</span>
          <span className="text-[13px] font-medium text-fg">{step.title}</span>
        </div>
        <div className="flex items-center gap-2 text-[11.5px] text-subtle">
          {step.exit_code !== undefined && (
            <Badge tone={step.exit_code === 0 ? 'ok' : step.exit_code === null ? 'neutral' : 'warn'}>exit {step.exit_code ?? '?'}</Badge>
          )}
          {formatDateTime(step.at)}
        </div>
      </div>
      {Array.isArray(step.command) && <CodeBlock className="mt-2">{`$ ${step.command.join(' ')}`}</CodeBlock>}
      {step.stdout ? <><div className="label mt-2">stdout</div><CodeBlock>{step.stdout}</CodeBlock></> : null}
      {step.stderr ? <><div className="label mt-2">stderr</div><CodeBlock className="text-warn">{step.stderr}</CodeBlock></> : null}
      {Object.keys(extra).length > 0 && (
        <dl className="mt-2 grid grid-cols-1 gap-1 text-[12px]">
          {Object.entries(extra).map(([k, v]) => (
            <div key={k} className="flex gap-2">
              <dt className="shrink-0 font-mono text-subtle">{k}</dt>
              <dd className="min-w-0 whitespace-pre-wrap break-all font-mono text-muted">{stringify(v)}</dd>
            </div>
          ))}
        </dl>
      )}
    </li>
  )
}

function RunDrawer({ runId, title, onClose }: { runId: string | null; title?: string; onClose: () => void }) {
  const [running, setRunning] = useState(false)
  const run = useApi((s) => api.run(runId!, s), [runId], { enabled: Boolean(runId), interval: running ? 2_500 : undefined })
  const r = run.data
  const isRunning = r?.status === 'running'
  if (isRunning !== running) setRunning(isRunning)
  const ev = r?.evidence ?? {}

  return (
    <Drawer
      open={Boolean(runId)}
      onClose={onClose}
      width="max-w-3xl"
      title={title ?? r?.scenario_id ?? 'Simulation run'}
      subtitle={
        r && (
          <span className="flex flex-wrap items-center gap-2">
            <OutcomeBadge run={r} />
            <span className="font-mono">{r.id}</span>
            <span>started {formatDateTime(r.started_at)} by {r.requested_by ?? '—'}</span>
          </span>
        )
      }
    >
      {run.initialLoading && <Loading />}
      {run.error ? <ErrorState error={run.error} onRetry={run.reload} /> : null}
      {r && (
        <>
          {isRunning && (
            <div className="mb-4 flex items-center gap-2 rounded-md border border-accent/30 bg-accent/[0.06] px-3 py-2 text-[12.5px] text-fg">
              <LoaderCircle className="h-4 w-4 animate-spin text-accent" />
              Simulation in progress — waiting for telemetry. This view refreshes automatically.
            </div>
          )}
          {r.error && (
            <div className="mb-4">
              <ErrorState error={new Error(r.error)} />
            </div>
          )}
          <Section title="Summary">
            <KeyValueGrid
              columns={3}
              items={[
                { label: 'Scenario', value: r.scenario_id, mono: true },
                { label: 'Status', value: humanize(r.status) },
                { label: 'Duration', value: r.finished_at ? formatDuration(r.started_at, r.finished_at) : 'in progress' },
                { label: 'Finished', value: formatDateTime(r.finished_at) },
                { label: 'Incident', value: r.incident_id ? <Link className="link" to={`/incidents/${r.incident_id}`}>#{r.incident_id}</Link> : null },
              ]}
            />
          </Section>

          <Section title="Verification checks">
            {r.checks?.length ? (
              <ul className="space-y-2">
                {r.checks.map((c, i) => {
                  const observed = Object.fromEntries(Object.entries(c).filter(([k]) => k !== 'title' && k !== 'passed'))
                  return (
                    <li key={i} className={`rounded-md border px-3 py-2 ${c.passed ? 'border-ok/30 bg-ok/[0.04]' : 'border-bad/30 bg-bad/[0.05]'}`}>
                      <div className="flex items-start gap-2">
                        {c.passed ? <Check className="mt-0.5 h-4 w-4 shrink-0 text-ok" /> : <X className="mt-0.5 h-4 w-4 shrink-0 text-bad" />}
                        <span className="text-[13px] text-fg">{c.title}</span>
                        <Badge tone={c.passed ? 'ok' : 'bad'} className="ml-auto">{c.passed ? 'pass' : 'fail'}</Badge>
                      </div>
                      {Object.keys(observed).length > 0 && (
                        <dl className="mt-1.5 space-y-0.5 pl-6 text-[11.5px]">
                          {Object.entries(observed).map(([k, v]) => (
                            <div key={k} className="flex gap-2">
                              <dt className="shrink-0 font-mono text-subtle">{k}</dt>
                              <dd className="min-w-0 break-all font-mono text-muted">
                                {k === 'event_ids' && Array.isArray(v) ? (
                                  <span className="flex flex-wrap gap-1">
                                    {v.length === 0 ? '[]' : v.map((id) => <Link key={String(id)} className="link" to={`/threats?event=${encodeURIComponent(String(id))}`}>{String(id)}</Link>)}
                                  </span>
                                ) : (
                                  stringify(v)
                                )}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      )}
                    </li>
                  )
                })}
              </ul>
            ) : (
              <p className="text-[12.5px] text-subtle">{isRunning ? 'Checks are recorded when the run finishes.' : 'No checks recorded.'}</p>
            )}
          </Section>

          <Section title="Evidence">
            <div className="space-y-3 text-[12.5px]">
              <div>
                <div className="label">Security events</div>
                {ev.event_ids?.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {ev.event_ids.map((id) => (
                      <Link key={id} to={`/threats?event=${encodeURIComponent(id)}`} className="rounded border border-border-strong bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-accent hover:border-accent/50">
                        {id}
                      </Link>
                    ))}
                  </div>
                ) : (
                  <span className="text-subtle">None</span>
                )}
              </div>
              <div>
                <div className="label">Incidents</div>
                {ev.incident_ids?.length ? (
                  <div className="flex flex-wrap gap-2">
                    {ev.incident_ids.map((id) => <Link key={id} className="link font-mono" to={`/incidents/${id}`}>#{id}</Link>)}
                  </div>
                ) : (
                  <span className="text-subtle">None</span>
                )}
              </div>
              <div>
                <div className="label">Response actions</div>
                {ev.response_actions?.length ? (
                  <ul className="space-y-1">
                    {ev.response_actions.map((a) => (
                      <li key={a.id} className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-fg">{humanize(a.action)}</span>
                        <Badge>{humanize(a.mode)}</Badge>
                        <Badge tone={a.status === 'succeeded' ? 'ok' : a.status === 'failed' ? 'bad' : a.status === 'pending_approval' ? 'warn' : 'neutral'}>{humanize(a.status)}</Badge>
                        <span className="font-mono text-[11px] text-subtle">{a.id}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-subtle">None</span>
                )}
              </div>
              {ev.scan_id && (
                <div>
                  <div className="label">Image scan</div>
                  <Link className="link font-mono" to={`/vulnerabilities?scan=${encodeURIComponent(ev.scan_id)}`}>{ev.scan_id}</Link>
                </div>
              )}
              {ev.findings && (
                <div>
                  <div className="label">Posture findings</div>
                  {ev.findings.length ? <div className="flex flex-wrap gap-1">{ev.findings.map((f) => <Badge key={f}><span className="font-mono">{f}</span></Badge>)}</div> : <span className="text-subtle">None</span>}
                </div>
              )}
              {ev.policies && (
                <div>
                  <div className="label">Kyverno policies</div>
                  {ev.policies.length ? <div className="flex flex-wrap gap-1">{ev.policies.map((p) => <Badge key={p}><span className="font-mono">{p}</span></Badge>)}</div> : <span className="text-subtle">None</span>}
                </div>
              )}
            </div>
          </Section>

          <Section title="Steps">
            {r.steps?.length ? (
              <ol className="space-y-2">
                {r.steps.map((s, i) => <StepView key={i} step={s} index={i} />)}
              </ol>
            ) : (
              <p className="text-[12.5px] text-subtle">{isRunning ? 'Steps are recorded when the run finishes.' : 'No steps recorded.'}</p>
            )}
          </Section>
          <JsonView value={r} title="Raw run record" />
        </>
      )}
    </Drawer>
  )
}
