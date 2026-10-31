import { Link, useSearchParams } from 'react-router-dom'
import { Info } from 'lucide-react'
import { api } from '../api/client'
import type { CoverageStatus, TechniqueCoverage } from '../api/types'
import { Badge, type Tone } from '../components/Badge'
import { Card, PageHeader, Section } from '../components/Card'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { KeyValueGrid } from '../components/KeyValue'
import { Loading } from '../components/Loading'
import { useApi } from '../hooks/useApi'
import { cx, formatDateTime, formatNumber, humanize } from '../lib/format'

const STATUS_STYLE: Record<CoverageStatus, { tile: string; tone: Tone; label: string; swatch: string }> = {
  validated: { tile: 'border-ok/45 bg-ok/[0.10] hover:bg-ok/[0.16]', tone: 'ok', label: 'Validated', swatch: 'bg-ok' },
  implemented: { tile: 'border-accent/40 bg-accent/[0.08] hover:bg-accent/[0.14]', tone: 'accent', label: 'Implemented', swatch: 'bg-accent' },
  not_covered: { tile: 'border-border bg-surface-2/40 hover:bg-surface-2', tone: 'neutral', label: 'Not covered', swatch: 'bg-subtle/50' },
}

function Meter({ value, color }: { value: number; color: string }) {
  return (
    <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
      <div className={cx('h-full rounded-full', color)} style={{ width: `${Math.min(100, value)}%` }} />
    </div>
  )
}

export default function MitrePage() {
  const [params, setParams] = useSearchParams()
  const selectedId = params.get('technique')
  const setSelected = (id: string | null) =>
    setParams((p) => {
      const n = new URLSearchParams(p)
      if (id) n.set('technique', id)
      else n.delete('technique')
      return n
    }, { replace: true })
  const cov = useApi((s) => api.mitre(s), [], { interval: 60_000 })

  if (cov.initialLoading) return <Loading />
  const c = cov.data
  if (!c) return <ErrorState error={cov.error} onRetry={cov.reload} />

  const selected = c.techniques.find((t) => t.id === selectedId) ?? null
  const otherSelected = !selected && selectedId ? c.observed_other_techniques.find((t) => t.id === selectedId) : undefined

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK coverage"
        description="Coverage of a curated technique reference set, computed from implemented detections and recorded simulation runs."
      />

      <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="rounded-lg border border-border bg-surface p-4">
          <div className="text-[12px] font-medium text-muted">Validated</div>
          <div className="mt-2 text-[26px] font-semibold leading-none tabular-nums text-ok">
            {c.validated_pct}%<span className="ml-2 text-[13px] font-normal text-subtle">{c.validated} of {c.total_techniques} techniques</span>
          </div>
          <Meter value={c.validated_pct} color="bg-ok" />
          <p className="mt-2 text-[11.5px] text-subtle">A detection for the technique was confirmed by a recorded simulation run (outcome detected or blocked).</p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-4">
          <div className="text-[12px] font-medium text-muted">Implemented</div>
          <div className="mt-2 text-[26px] font-semibold leading-none tabular-nums text-accent">
            {c.implemented_pct}%<span className="ml-2 text-[13px] font-normal text-subtle">{c.implemented} of {c.total_techniques} techniques</span>
          </div>
          <Meter value={c.implemented_pct} color="bg-accent" />
          <p className="mt-2 text-[11.5px] text-subtle">A detection exists in the catalog (includes validated). Not yet validated means no successful simulation has confirmed it.</p>
        </div>
        <div className="flex gap-3 rounded-lg border border-border bg-surface p-4">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-subtle" />
          <div>
            <div className="text-[12px] font-medium text-muted">Reference set</div>
            <p className="mt-1 text-[13px] text-fg">{c.reference_set}</p>
            <p className="mt-2 text-[11.5px] text-subtle">
              Percentages are relative to these {c.total_techniques} techniques only, not to the full ATT&CK framework.
            </p>
          </div>
        </div>
      </div>

      <Card
        title="Coverage matrix"
        subtitle="Techniques grouped by tactic; a technique appears under every tactic it belongs to"
        actions={
          <div className="flex flex-wrap items-center gap-3 text-[11.5px] text-muted">
            {(Object.keys(STATUS_STYLE) as CoverageStatus[]).map((s) => (
              <span key={s} className="flex items-center gap-1.5">
                <span className={cx('h-2.5 w-2.5 rounded-sm', STATUS_STYLE[s].swatch)} />
                {STATUS_STYLE[s].label}
              </span>
            ))}
          </div>
        }
        bodyClassName="overflow-x-auto"
      >
        <div className="flex min-w-max gap-2">
          {c.tactics.map((tactic) => {
            const techs = c.techniques.filter((t) => t.tactics.includes(tactic))
            const covered = techs.filter((t) => t.status !== 'not_covered').length
            return (
              <div key={tactic} className="w-[168px] shrink-0">
                <div className="mb-2 rounded-md border border-border bg-surface-2 px-2.5 py-2">
                  <div className="text-[12px] font-semibold capitalize text-fg">{humanize(tactic)}</div>
                  <div className="text-[11px] text-subtle">{covered}/{techs.length} covered</div>
                </div>
                <div className="space-y-1.5">
                  {techs.length === 0 && <div className="px-1 text-[11px] text-subtle">No techniques in reference set</div>}
                  {techs.map((t) => (
                    <TechniqueTile key={t.id} t={t} active={t.id === selectedId} onClick={() => setSelected(t.id)} />
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      </Card>

      <Card className="mt-4" title="Other observed techniques" subtitle="Technique IDs tagged on received events (e.g. upstream Falco rule tags) that are outside the reference set">
        {c.observed_other_techniques.length === 0 ? (
          <EmptyState compact title="None observed" />
        ) : (
          <div className="flex flex-wrap gap-2">
            {c.observed_other_techniques.map((t) => (
              <span key={t.id} className="inline-flex items-center gap-2 rounded-md border border-border bg-surface-2 px-2 py-1 text-[12px]">
                <span className="font-mono text-fg">{t.id}</span>
                <span className="text-subtle">{formatNumber(t.observed_events)} events</span>
              </span>
            ))}
          </div>
        )}
      </Card>

      <Drawer
        open={Boolean(selected) || Boolean(otherSelected)}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.id} · ${selected.name}` : selectedId}
        subtitle={
          selected && (
            <span className="flex flex-wrap items-center gap-2">
              <Badge tone={STATUS_STYLE[selected.status].tone} dot>{STATUS_STYLE[selected.status].label}</Badge>
              <Badge>{selected.matrix === 'containers' ? 'ATT&CK Containers matrix' : 'Enterprise Linux'}</Badge>
            </span>
          )
        }
      >
        {otherSelected && (
          <p className="text-[13px] text-muted">
            {otherSelected.id} is outside the reference set. It was observed on {formatNumber(otherSelected.observed_events)} events.
          </p>
        )}
        {selected && (
          <>
            <Section title="Technique">
              <KeyValueGrid
                items={[
                  { label: 'Tactics', value: selected.tactics.map(humanize).join(', ') },
                  {
                    label: 'Observed events',
                    value: selected.observed_events ? (
                      <span>{formatNumber(selected.observed_events)} events tagged with {selected.id}</span>
                    ) : (
                      '0'
                    ),
                  },
                ]}
              />
            </Section>
            <Section title="Detections">
              {selected.detections.length === 0 ? (
                <p className="text-[12.5px] text-subtle">No KubeShield detection maps to this technique.</p>
              ) : (
                <ul className="space-y-2">
                  {selected.detections.map((d) => (
                    <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-surface-2/50 px-3 py-2">
                      <div className="min-w-0">
                        <div className="text-[13px] font-medium text-fg">{d.name}</div>
                        <div className="font-mono text-[11.5px] text-subtle">{d.id} · {d.source}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge tone={d.validated ? 'ok' : 'accent'}>{d.validated ? 'validated' : 'implemented'}</Badge>
                        <Link className="link text-[12px]" to={`/threats?rule_id=${encodeURIComponent(d.id)}`}>Events</Link>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Section>
            <Section title="Validations">
              {selected.validations.length === 0 ? (
                <p className="text-[12.5px] text-subtle">
                  No successful simulation run has validated a detection for this technique yet.
                  {selected.detections.length > 0 && (
                    <> Run the matching scenario on the <Link className="link" to="/simulations">Attack Simulation</Link> page.</>
                  )}
                </p>
              ) : (
                <ul className="space-y-2">
                  {selected.validations.map((v) => (
                    <li key={`${v.detection}-${v.run_id}`} className="rounded-md border border-ok/30 bg-ok/[0.04] px-3 py-2 text-[12.5px]">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-fg">{v.detection}</span>
                        <span className="text-subtle">validated by scenario</span>
                        <span className="font-mono text-muted">{v.scenario}</span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[11.5px] text-subtle">
                        <span>{formatDateTime(v.at)}</span>
                        <Link className="link font-mono" to={`/simulations?run=${encodeURIComponent(v.run_id)}`}>run {v.run_id}</Link>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Section>
          </>
        )}
      </Drawer>
    </div>
  )
}

function TechniqueTile({ t, active, onClick }: { t: TechniqueCoverage; active: boolean; onClick: () => void }) {
  const st = STATUS_STYLE[t.status]
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx('block w-full rounded-md border px-2.5 py-2 text-left transition-colors', st.tile, active && 'ring-2 ring-accent')}
      title={`${t.id} ${t.name} — ${st.label}`}
    >
      <div className="flex items-center justify-between gap-1">
        <span className="font-mono text-[11px] text-muted">{t.id}</span>
        {t.observed_events > 0 && <span className="rounded bg-white/[0.07] px-1 text-[10px] tabular-nums text-muted" title="Observed events">{formatNumber(t.observed_events)}</span>}
      </div>
      <div className={cx('mt-0.5 line-clamp-3 text-[11.5px] leading-snug', t.status === 'not_covered' ? 'text-subtle' : 'text-fg')}>{t.name}</div>
    </button>
  )
}
