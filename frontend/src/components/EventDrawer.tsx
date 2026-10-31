import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { api } from '../api/client'
import type { SecurityEvent } from '../api/types'
import { useApi } from '../hooks/useApi'
import { formatDateTime } from '../lib/format'
import { Badge } from './Badge'
import { Section } from './Card'
import { Drawer } from './Drawer'
import { ErrorState } from './ErrorState'
import { JsonView } from './JsonView'
import { KeyValueGrid, KeyValueTable } from './KeyValue'
import { Loading } from './Loading'
import { SeverityBadge } from './SeverityBadge'
import { TechniqueTags } from './Techniques'

export function EventDrawer({ eventId, onClose }: { eventId: string | null; onClose: () => void }) {
  const { data, error, initialLoading, reload } = useApi((s) => api.event(eventId!, s), [eventId], {
    enabled: Boolean(eventId),
  })
  return (
    <Drawer
      open={Boolean(eventId)}
      onClose={onClose}
      title={data ? (data.detection ?? data.rule) : 'Security event'}
      subtitle={
        data && (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <Badge>{data.source}</Badge>
            {data.rule_id && <span className="font-mono text-[12px]">{data.rule_id}</span>}
            <span>{formatDateTime(data.timestamp)}</span>
          </span>
        )
      }
    >
      {initialLoading && <Loading />}
      {error ? <ErrorState error={error} onRetry={reload} /> : null}
      {data && <EventDetailBody event={data} />}
    </Drawer>
  )
}

export function EventDetailBody({ event: e }: { event: SecurityEvent }) {
  const p = e.process ?? {}
  const hasProcess = Object.keys(p).length > 0
  return (
    <div>
      {e.message && (
        <p className="mb-5 rounded-md border border-border bg-surface-2 px-3 py-2.5 font-mono text-[12px] leading-relaxed text-muted">
          {e.message}
        </p>
      )}

      {e.incident_id && (
        <Link
          to={`/incidents/${e.incident_id}`}
          className="mb-5 flex items-center justify-between rounded-md border border-accent/30 bg-accent/[0.06] px-3 py-2.5 text-[13px] hover:bg-accent/10"
        >
          <span>
            Correlated into <span className="font-semibold text-fg">incident #{e.incident_id}</span>
          </span>
          <ArrowRight className="h-4 w-4 text-accent" />
        </Link>
      )}

      <Section title="Detection">
        <KeyValueGrid
          items={[
            { label: 'Detection', value: e.detection ?? 'Not in KubeShield catalog' },
            { label: 'Source rule', value: e.rule },
            { label: 'Rule ID', value: e.rule_id, mono: true },
            { label: 'Source priority', value: e.source_priority },
            { label: 'Event time', value: formatDateTime(e.timestamp) },
            { label: 'Ingested', value: formatDateTime(e.ingested_at) },
          ]}
        />
      </Section>

      <Section title="Workload">
        <KeyValueGrid
          items={[
            { label: 'Namespace', value: e.namespace, mono: true },
            { label: 'Pod', value: e.pod, mono: true },
            { label: 'Container', value: e.container, mono: true },
            { label: 'Container ID', value: e.container_id, mono: true },
            { label: 'Image', value: e.image, mono: true },
            { label: 'Node', value: e.node, mono: true },
          ]}
        />
      </Section>

      <Section title="Process">
        {hasProcess ? (
          <KeyValueGrid
            items={[
              { label: 'Name', value: p.name, mono: true },
              { label: 'PID', value: p.pid, mono: true },
              { label: 'Command line', value: p.cmdline, mono: true },
              { label: 'Executable', value: p.exepath, mono: true, hidden: !p.exepath },
              { label: 'Parent', value: p.parent, mono: true },
              { label: 'Parent command line', value: p.parent_cmdline, mono: true, hidden: !p.parent_cmdline },
              { label: 'User', value: p.user !== undefined ? `${p.user}${p.uid !== undefined ? ` (uid ${p.uid})` : ''}` : null, mono: true },
              { label: 'TTY', value: p.tty, mono: true, hidden: p.tty === undefined },
            ]}
          />
        ) : (
          <p className="text-[12.5px] text-subtle">No process context for this event (network or admission source).</p>
        )}
      </Section>

      <Section title="Evidence">
        <KeyValueTable data={e.evidence} />
      </Section>

      <Section title="MITRE ATT&CK techniques">
        <TechniqueTags ids={e.techniques} />
      </Section>

      {e.tags && e.tags.length > 0 && (
        <Section title="Tags">
          <div className="flex flex-wrap gap-1">
            {e.tags.map((t) => (
              <Badge key={t}>{t}</Badge>
            ))}
          </div>
        </Section>
      )}

      {e.recommended_response && (
        <Section title="Recommended response">
          <p className="rounded-md border border-border bg-surface-2 px-3 py-2.5 text-[13px] leading-relaxed text-fg">
            {e.recommended_response}
          </p>
        </Section>
      )}

      {e.raw !== undefined && (
        <Section title="Raw event">
          <JsonView value={e.raw} title="Raw JSON payload" />
        </Section>
      )}
    </div>
  )
}
