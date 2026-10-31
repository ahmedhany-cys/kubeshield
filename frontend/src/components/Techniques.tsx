import { Link } from 'react-router-dom'

/** ATT&CK technique ids rendered as compact tags linking to the coverage page. */
export function TechniqueTags({ ids }: { ids: string[] | null | undefined }) {
  if (!ids || ids.length === 0) return <span className="text-subtle">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {ids.map((t) => (
        <Link
          key={t}
          to={`/mitre?technique=${encodeURIComponent(t)}`}
          className="inline-flex h-5 items-center rounded border border-border-strong bg-surface-2 px-1.5 font-mono text-[11px] text-muted hover:border-accent/50 hover:text-fg"
          onClick={(e) => e.stopPropagation()}
        >
          {t}
        </Link>
      ))}
    </div>
  )
}
