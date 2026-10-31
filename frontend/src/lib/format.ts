const dateFmt = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
})
const shortFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
const hourFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' })
const numFmt = new Intl.NumberFormat()

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null
  // Backend timestamps are UTC; treat naive ISO strings as UTC.
  const hasZone = /[zZ]|[+-]\d\d:?\d\d$/.test(value)
  const d = new Date(hasZone ? value : `${value}Z`)
  return Number.isNaN(d.getTime()) ? null : d
}

export function formatDateTime(value: string | null | undefined): string {
  const d = parseDate(value)
  return d ? dateFmt.format(d) : '—'
}

export function formatShort(value: string | null | undefined): string {
  const d = parseDate(value)
  return d ? shortFmt.format(d) : '—'
}

export function formatHour(value: string | null | undefined): string {
  const d = parseDate(value)
  return d ? hourFmt.format(d) : ''
}

export function relativeTime(value: string | null | undefined, now: number = Date.now()): string {
  const d = parseDate(value)
  if (!d) return '—'
  const diff = Math.round((now - d.getTime()) / 1000)
  const abs = Math.abs(diff)
  const suffix = diff >= 0 ? 'ago' : 'from now'
  if (abs < 45) return diff >= 0 ? 'just now' : 'in a few seconds'
  if (abs < 90) return `1 min ${suffix}`
  if (abs < 3600) return `${Math.round(abs / 60)} min ${suffix}`
  if (abs < 86400) return `${Math.round(abs / 3600)} h ${suffix}`
  if (abs < 86400 * 30) return `${Math.round(abs / 86400)} d ${suffix}`
  return formatShort(value)
}

export function formatDuration(start: string | null | undefined, end: string | null | undefined): string {
  const a = parseDate(start)
  const b = parseDate(end)
  if (!a || !b) return '—'
  const s = Math.max(0, Math.round((b.getTime() - a.getTime()) / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  return `${m}m ${s % 60}s`
}

export function formatNumber(n: number | null | undefined): string {
  return n === null || n === undefined ? '—' : numFmt.format(n)
}

export function humanize(value: string | null | undefined): string {
  if (!value) return '—'
  const s = value.replace(/[_-]+/g, ' ').trim()
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export function pct(part: number, total: number): number {
  return total > 0 ? Math.round((part / total) * 1000) / 10 : 0
}

export function stringify(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

export function workloadRef(ns: string | null | undefined, name: string | null | undefined): string {
  if (!ns && !name) return '—'
  return `${ns ?? '—'}/${name ?? '—'}`
}
