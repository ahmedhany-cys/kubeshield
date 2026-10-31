import { useEffect, useState, type ReactNode } from 'react'
import { Search, X } from 'lucide-react'
import { cx } from '../lib/format'

export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
  className,
  debounce = 0,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  className?: string
  /** Debounce in ms for server-side searches. */
  debounce?: number
}) {
  const [local, setLocal] = useState(value)
  useEffect(() => setLocal(value), [value])
  useEffect(() => {
    if (!debounce || local === value) return
    const id = window.setTimeout(() => onChange(local), debounce)
    return () => window.clearTimeout(id)
  }, [local, debounce, onChange, value])

  return (
    <div className={cx('relative', className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-subtle" />
      <input
        type="search"
        value={local}
        onChange={(e) => {
          setLocal(e.target.value)
          if (!debounce) onChange(e.target.value)
        }}
        placeholder={placeholder}
        aria-label={placeholder}
        className="input w-full pl-8 pr-7 [&::-webkit-search-cancel-button]:hidden"
      />
      {local && (
        <button
          type="button"
          onClick={() => {
            setLocal('')
            onChange('')
          }}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-subtle hover:text-fg"
          aria-label="Clear search"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  )
}

export interface Option {
  value: string
  label: string
}

export function Select({
  value,
  onChange,
  options,
  placeholder,
  label,
  className,
  disabled,
}: {
  value: string
  onChange: (v: string) => void
  options: (Option | string)[]
  /** Label of the empty "all" option. Omit to require a value. */
  placeholder?: string
  label?: string
  className?: string
  disabled?: boolean
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label ?? placeholder}
      disabled={disabled}
      className={cx('input cursor-pointer pr-7', className)}
    >
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => {
        const opt = typeof o === 'string' ? { value: o, label: o } : o
        return (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        )
      })}
    </select>
  )
}

export function Field({ label, children, hint, className }: { label: string; children: ReactNode; hint?: ReactNode; className?: string }) {
  return (
    <label className={cx('block', className)}>
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[11.5px] text-subtle">{hint}</span>}
    </label>
  )
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  label: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cx(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'border-accent-strong bg-accent-strong' : 'border-border-strong bg-surface-3',
      )}
    >
      <span
        className={cx(
          'inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform',
          checked ? 'translate-x-[18px]' : 'translate-x-[2px]',
        )}
      />
    </button>
  )
}

/** Toggle buttons for selecting multiple values (e.g. severities). */
export function ChipGroup<V extends string>({
  options,
  value,
  onChange,
  render,
  label,
}: {
  options: V[]
  value: V[]
  onChange: (v: V[]) => void
  render?: (v: V) => ReactNode
  label: string
}) {
  return (
    <div className="flex flex-wrap items-center gap-1" role="group" aria-label={label}>
      {options.map((o) => {
        const on = value.includes(o)
        return (
          <button
            key={o}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(on ? value.filter((v) => v !== o) : [...value, o])}
            className={cx(
              'h-7 rounded-md border px-2 text-[12px] capitalize transition-colors',
              on ? 'border-accent/50 bg-accent/10 text-fg' : 'border-border text-muted hover:text-fg',
            )}
          >
            {render ? render(o) : o}
          </button>
        )
      })}
    </div>
  )
}
