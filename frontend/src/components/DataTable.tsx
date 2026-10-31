import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsUpDown } from 'lucide-react'
import { cx, formatNumber } from '../lib/format'
import { EmptyState } from './EmptyState'
import { SearchInput } from './Form'
import { Loading } from './Loading'

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T) => ReactNode
  /** Enables sorting on this column. */
  sortValue?: (row: T) => string | number | null | undefined
  className?: string
  headerClassName?: string
  align?: 'left' | 'right' | 'center'
}

interface ServerPagination {
  total: number
  offset: number
  limit: number
  onChange: (offset: number) => void
}

export interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[] | undefined
  rowKey: (row: T) => string | number
  /** Client-side text search; return the searchable text for a row. */
  searchText?: (row: T) => string
  searchPlaceholder?: string
  /** Controlled search (e.g. server-side search). */
  search?: string
  onSearchChange?: (value: string) => void
  toolbar?: ReactNode
  onRowClick?: (row: T) => void
  selectedKey?: string | number | null
  rowClassName?: (row: T) => string | undefined
  empty?: ReactNode
  loading?: boolean
  pageSize?: number
  pagination?: ServerPagination
  initialSort?: { key: string; dir: 'asc' | 'desc' }
  dense?: boolean
  footer?: ReactNode
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  searchText,
  searchPlaceholder = 'Search…',
  search: controlledSearch,
  onSearchChange,
  toolbar,
  onRowClick,
  selectedKey,
  rowClassName,
  empty,
  loading,
  pageSize = 25,
  pagination,
  initialSort,
  dense,
  footer,
}: DataTableProps<T>) {
  const [localSearch, setLocalSearch] = useState('')
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(initialSort ?? null)
  const [page, setPage] = useState(0)
  const search = controlledSearch ?? localSearch
  const setSearch = onSearchChange ?? setLocalSearch
  const showSearch = Boolean(searchText || onSearchChange)

  const filtered = useMemo(() => {
    let out = rows ?? []
    if (searchText && search.trim() && !onSearchChange) {
      const needle = search.trim().toLowerCase()
      out = out.filter((r) => searchText(r).toLowerCase().includes(needle))
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key)
      if (col?.sortValue) {
        const sv = col.sortValue
        out = [...out].sort((a, b) => {
          const va = sv(a)
          const vb = sv(b)
          if (va === vb) return 0
          if (va === null || va === undefined) return 1
          if (vb === null || vb === undefined) return -1
          const r = typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb))
          return sort.dir === 'asc' ? r : -r
        })
      }
    }
    return out
  }, [rows, search, searchText, onSearchChange, sort, columns])

  useEffect(() => setPage(0), [search, rows?.length])

  const clientPaged = !pagination
  const pageCount = clientPaged ? Math.max(1, Math.ceil(filtered.length / pageSize)) : 1
  const safePage = Math.min(page, pageCount - 1)
  const visible = clientPaged ? filtered.slice(safePage * pageSize, safePage * pageSize + pageSize) : filtered

  const toggleSort = (key: string) => {
    setSort((s) => (s?.key === key ? (s.dir === 'desc' ? { key, dir: 'asc' } : null) : { key, dir: 'desc' }))
  }

  const cellPad = dense ? 'px-3 py-1.5' : 'px-3 py-2'

  return (
    <div className="min-w-0">
      {(showSearch || toolbar) && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2.5">
          {showSearch && (
            <SearchInput value={search} onChange={setSearch} placeholder={searchPlaceholder} className="w-full sm:w-64" />
          )}
          {toolbar}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr className="border-b border-border bg-surface-2/60">
              {columns.map((c) => {
                const active = sort?.key === c.key
                return (
                  <th
                    key={c.key}
                    scope="col"
                    className={cx(
                      'whitespace-nowrap px-3 py-2 text-[11px] font-medium uppercase tracking-wide text-subtle',
                      c.align === 'right' ? 'text-right' : c.align === 'center' ? 'text-center' : 'text-left',
                      c.headerClassName,
                    )}
                    aria-sort={active ? (sort?.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                  >
                    {c.sortValue ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(c.key)}
                        className={cx('inline-flex items-center gap-1 uppercase hover:text-fg', active && 'text-fg')}
                      >
                        {c.header}
                        {active ? (
                          sort?.dir === 'asc' ? (
                            <ArrowUp className="h-3 w-3" />
                          ) : (
                            <ArrowDown className="h-3 w-3" />
                          )
                        ) : (
                          <ChevronsUpDown className="h-3 w-3 opacity-40" />
                        )}
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => {
              const key = rowKey(row)
              const selected = selectedKey !== undefined && selectedKey !== null && key === selectedKey
              return (
                <tr
                  key={key}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === 'Enter') onRowClick(row)
                        }
                      : undefined
                  }
                  tabIndex={onRowClick ? 0 : undefined}
                  className={cx(
                    'border-b border-border/70 last:border-0',
                    onRowClick && 'cursor-pointer hover:bg-white/[0.025]',
                    selected && 'bg-accent/[0.07] hover:bg-accent/[0.09]',
                    rowClassName?.(row),
                  )}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={cx(
                        cellPad,
                        'align-middle',
                        c.align === 'right' ? 'text-right' : c.align === 'center' ? 'text-center' : 'text-left',
                        c.className,
                      )}
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {loading && rows === undefined && <Loading />}
      {!loading && rows !== undefined && visible.length === 0 && (
        <div className="border-t border-border/0">
          {search && rows.length > 0 ? (
            <EmptyState compact title="No matches" description="No rows match the current search or filters." />
          ) : (
            (empty ?? <EmptyState compact title="Nothing to show" />)
          )}
        </div>
      )}
      {clientPaged && filtered.length > pageSize && (
        <PaginationBar
          from={safePage * pageSize + 1}
          to={Math.min(filtered.length, (safePage + 1) * pageSize)}
          total={filtered.length}
          canPrev={safePage > 0}
          canNext={safePage < pageCount - 1}
          onPrev={() => setPage(safePage - 1)}
          onNext={() => setPage(safePage + 1)}
        />
      )}
      {pagination && pagination.total > 0 && (
        <PaginationBar
          from={pagination.offset + 1}
          to={Math.min(pagination.total, pagination.offset + (rows?.length ?? 0))}
          total={pagination.total}
          canPrev={pagination.offset > 0}
          canNext={pagination.offset + pagination.limit < pagination.total}
          onPrev={() => pagination.onChange(Math.max(0, pagination.offset - pagination.limit))}
          onNext={() => pagination.onChange(pagination.offset + pagination.limit)}
        />
      )}
      {footer}
    </div>
  )
}

function PaginationBar({
  from,
  to,
  total,
  canPrev,
  canNext,
  onPrev,
  onNext,
}: {
  from: number
  to: number
  total: number
  canPrev: boolean
  canNext: boolean
  onPrev: () => void
  onNext: () => void
}) {
  return (
    <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[12px] text-subtle">
      <span className="tabular-nums">
        {formatNumber(from)}–{formatNumber(to)} of {formatNumber(total)}
      </span>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={onPrev}
          disabled={!canPrev}
          className="flex h-7 w-7 items-center justify-center rounded-md border border-border text-muted hover:text-fg disabled:opacity-40"
          aria-label="Previous page"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          onClick={onNext}
          disabled={!canNext}
          className="flex h-7 w-7 items-center justify-center rounded-md border border-border text-muted hover:text-fg disabled:opacity-40"
          aria-label="Next page"
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  )
}
