import { useState } from 'react'
import { Check, ChevronDown, ChevronRight, Copy } from 'lucide-react'
import { cx } from '../lib/format'

export function JsonView({
  value,
  title = 'Raw JSON',
  defaultOpen = false,
  maxHeight = 420,
}: {
  value: unknown
  title?: string
  defaultOpen?: boolean
  maxHeight?: number
}) {
  const [open, setOpen] = useState(defaultOpen)
  const [copied, setCopied] = useState(false)
  const text = JSON.stringify(value ?? null, null, 2)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="rounded-md border border-border bg-bg/60">
      <div className="flex items-center justify-between px-3 py-1.5">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-1.5 text-[12px] font-medium text-muted hover:text-fg"
          aria-expanded={open}
        >
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          {title}
        </button>
        {open && (
          <button type="button" onClick={copy} className="flex items-center gap-1 text-[11px] text-subtle hover:text-fg">
            {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        )}
      </div>
      {open && (
        <pre
          className={cx('overflow-auto border-t border-border px-3 py-2 font-mono text-[11.5px] leading-relaxed text-muted')}
          style={{ maxHeight }}
        >
          {text}
        </pre>
      )}
    </div>
  )
}

/** Inline code-ish block for command lines and stdout. */
export function CodeBlock({ children, className }: { children: string; className?: string }) {
  return (
    <pre
      className={cx(
        'max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-bg/70 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-muted',
        className,
      )}
    >
      {children}
    </pre>
  )
}
