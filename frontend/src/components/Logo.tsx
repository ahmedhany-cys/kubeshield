export function Logo({ className = 'h-7 w-7' }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="#0f1a2b" />
      <path
        d="M16 5l9 3.5v6.8c0 5.6-3.8 10.2-9 11.7-5.2-1.5-9-6.1-9-11.7V8.5L16 5z"
        fill="none"
        stroke="#3ba7ff"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path d="M12 16.2l2.8 2.8 5.2-5.6" fill="none" stroke="#3ba7ff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
