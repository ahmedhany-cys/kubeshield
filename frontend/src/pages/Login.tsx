import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { LogIn } from 'lucide-react'
import { errorMessage } from '../api/client'
import { Button } from '../components/Button'
import { InlineError } from '../components/ErrorState'
import { Field } from '../components/Form'
import { Loading } from '../components/Loading'
import { Logo } from '../components/Logo'
import { useAuth } from '../hooks/useAuth'

function safeNext(value: string | null): string {
  // Only allow in-app relative paths to prevent open redirects.
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/login')) return '/'
  return value
}

export default function LoginPage() {
  const { user, checking, login } = useAuth()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const next = safeNext(params.get('next'))

  if (checking) return <Loading label="Checking session…" className="h-full" />
  if (user) return <Navigate to={next} replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setPending(true)
    setError(null)
    try {
      await login(username.trim(), password)
      setPassword('')
      navigate(next, { replace: true })
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-bg px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <Logo className="h-11 w-11" />
          <h1 className="mt-4 text-[20px] font-semibold tracking-tight text-fg">Sign in to KubeShield</h1>
          <p className="mt-1 text-[13px] text-muted">Kubernetes runtime threat detection and response</p>
        </div>
        <form onSubmit={submit} className="rounded-lg border border-border bg-surface p-6 shadow-xl shadow-black/30">
          <Field label="Username" className="mb-4">
            <input
              className="input h-9 w-full"
              autoComplete="username"
              autoFocus
              required
              maxLength={64}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Field>
          <Field label="Password" className="mb-5">
            <input
              className="input h-9 w-full"
              type="password"
              autoComplete="current-password"
              required
              maxLength={256}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          <Button
            type="submit"
            variant="primary"
            className="h-9 w-full"
            loading={pending}
            icon={<LogIn className="h-4 w-4" />}
            disabled={!username || !password}
          >
            Sign in
          </Button>
          <InlineError message={error} />
        </form>
        <p className="mt-6 text-center text-[11.5px] text-subtle">
          Sessions use an HttpOnly cookie. Accounts are managed by the KubeShield administrator.
        </p>
      </div>
    </div>
  )
}
