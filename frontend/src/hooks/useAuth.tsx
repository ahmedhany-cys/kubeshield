import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError, onUnauthorized } from '../api/client'
import { ROLE_RANK, type Me, type Role } from '../api/types'

interface AuthContextValue {
  user: Me | null
  checking: boolean
  can: (role: Role) => boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null)
  const [checking, setChecking] = useState(true)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    let cancelled = false
    api
      .me()
      .then((me) => !cancelled && setUser(me))
      .catch((err: unknown) => {
        if (!cancelled && !(err instanceof ApiError && err.status === 401)) setUser(null)
      })
      .finally(() => !cancelled && setChecking(false))
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    onUnauthorized(() => {
      setUser(null)
      if (location.pathname !== '/login') {
        const next = location.pathname + location.search
        navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true })
      }
    })
    return () => onUnauthorized(null)
  }, [navigate, location.pathname, location.search])

  const login = useCallback(async (username: string, password: string) => {
    const me = await api.login(username, password)
    setUser({ username: me.username, role: me.role })
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      // Session may already be gone; the cookie is cleared server-side either way.
    }
    setUser(null)
    navigate('/login', { replace: true })
  }, [navigate])

  const can = useCallback((role: Role) => (user ? ROLE_RANK[user.role] >= ROLE_RANK[role] : false), [user])

  const value = useMemo(() => ({ user, checking, can, login, logout }), [user, checking, can, login, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
