import { useState } from 'react'
import { api } from '../api'
import type { AuthUser } from '../types'

// Login is the gate shown until api.me() succeeds -- see App.tsx, which
// mounts this in place of the whole app while auth state is unknown or
// signed-out. Aperture ships with a single seeded test account
// (user / user, see cmd/aperture/main.go) so there's always something to
// sign in with out of the box.
export function Login({ onLoggedIn }: { onLoggedIn: (user: AuthUser) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const user = await api.login(email, password)
      onLoggedIn(user)
    } catch {
      // Deliberately generic -- the backend gives wrong-email and
      // wrong-password the same message/status so this can't leak which
      // one was wrong either.
      setError('Invalid email or password')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-neutral-950">
      <form onSubmit={submit} className="w-full max-w-xs space-y-4 rounded-lg border border-neutral-800 bg-neutral-900 p-6">
        <h1 className="text-center text-lg font-semibold text-neutral-100">Aperture</h1>
        <div className="space-y-1">
          <label className="block text-xs font-medium uppercase tracking-wide text-neutral-500" htmlFor="login-email">
            Username
          </label>
          <input
            id="login-email"
            type="text"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500"
            required
          />
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium uppercase tracking-wide text-neutral-500" htmlFor="login-password">
            Password
          </label>
          <input
            id="login-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500"
            required
          />
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-sky-600 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
