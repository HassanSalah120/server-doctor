import { useEffect, useState } from 'react'
import { RouterProvider } from 'react-router-dom'

import { router } from './router'
import { api } from './services/api'

export default function App() {
  const [authState, setAuthState] = useState<'loading' | 'ready' | 'login'>('loading')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.authStatus()
      .then((status) => setAuthState(status.authenticated ? 'ready' : 'login'))
      .catch(() => setAuthState('login'))
  }, [])

  async function submitLogin(event: React.FormEvent) {
    event.preventDefault()
    try {
      setError(null)
      const status = await api.login(password)
      setAuthState(status.authenticated ? 'ready' : 'login')
      setPassword('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    }
  }

  if (authState === 'loading') {
    return <div className="min-h-screen bg-slate-950 p-8 text-slate-300">Loading...</div>
  }

  if (authState === 'login') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-slate-100">
        <form onSubmit={submitLogin} className="w-full max-w-sm rounded-lg border border-slate-800 bg-slate-900/60 p-5">
          <div className="text-lg font-semibold">ServerDoctor</div>
          <div className="mt-1 text-sm text-slate-400">Local web access is protected.</div>
          <label className="mt-5 block text-sm text-slate-300">
            Password
            <input
              className="mt-2 min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-100 outline-none focus:border-sky-500"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoFocus
            />
          </label>
          {error && <div className="mt-3 rounded border border-red-800 bg-red-950/40 p-2 text-sm text-red-200">{error}</div>}
          <button type="submit" className="mt-4 min-h-11 w-full rounded-lg bg-sky-600 px-4 font-semibold text-white hover:bg-sky-500">
            Log in
          </button>
        </form>
      </div>
    )
  }

  return <RouterProvider router={router} />
}
