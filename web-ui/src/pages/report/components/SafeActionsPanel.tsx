import { useState } from 'react'
import { buttonClass, panelClass } from '../../../components/ui/styles'
import { api, type SafeActionResponse } from '../../../services/api'

const actions = [
  { id: 'nginx_test', label: 'Test Nginx config', runAllowed: true },
  { id: 'list_open_ports', label: 'List open ports', runAllowed: true },
  { id: 'nginx_reload', label: 'Preview Nginx reload', runAllowed: false },
]

export function SafeActionsPanel({ serverId }: { serverId?: number }) {
  const [loadingAction, setLoadingAction] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [response, setResponse] = useState<SafeActionResponse | null>(null)

  async function preview(actionId: string) {
    if (!serverId) return
    try {
      setLoadingAction(actionId)
      setError(null)
      setResponse(await api.safeAction(serverId, actionId, 'preview'))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load action')
    } finally {
      setLoadingAction(null)
    }
  }

  if (!serverId) return <div className={panelClass() + ' text-slate-400'}>No server selected for safe actions.</div>

  return (
    <div className={panelClass() + ' space-y-3'}>
      <div>
        <div className="text-sm font-semibold text-slate-100">Safe Actions</div>
        <div className="text-xs text-slate-500">Registry-defined previews and read-only commands.</div>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {actions.map((action) => (
          <button
            key={action.id}
            type="button"
            className={buttonClass({ variant: 'default', size: 'sm' }) + ' min-h-11 justify-center'}
            onClick={() => preview(action.id)}
            disabled={loadingAction === action.id}
          >
            {loadingAction === action.id ? 'Loading...' : action.label}
          </button>
        ))}
      </div>
      {error && <div className="rounded border border-red-900 bg-red-950/30 p-2 text-sm text-red-300">{error}</div>}
      {response && (
        <div className="rounded border border-slate-800 bg-slate-950/50 p-3">
          <div className="text-xs uppercase tracking-wide text-slate-500">{response.risk} risk</div>
          <pre className="mt-2 overflow-auto whitespace-pre-wrap text-xs text-slate-300">{response.command}</pre>
          {response.output && <pre className="mt-2 overflow-auto whitespace-pre-wrap text-xs text-slate-400">{response.output}</pre>}
        </div>
      )}
    </div>
  )
}
