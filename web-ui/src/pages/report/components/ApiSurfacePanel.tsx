import { panelClass } from '../../../components/ui/styles'
import { SeverityBadge } from './Primitives'
import type { Finding } from '../../../services/api'

const API_LABELS: Record<string, string> = {
  'API-001': 'Sensitive endpoints',
  'API-002': 'GraphQL exposure',
  'API-003': 'Debug panel',
  'API-004': 'Backup files',
  'API-005': 'VCS exposure',
  'API-006': 'Stack traces',
}

export function ApiSurfacePanel({ findings }: { findings: Finding[] }) {
  const apiFindings = findings.filter((f) => f.rule_id.startsWith('API-'))
  if (apiFindings.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No API surface findings.</div>
  }

  const critical = apiFindings.filter((f) => f.severity.toLowerCase() === 'critical').length
  const warnings = apiFindings.filter((f) => f.severity.toLowerCase() === 'warning').length

  return (
    <div className={panelClass() + ' space-y-3'}>
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-100">API Surface</div>
        <div className="flex gap-1 text-xs text-slate-500">
          {critical > 0 && <span className="text-red-400">{critical} critical</span>}
          {warnings > 0 && <span className="text-yellow-400">{warnings} warnings</span>}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {apiFindings.map((f) => (
          <span
            key={f.id}
            className={`inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs ${
              f.severity.toLowerCase() === 'critical'
                ? 'bg-red-500/10 text-red-300'
                : f.severity.toLowerCase() === 'warning'
                  ? 'bg-yellow-500/10 text-yellow-300'
                  : 'bg-slate-800 text-slate-300'
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                f.severity.toLowerCase() === 'critical'
                  ? 'bg-red-400'
                  : f.severity.toLowerCase() === 'warning'
                    ? 'bg-yellow-400'
                    : 'bg-slate-500'
              }`}
            />
            {API_LABELS[f.rule_id] || f.rule_id}
          </span>
        ))}
      </div>

      {apiFindings.map((f) => (
        <div key={f.id} className="rounded border border-slate-800 p-2 text-sm">
          <div className="flex items-start justify-between gap-2">
            <div className="font-medium text-slate-200">{f.title}</div>
            <SeverityBadge severity={f.severity} />
          </div>
          {f.description && <div className="mt-1 text-xs text-slate-400">{f.description}</div>}
          <div className="mt-1 text-xs text-slate-500">{f.rule_id}</div>
        </div>
      ))}
    </div>
  )
}
