import { panelClass } from '../../../components/ui/styles'
import type { RootCause } from '../../../services/api'

export function RootCausePanel({ rootCauses }: { rootCauses?: RootCause[] }) {
  if (!rootCauses) {
    return <div className={panelClass() + ' text-slate-400'}>Loading diagnosis...</div>
  }
  if (rootCauses.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No root-cause groups found.</div>
  }

  return (
    <div className={panelClass() + ' space-y-3'}>
      <div>
        <div className="text-sm font-semibold text-slate-100">Root Cause Groups</div>
        <div className="text-xs text-slate-500">Grouped hypotheses from related findings.</div>
      </div>
      {rootCauses.map((cause) => (
        <div key={cause.id} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="font-medium text-slate-100">{cause.title}</div>
            <span className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300">
              {Math.round(cause.confidence * 100)}%
            </span>
          </div>
          <p className="mt-2 text-sm text-slate-300">{cause.hypothesis}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {cause.supporting_rule_ids.map((id) => (
              <span key={id} className="rounded bg-slate-900 px-2 py-1 text-xs text-slate-300">
                {id}
              </span>
            ))}
          </div>
          <ul className="mt-2 space-y-1 text-sm text-slate-400">
            {cause.recommended_next_steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}
