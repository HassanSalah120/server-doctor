import { panelClass } from '../../../components/ui/styles'
import type { DeploymentReadiness } from '../../../services/api'

export function ReadinessSummaryCard({ readiness }: { readiness?: DeploymentReadiness | null }) {
  if (readiness === undefined) return <div className={panelClass() + ' text-slate-400'}>Loading readiness...</div>
  if (readiness === null) return <div className={panelClass() + ' text-slate-400'}>No readiness data available.</div>

  const statusLabel = readiness.ready ? 'READY' : 'BLOCKED'
  const statusColor = readiness.ready ? 'text-green-400' : 'text-red-400'

  return (
    <div className={panelClass() + ' space-y-3'}>
      <div className="text-sm font-semibold text-slate-100">Deployment Readiness</div>

      <div className="flex items-center justify-between gap-2">
        <span className={`text-lg font-bold uppercase tracking-wide ${statusColor}`}>
          {statusLabel}
        </span>
        <span className="text-sm text-slate-400">
          Readiness Score: <span className="font-semibold text-slate-100">{readiness.score}/100</span>
        </span>
      </div>

      {readiness.score_explanation && readiness.score_explanation.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why this score</div>
          <ul className="space-y-0.5">
            {readiness.score_explanation.map((reason, i) => (
              <li key={i} className="text-xs text-slate-400">- {reason}</li>
            ))}
          </ul>
        </div>
      )}

      {readiness.blockers.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-red-400">Blockers</div>
          <ul className="space-y-1">
            {readiness.blockers.map((blocker, i) => (
              <li key={i} className="rounded bg-red-500/10 px-2 py-1 text-sm text-red-200">
                {blocker}
              </li>
            ))}
          </ul>
        </div>
      )}

      {readiness.warnings.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-yellow-400">Warnings</div>
          <ul className="space-y-1">
            {readiness.warnings.map((w, i) => (
              <li key={i} className="rounded bg-yellow-500/10 px-2 py-1 text-sm text-yellow-200">
                {w}
              </li>
            ))}
          </ul>
        </div>
      )}

      {readiness.needs_verification && readiness.needs_verification.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-slate-400">Needs Verification</div>
          <ul className="space-y-1">
            {readiness.needs_verification.map((item, i) => (
              <li key={i} className="rounded bg-slate-500/10 px-2 py-1 text-sm text-slate-300">
                {item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {readiness.blockers.length === 0 && readiness.warnings.length === 0 && (!readiness.needs_verification || readiness.needs_verification.length === 0) && (
        <div className="text-sm text-slate-500">All checks passed.</div>
      )}
    </div>
  )
}
