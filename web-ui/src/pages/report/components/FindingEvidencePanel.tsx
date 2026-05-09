import { panelClass } from '../../../components/ui/styles'
import type { FindingView } from '../../../services/api'

export function FindingEvidencePanel({ findings }: { findings?: FindingView[] }) {
  if (!findings || findings.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No finding evidence available.</div>
  }
  return (
    <div className={panelClass() + ' space-y-3'}>
      <div className="font-semibold text-slate-100">Evidence</div>
      {findings.slice(0, 8).map((finding) => (
        <details key={finding.id} className="rounded border border-slate-800 p-3">
          <summary className="cursor-pointer text-sm font-semibold text-slate-200">{finding.rule_id}</summary>
          <div className="mt-2 space-y-2">
            {finding.evidence.length === 0 ? (
              <div className="text-sm text-slate-500">No parsed evidence.</div>
            ) : finding.evidence.map((evidence, index) => (
              <pre key={index} className="max-h-32 overflow-auto rounded bg-slate-950 p-2 text-xs text-slate-300">
                {evidence.command || evidence.source_file || 'evidence'}{'\n'}{evidence.excerpt || ''}
              </pre>
            ))}
          </div>
        </details>
      ))}
    </div>
  )
}
