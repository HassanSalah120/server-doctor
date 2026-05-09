import { panelClass } from '../../../components/ui/styles'
import type { Finding } from '../../../services/api'

export function EndpointProbePanel({ findings }: { findings: Finding[] }) {
  const probeFindings = findings.filter((finding) => finding.rule_id.startsWith('HTTP-PROBE'))
  if (probeFindings.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No endpoint probe findings.</div>
  }

  return (
    <div className={panelClass() + ' space-y-2'}>
      <div className="text-sm font-semibold text-slate-100">Endpoint Probes</div>
      {probeFindings.map((finding) => (
        <div key={finding.id} className="rounded border border-slate-800 p-2 text-sm">
          <div className="font-medium text-slate-200">{finding.title}</div>
          <div className="text-xs text-slate-500">{finding.rule_id}</div>
        </div>
      ))}
    </div>
  )
}
