import { panelClass } from '../../../components/ui/styles'
import { SeverityBadge } from './Primitives'
import type { Finding } from '../../../services/api'

const HEADER_LABELS: Record<string, string> = {
  'HDR-001': 'CSP',
  'HDR-002': 'CSP (weak)',
  'HDR-003': 'HSTS',
  'HDR-004': 'HSTS (short)',
  'HDR-005': 'X-Frame-Options',
  'HDR-006': 'X-Content-Type-Options',
  'HDR-007': 'X-XSS-Protection',
  'HDR-008': 'Referrer-Policy',
  'HDR-009': 'Cache-Control (sensitive)',
}

export function SecurityHeadersPanel({ findings }: { findings: Finding[] }) {
  const hdrFindings = findings.filter((f) => f.rule_id.startsWith('HDR-'))
  const corsFindings = findings.filter((f) => f.rule_id.startsWith('CORS-'))
  const all = [...hdrFindings, ...corsFindings]
  if (all.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No security header findings.</div>
  }

  const missingHeaders = hdrFindings.filter((f) => f.severity.toLowerCase() !== 'info')
  const infoHeaders = hdrFindings.filter((f) => f.severity.toLowerCase() === 'info')

  return (
    <div className={panelClass() + ' space-y-3'}>
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-100">Security Headers & CORS</div>
        <div className="flex gap-1 text-xs text-slate-500">
          <span className="text-red-400">{missingHeaders.length} missing</span>
          <span>·</span>
          <span className="text-slate-400">{infoHeaders.length} advisory</span>
          {corsFindings.length > 0 && (
            <>
              <span>·</span>
              <span className="text-yellow-400">{corsFindings.length} CORS</span>
            </>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {missingHeaders.map((f) => (
          <span
            key={f.id}
            className="inline-flex items-center gap-1 rounded-md bg-red-500/10 px-2 py-1 text-xs text-red-300"
            title={f.description || ''}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
            {HEADER_LABELS[f.rule_id] || f.rule_id}
          </span>
        ))}
        {infoHeaders.map((f) => (
          <span
            key={f.id}
            className="inline-flex items-center gap-1 rounded-md bg-slate-800 px-2 py-1 text-xs text-slate-300"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
            {HEADER_LABELS[f.rule_id] || f.rule_id}
          </span>
        ))}
        {corsFindings.map((f) => (
          <span
            key={f.id}
            className="inline-flex items-center gap-1 rounded-md bg-yellow-500/10 px-2 py-1 text-xs text-yellow-300"
            title={f.description || ''}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
            {f.rule_id}
          </span>
        ))}
      </div>

      {all.map((f) => (
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
