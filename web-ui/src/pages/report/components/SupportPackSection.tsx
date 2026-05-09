import type { ReportSupportPack } from '../../../services/api'
import { panelClass } from '../../../components/ui/styles'
import { CardSection } from './Primitives'

interface SupportPackSectionProps {
  supportPack: ReportSupportPack | null | undefined
}

function keyValueRows(context: ReportSupportPack['runtime_context']): Array<{ key: string; value: string }> {
  return [
    { key: 'ServerDoctor', value: `${context.doctor_version} (${context.doctor_build})` },
    { key: 'Mode', value: context.mode },
    { key: 'OS', value: context.os },
    { key: 'Nginx', value: context.nginx },
    { key: 'Target', value: context.target_host },
    { key: 'Runner', value: context.runner },
    { key: 'Install', value: context.install_hint },
  ]
}

function coverageStatusClass(status: string): string {
  if (status === 'collected') return 'border-green-500/40 bg-green-500/15 text-green-300'
  if (status === 'not_accessible') return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300'
  if (status === 'not_applicable') return 'border-slate-600 bg-slate-700/30 text-slate-300'
  if (status === 'error') return 'border-red-500/40 bg-red-500/15 text-red-300'
  return 'border-blue-500/40 bg-blue-500/15 text-blue-300'
}

export function SupportPackSection({ supportPack }: SupportPackSectionProps) {
  if (!supportPack) return null

  const runtimeRows = keyValueRows(supportPack.runtime_context)
  const reproRows = Array.isArray(supportPack.reproduction_commands) ? supportPack.reproduction_commands : []
  const evidenceRows = Array.isArray(supportPack.evidence_snippets) ? supportPack.evidence_snippets : []
  const pathNotes = Array.isArray(supportPack.path_notes) ? supportPack.path_notes : []
  const coverageRows = Array.isArray(supportPack.coverage_matrix) ? supportPack.coverage_matrix : []
  const expectedBehavior = Array.isArray(supportPack.expected_behavior) ? supportPack.expected_behavior : []

  return (
    <CardSection title="Issue Repro Pack" right={<p className="text-xs text-slate-400">Copy-ready support context</p>}>
      <div className="space-y-4">
        <div className={panelClass()}>
          <div className="mb-2 text-sm font-medium text-slate-200">Runtime context</div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {runtimeRows.map((row) => (
              <div key={row.key} className={panelClass() + ' p-3'}>
                <div className="text-[10px] uppercase tracking-wide text-slate-500">{row.key}</div>
                <div className="mt-1 text-sm text-slate-200">{row.value || '-'}</div>
              </div>
            ))}
          </div>
        </div>

        {reproRows.length > 0 && (
          <div className={panelClass()}>
            <div className="mb-2 text-sm font-medium text-slate-200">Reproduction commands</div>
            <div className="space-y-2">
              {reproRows.map((row, idx) => (
                <div key={`${row.title}-${idx}`} className={panelClass() + ' p-3'}>
                  <div className="text-sm font-medium text-slate-200">{row.title}</div>
                  <pre className="mt-2 overflow-auto rounded border border-slate-800 bg-slate-950/60 p-2 text-xs text-slate-300">
                    {row.command}
                  </pre>
                  <div className="mt-2 text-xs text-slate-400">Expected: {row.expected}</div>
                  {row.observed && <div className="mt-1 text-xs text-slate-500">Observed: {row.observed}</div>}
                </div>
              ))}
            </div>
          </div>
        )}

        {evidenceRows.length > 0 && (
          <div className={panelClass()}>
            <div className="mb-2 text-sm font-medium text-slate-200">Evidence snippets</div>
            <div className="space-y-2">
              {evidenceRows.map((row, idx) => (
                <div key={`${row.topic}-${idx}`} className={panelClass() + ' p-3'}>
                  <div className="text-sm text-slate-200">{row.topic}</div>
                  <div className="mt-1 text-xs text-slate-500">Command: {row.command}</div>
                  <pre className="mt-2 overflow-auto rounded border border-slate-800 bg-slate-950/60 p-2 text-xs text-slate-300">
                    {row.snippet}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {pathNotes.length > 0 && (
          <div className={panelClass()}>
            <div className="mb-2 text-sm font-medium text-slate-200">Path notes</div>
            <ul className="space-y-1 text-sm text-slate-300">
              {pathNotes.map((note, idx) => (
                <li key={`${idx}-${note.slice(0, 40)}`}>- {note}</li>
              ))}
            </ul>
          </div>
        )}

        {coverageRows.length > 0 && (
          <div className={panelClass()}>
            <div className="mb-2 text-sm font-medium text-slate-200">Coverage matrix</div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-slate-400">
                  <tr>
                    <th className="px-2 py-1 text-left">Check</th>
                    <th className="px-2 py-1 text-left">Status</th>
                    <th className="px-2 py-1 text-left">Detail</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {coverageRows.map((row, idx) => (
                    <tr key={`${row.check}-${idx}`}>
                      <td className="px-2 py-1.5 text-slate-300">{row.check}</td>
                      <td className="px-2 py-1.5">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase ${coverageStatusClass(row.status)}`}>
                          {row.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 text-slate-500">{row.detail || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {expectedBehavior.length > 0 && (
          <div className={panelClass()}>
            <div className="mb-2 text-sm font-medium text-slate-200">Expected tool behavior</div>
            <ul className="space-y-1 text-sm text-slate-300">
              {expectedBehavior.map((line, idx) => (
                <li key={`${idx}-${line.slice(0, 40)}`}>- {line}</li>
              ))}
            </ul>
          </div>
        )}

        <details className="rounded-md border border-slate-800 bg-slate-950/20 p-3">
          <summary className="cursor-pointer text-sm text-slate-300">View support pack JSON</summary>
          <pre className="mt-3 max-h-[420px] overflow-auto rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-300">
            {JSON.stringify(supportPack, null, 2)}
          </pre>
        </details>
      </div>
    </CardSection>
  )
}
