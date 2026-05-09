import { useState } from 'react'
import type { DiagnosisViewModel } from '../diagnosis'
import { buttonClass, panelClass, tableShellClass } from '../../../components/ui/styles'
import { clampPercent } from '../utils'
import { CardSection, EffortPill, PhasePill, SeverityPill, YesNoPill } from './Primitives'

interface DiagnosisSectionProps {
  diagnosisRaw: unknown
  diagnosis: DiagnosisViewModel | null
}

export function DiagnosisSection({ diagnosisRaw, diagnosis }: DiagnosisSectionProps) {
  const [showFullPlan, setShowFullPlan] = useState(false)

  if (diagnosisRaw == null) return null

  return (
    <CardSection title="AI Diagnosis" right={<p className="text-sm text-slate-400">Decision-first remediation view</p>}>
      {diagnosis ? (
        <div className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            <div className={panelClass() + ' lg:col-span-2'}>
              <div className="text-sm font-medium text-slate-200">Root cause</div>
              <div className="mt-2 text-sm text-slate-300">{diagnosis.rootCause || '-'}</div>
              {diagnosis.healthSummary && (
                <div className={panelClass() + ' mt-3 p-3 text-sm text-slate-300'}>
                  {diagnosis.healthSummary}
                </div>
              )}
            </div>

            <div className={panelClass()}>
              <div className="text-sm font-medium text-slate-200">Confidence</div>
              {diagnosis.confidence !== null ? (
                <>
                  <div className="mt-3 h-2 overflow-hidden rounded bg-slate-800">
                    <div className="h-2 bg-sky-600" style={{ width: `${clampPercent(diagnosis.confidence * 100)}%` }} />
                  </div>
                  <div className="mt-2 text-xs text-slate-400">{Math.round(diagnosis.confidence * 100)}%</div>
                </>
              ) : (
                <div className="mt-2 text-sm text-slate-400">-</div>
              )}
            </div>
          </div>

          {diagnosis.topRisks.length > 0 && (
            <div className={panelClass()}>
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium text-slate-200">Top risks</div>
                <div className="text-xs text-slate-500">Highest impact items</div>
              </div>

              <div className="mt-3 space-y-2">
                {diagnosis.topRisks.slice(0, 6).map((risk, idx) => (
                  <div key={`${risk.title}-${idx}`} className={panelClass() + ' p-3'}>
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <SeverityPill severity={risk.severity} />
                        <div className="text-sm font-medium text-slate-100">{risk.title}</div>
                      </div>
                      {risk.findingId && <div className="text-xs text-slate-500">{risk.findingId}</div>}
                    </div>
                    {risk.impact && <div className="mt-2 text-sm text-slate-300">{risk.impact}</div>}
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      {risk.fixEffort && <EffortPill effort={risk.fixEffort} />}
                      {risk.confidence !== null && <span className="text-xs text-slate-400">Confidence: {Math.round(risk.confidence * 100)}%</span>}
                      {risk.isAutoFixable !== null && <YesNoPill value={risk.isAutoFixable} yesLabel="Auto-fix" noLabel="Manual" />}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {diagnosis.autoFixCandidates.length > 0 && (
            <div className={panelClass()}>
              <div className="text-sm font-medium text-slate-200">Auto-fix candidates</div>
              <div className="mt-0.5 text-xs text-slate-500">Items marked as safe to automate (where supported)</div>
              <div className="mt-3 flex flex-wrap gap-2">
                {diagnosis.autoFixCandidates.slice(0, 12).map((candidate) => (
                  <span key={candidate} className="rounded-md border border-slate-800 bg-slate-900/40 px-2 py-1 text-xs text-slate-200">
                    {candidate}
                  </span>
                ))}
              </div>
            </div>
          )}

          {diagnosis.remediationPlan.length > 0 && (
            <div className={panelClass()}>
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-slate-200">Remediation plan</div>
                  <div className="mt-0.5 text-xs text-slate-500">Top 5 priorities first</div>
                </div>
                <button
                  type="button"
                  onClick={() => setShowFullPlan((prev) => !prev)}
                  className={buttonClass({ variant: 'default', size: 'sm' })}
                >
                  {showFullPlan ? 'Hide full plan' : `Show full plan (${diagnosis.remediationPlan.length})`}
                </button>
              </div>

              <div className="space-y-2">
                {diagnosis.remediationPlan.slice(0, 5).map((item, idx) => (
                  <div key={`${item.title}-${idx}`} className={panelClass() + ' p-3'}>
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-medium text-slate-100">
                        #{item.priority ?? idx + 1} {item.title}
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {item.effort && <EffortPill effort={item.effort} />}
                        {item.phase !== null && <PhasePill phase={item.phase} />}
                        {item.requiresDowntime !== null && <YesNoPill value={!item.requiresDowntime} yesLabel="No downtime" noLabel="Downtime" />}
                      </div>
                    </div>
                    {item.description && <div className="mt-1 text-xs text-slate-400">{item.description}</div>}
                  </div>
                ))}
              </div>

              {showFullPlan && (
                <div className="mt-3 overflow-x-auto border-t border-slate-800 pt-3">
                  <div className={tableShellClass()}>
                    <table className="w-full text-sm">
                      <thead className="bg-slate-800/50 text-slate-400">
                      <tr>
                        <th className="px-4 py-2 text-left">Priority</th>
                        <th className="px-4 py-2 text-left">Title</th>
                        <th className="px-4 py-2 text-left">Category</th>
                        <th className="px-4 py-2 text-left">Effort</th>
                        <th className="px-4 py-2 text-left">Phase</th>
                        <th className="px-4 py-2 text-left">ETA</th>
                        <th className="px-4 py-2 text-left">Downtime</th>
                        <th className="px-4 py-2 text-left">Auto-fix</th>
                      </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                      {diagnosis.remediationPlan.slice(0, 20).map((item, idx) => (
                        <tr key={`${item.title}-table-${idx}`} className="hover:bg-slate-800/30">
                          <td className="px-4 py-2 align-top font-mono text-xs text-slate-300">{item.priority ?? idx + 1}</td>
                          <td className="px-4 py-2">
                            <div className="font-medium text-slate-100">{item.title}</div>
                            {item.description && <div className="mt-1 whitespace-pre-wrap text-xs text-slate-400">{item.description}</div>}
                          </td>
                          <td className="px-4 py-2 align-top text-slate-300">{item.category || '-'}</td>
                          <td className="px-4 py-2 align-top">{item.effort ? <EffortPill effort={item.effort} /> : <span className="text-slate-400">-</span>}</td>
                          <td className="px-4 py-2 align-top">{item.phase !== null ? <PhasePill phase={item.phase} /> : <span className="text-slate-400">-</span>}</td>
                          <td className="px-4 py-2 align-top text-slate-300">{item.estimatedTime || '-'}</td>
                          <td className="px-4 py-2 align-top">
                            {item.requiresDowntime !== null ? <YesNoPill value={!item.requiresDowntime} yesLabel="No" noLabel="Yes" /> : <span className="text-slate-400">-</span>}
                          </td>
                          <td className="px-4 py-2 align-top">
                            {item.isAutoFixable !== null ? <YesNoPill value={item.isAutoFixable} yesLabel="Yes" noLabel="No" /> : <span className="text-slate-400">-</span>}
                          </td>
                        </tr>
                      ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            {Object.keys(diagnosis.environmentSummary).length > 0 && (
              <div className={panelClass()}>
                <div className="text-sm font-medium text-slate-200">Environment</div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                  {Object.entries(diagnosis.environmentSummary).map(([key, value]) => (
                    <div key={key} className={panelClass() + ' p-3'}>
                      <div className="text-xs text-slate-500">{key}</div>
                      <div className="mt-0.5 text-slate-200">{String(value)}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {Object.keys(diagnosis.categoryBreakdown).length > 0 && (
              <div className={panelClass()}>
                <div className="text-sm font-medium text-slate-200">Category breakdown</div>
                <div className="mt-3 space-y-2">
                  {Object.entries(diagnosis.categoryBreakdown).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-900/40 px-3 py-2">
                      <div className="text-sm text-slate-300">{key}</div>
                      <div className="text-sm font-medium text-slate-100">{value}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="mt-3 text-sm text-slate-400">AI diagnosis data is not in a structured format.</div>
      )}

      <details className="mt-4 rounded-md border border-slate-800 bg-slate-950/20 p-3">
        <summary className="cursor-pointer text-sm text-slate-300">View raw diagnosis JSON</summary>
        <pre className="mt-3 max-h-[420px] overflow-auto rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-300">
          {JSON.stringify(diagnosisRaw, null, 2)}
        </pre>
      </details>
    </CardSection>
  )
}
