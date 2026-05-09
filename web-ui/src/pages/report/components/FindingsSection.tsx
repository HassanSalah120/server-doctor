import { useMemo, useState } from 'react'
import type { Finding } from '../../../services/api'
import { buttonClass, panelClass } from '../../../components/ui/styles'
import { filterFindingsByCategory, groupBySeverity, severityRank, uniqueCategories } from '../utils'
import { CardSection, SeverityBadge, SeverityPieChart } from './Primitives'

interface FindingsSectionProps {
  findings: Finding[]
  isPending: boolean
  categoryFilter: string
  onCategoryFilterChange: (next: string) => void
}

function FindingCard({ finding, compact = false }: { finding: Finding; compact?: boolean }) {
  return (
    <div className={panelClass() + ' p-3'}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity || 'info'} />
          {finding.is_regression && (
            <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold uppercase text-amber-200">
              Regression
            </span>
          )}
          <div className="text-sm font-medium text-slate-100">{finding.title}</div>
        </div>
        {finding.rule_id && finding.rule_id !== 'unknown' && <div className="text-xs text-slate-500">{finding.rule_id}</div>}
      </div>

      {!compact && (finding.category || finding.component) && (
        <div className="mt-2 flex flex-wrap gap-2">
          {finding.category && finding.category !== 'unknown' && (
            <span className="rounded-lg border border-slate-800 bg-slate-900/40 px-2 py-0.5 text-xs text-slate-200">
              {finding.category}
            </span>
          )}
          {finding.component && finding.component !== 'unknown' && (
            <span className="rounded-lg border border-slate-800 bg-slate-900/40 px-2 py-0.5 text-xs text-slate-200">
              {finding.component}
            </span>
          )}
        </div>
      )}

      {finding.description && <div className="mt-1 text-xs text-slate-400">{finding.description}</div>}
      {!compact && finding.recommendation && <div className="mt-2 text-xs text-blue-400">Fix: {finding.recommendation}</div>}
    </div>
  )
}

export function FindingsSection({ findings, isPending, categoryFilter, onCategoryFilterChange }: FindingsSectionProps) {
  const [showAllFindings, setShowAllFindings] = useState(false)
  const categories = useMemo(() => uniqueCategories(findings), [findings])

  const filteredFindings = useMemo(() => filterFindingsByCategory(findings, categoryFilter), [findings, categoryFilter])
  const groups = useMemo(() => groupBySeverity(filteredFindings), [filteredFindings])

  const pieData = useMemo(
    () => Object.fromEntries(Object.entries(groups).map(([severity, items]) => [severity, items.length])),
    [groups],
  )

  const prioritizedFindings = useMemo(
    () => [...filteredFindings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [filteredFindings],
  )

  const headlineFindings = prioritizedFindings.slice(0, 5)
  const overflowFindings = prioritizedFindings.slice(5)

  return (
    <CardSection title="Findings" right={findings.length > 0 ? <SeverityPieChart data={pieData} /> : undefined}>
      {findings.length === 0 ? (
        <div className="mt-3 space-y-1 text-sm text-slate-400">
          <div>{isPending ? 'This job is still running. Findings will appear when it finishes.' : 'No findings for this job.'}</div>
          {isPending && <div className="text-xs text-slate-500">Tip: press Refresh or check Jobs for progress.</div>}
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          {categories.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  onCategoryFilterChange('all')
                  setShowAllFindings(false)
                }}
                className={
                  buttonClass({ variant: categoryFilter === 'all' ? 'default' : 'ghost', size: 'sm' }) +
                  (categoryFilter === 'all' ? '' : ' border border-slate-800')
                }
              >
                All
              </button>
              {categories.map((category) => (
                <button
                  key={category}
                  type="button"
                  onClick={() => {
                    onCategoryFilterChange(category)
                    setShowAllFindings(false)
                  }}
                  className={
                    buttonClass({ variant: categoryFilter === category ? 'default' : 'ghost', size: 'sm' }) +
                    (categoryFilter === category ? '' : ' border border-slate-800')
                  }
                >
                  {category}
                </button>
              ))}
              <div className="ml-auto text-xs text-slate-500">
                Showing {filteredFindings.length}/{findings.length}
              </div>
            </div>
          )}

          {filteredFindings.length === 0 ? (
            <div className={panelClass() + ' p-3 text-sm text-slate-400'}>No findings in this category.</div>
          ) : (
            <>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-xs uppercase tracking-[0.14em] text-slate-400">Top 5 prioritized findings</div>
                  <div className="text-xs text-slate-500">Sorted by severity</div>
                </div>
                <div className="space-y-2">
                  {headlineFindings.map((finding) => (
                    <FindingCard key={finding.id} finding={finding} />
                  ))}
                </div>
              </div>

              {overflowFindings.length > 0 && (
                <details open={showAllFindings} className={panelClass({ padded: false })}>
                  <summary
                    className="cursor-pointer px-3 py-2 text-sm text-slate-300"
                    onClick={(event) => {
                      event.preventDefault()
                      setShowAllFindings((prev) => !prev)
                    }}
                  >
                    {showAllFindings ? 'Hide' : 'Show'} remaining {overflowFindings.length} finding(s)
                  </summary>
                  {showAllFindings && (
                    <div className="space-y-2 border-t border-slate-800 p-3">
                      {overflowFindings.map((finding) => (
                        <FindingCard key={`overflow-${finding.id}`} finding={finding} compact />
                      ))}
                    </div>
                  )}
                </details>
              )}
            </>
          )}
        </div>
      )}
    </CardSection>
  )
}
