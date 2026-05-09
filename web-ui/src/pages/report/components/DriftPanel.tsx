import { useEffect, useState } from 'react'
import { panelClass } from '../../../components/ui/styles'
import { api, type ReportCompareResponse } from '../../../services/api'

export function DriftPanel({ jobId }: { jobId: number }) {
  const [state, setState] = useState<{ loading: boolean; error?: string; data?: ReportCompareResponse }>({ loading: true })

  useEffect(() => {
    api.getReportCompare(jobId)
      .then((data) => setState({ loading: false, data }))
      .catch((err) => setState({ loading: false, error: err instanceof Error ? err.message : 'Failed to load drift' }))
  }, [jobId])

  if (state.loading) return <div className={panelClass() + ' text-slate-400'}>Loading drift...</div>
  if (state.error) return <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-300">{state.error}</div>
  const data = state.data
  if (!data || !data.previous_job_id || data.drift.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No drift detected.</div>
  }
  return (
    <div className={panelClass() + ' space-y-2'}>
      <div className="font-semibold text-slate-100">Timeline Drift</div>
      {data.drift.map((item) => (
        <div key={`${item.kind}-${item.title}`} className="rounded border border-slate-800 p-2 text-sm text-slate-300">
          {item.title}
        </div>
      ))}
    </div>
  )
}
