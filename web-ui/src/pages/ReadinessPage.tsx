import { useEffect, useMemo, useState } from 'react'
import { panelClass } from '../components/ui/styles'
import { api, type DeploymentReadiness, type Job } from '../services/api'

type State =
  | { status: 'loading' }
  | { status: 'error'; error: string }
  | { status: 'empty' }
  | { status: 'ready'; jobs: Job[]; selectedJobId: number; readiness: DeploymentReadiness }

export default function ReadinessPage() {
  const [state, setState] = useState<State>({ status: 'loading' })

  useEffect(() => {
    async function load() {
      try {
        const jobs = (await api.getJobs()).filter((job) => job.status === 'success')
        if (jobs.length === 0) {
          setState({ status: 'empty' })
          return
        }
        const selected = jobs[0]
        const readiness = await api.getReadiness(selected.id)
        setState({ status: 'ready', jobs, selectedJobId: selected.id, readiness })
      } catch (err) {
        setState({ status: 'error', error: err instanceof Error ? err.message : 'Failed to load readiness' })
      }
    }
    load()
  }, [])

  const content = useMemo(() => {
    if (state.status === 'loading') return <div className={panelClass() + ' text-slate-400'}>Loading readiness...</div>
    if (state.status === 'error') return <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-300">{state.error}</div>
    if (state.status === 'empty') return <div className={panelClass() + ' text-slate-400'}>No successful scans available.</div>

    return (
      <div className="space-y-4">
        <div className={panelClass() + ' space-y-3'}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-slate-100">Deployment Readiness</div>
              <div className="text-xs text-slate-500">Job #{state.selectedJobId}</div>
            </div>
            <div className={state.readiness.ready ? 'text-green-300' : 'text-red-300'}>
              {state.readiness.ready ? 'READY TO DEPLOY' : 'NOT READY'}
            </div>
          </div>
          <div className="text-3xl font-semibold text-slate-100">{state.readiness.score}</div>
        </div>
        {state.readiness.blockers.length > 0 && (
          <div className={panelClass() + ' space-y-2'}>
            <div className="font-semibold text-red-200">Blockers</div>
            {state.readiness.blockers.map((blocker) => (
              <div key={blocker} className="rounded border border-red-900/50 bg-red-950/20 p-2 text-sm text-red-100">
                {blocker}
              </div>
            ))}
          </div>
        )}
        <div className="grid gap-3 md:grid-cols-2">
          {state.readiness.checks.map((check) => (
            <div key={check.key} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
              <div className="font-medium text-slate-100">{check.label}</div>
              <div className="mt-1 text-sm text-slate-400">{check.status}</div>
            </div>
          ))}
        </div>
      </div>
    )
  }, [state])

  return <div className="space-y-5">{content}</div>
}
