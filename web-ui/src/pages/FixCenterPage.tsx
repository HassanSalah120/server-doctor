import { useEffect, useMemo, useState } from 'react'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, panelClass } from '../components/ui/styles'
import { api, type FixPlan, type Job } from '../services/api'

type AsyncState<T> =
  | { status: 'loading' }
  | { status: 'error'; error: string }
  | { status: 'empty' }
  | { status: 'ready'; data: T }

export default function FixCenterPage() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [selectedJobId, setSelectedJobId] = useState<number | null>(null)
  const [state, setState] = useState<AsyncState<FixPlan[]>>({ status: 'loading' })

  useEffect(() => {
    api.getJobs()
      .then((items) => {
        setJobs(items)
        const latest = items.find((job) => job.status === 'success' || job.status === 'failed') || items[0]
        setSelectedJobId(latest?.id ?? null)
      })
      .catch((err) => setState({ status: 'error', error: err instanceof Error ? err.message : 'Failed to load jobs' }))
  }, [])

  useEffect(() => {
    if (!selectedJobId) {
      setState({ status: 'empty' })
      return
    }
    setState({ status: 'loading' })
    api.previewFixes(selectedJobId)
      .then((data) => setState(data.plans.length ? { status: 'ready', data: data.plans } : { status: 'empty' }))
      .catch((err) => setState({ status: 'error', error: err instanceof Error ? err.message : 'Failed to load fix plans' }))
  }, [selectedJobId])

  const selectedJob = useMemo(
    () => jobs.find((job) => job.id === selectedJobId),
    [jobs, selectedJobId],
  )

  return (
    <div className="space-y-4">
      <PageHeader title="Fix Center" subtitle="Preview safe remediation plans before touching a server" />

      <div className={panelClass() + ' flex flex-col gap-3 sm:flex-row sm:items-center'}>
        <div className="text-sm text-slate-300">Scan job</div>
        <select
          className="min-h-11 rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
          value={selectedJobId ?? ''}
          onChange={(event) => setSelectedJobId(Number(event.target.value))}
        >
          {jobs.map((job) => (
            <option key={job.id} value={job.id}>
              #{job.id} {job.server_name || `Server ${job.server_id}`} {job.status}
            </option>
          ))}
        </select>
        {selectedJob && <div className="text-xs text-slate-500">{selectedJob.summary || 'No summary available'}</div>}
      </div>

      {state.status === 'loading' && <div className={panelClass() + ' p-6 text-slate-400'}>Loading fix plans...</div>}
      {state.status === 'error' && <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-300">{state.error}</div>}
      {state.status === 'empty' && <div className={panelClass() + ' p-6 text-slate-400'}>No fix plans available.</div>}
      {state.status === 'ready' && (
        <div className="space-y-3">
          {state.data.map((plan) => (
            <div key={plan.finding_id} className={panelClass() + ' space-y-3'}>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <div className="font-mono text-xs text-sky-300">{plan.rule_id}</div>
                  <div className="mt-1 font-semibold text-slate-100">{plan.summary}</div>
                </div>
                <span className="rounded border border-slate-700 px-2 py-1 text-xs uppercase text-slate-300">
                  {plan.risk}
                </span>
              </div>
              {plan.warnings.length > 0 && (
                <div className="rounded border border-yellow-800 bg-yellow-950/20 p-3 text-sm text-yellow-100">
                  {plan.warnings.join(' ')}
                </div>
              )}
              <CommandList title="Backup" commands={plan.backup_commands} />
              <CommandList title="Suggested change" commands={plan.apply_commands} />
              <CommandList title="Validate" commands={plan.validate_commands} />
              <CommandList title="Rollback" commands={plan.rollback_commands} />
              <button type="button" disabled className={buttonClass({ variant: 'default', size: 'md' }) + ' min-h-11 opacity-60'}>
                Preview only
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function CommandList({ title, commands }: { title: string; commands: FixPlan['backup_commands'] }) {
  if (!commands.length) return null
  return (
    <div>
      <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</div>
      <div className="space-y-1">
        {commands.map((command) => (
          <code key={`${command.label}-${command.command}`} className="block rounded bg-slate-950 p-2 text-xs text-slate-200">
            {command.command}
          </code>
        ))}
      </div>
    </div>
  )
}
