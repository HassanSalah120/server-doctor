import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, inputClass, panelClass, selectClass, tableShellClass } from '../components/ui/styles'
import { api, type Job, type JobLog } from '../services/api'

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, { bg: string; dot: string; text: string }> = {
    queued: { bg: 'bg-slate-800', dot: 'bg-slate-400', text: 'text-slate-200' },
    running: { bg: 'bg-blue-500/15', dot: 'bg-blue-400', text: 'text-blue-200' },
    success: { bg: 'bg-green-500/15', dot: 'bg-green-400', text: 'text-green-200' },
    failed: { bg: 'bg-red-500/15', dot: 'bg-red-400', text: 'text-red-200' },
    cancelled: { bg: 'bg-orange-500/15', dot: 'bg-orange-400', text: 'text-orange-200' },
    cancel_requested: { bg: 'bg-orange-500/15', dot: 'bg-orange-400', text: 'text-orange-200' },
  }
  const s = styles[status] || { bg: 'bg-slate-800', dot: 'bg-slate-400', text: 'text-slate-200' }
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border border-slate-700 px-2.5 py-1 text-xs font-semibold ${s.bg} ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      <span className="capitalize">{status.replaceAll('_', ' ')}</span>
    </span>
  )
}

export default function JobsPage() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [expandedLogJobId, setExpandedLogJobId] = useState<number | null>(null)
  const [jobLogs, setJobLogs] = useState<Record<number, JobLog[]>>({})
  const [logError, setLogError] = useState<string | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)
  const lastLogIds = useRef<Record<number, number>>({})

  useEffect(() => {
    loadJobs()
  }, [])

  useEffect(() => {
    const hasActiveJob = jobs.some(job => ['queued', 'running', 'cancel_requested'].includes(job.status))
    if (!hasActiveJob) return
    const timer = window.setInterval(() => {
      void loadJobs(true)
    }, 5000)
    return () => window.clearInterval(timer)
  }, [jobs])

  useEffect(() => {
    if (expandedLogJobId === null) return
    let stopped = false

    async function loadLogs(silent = false) {
      if (expandedLogJobId === null) return
      const afterLogId = lastLogIds.current[expandedLogJobId] || 0
      try {
        if (!silent) setLogsLoading(true)
        setLogError(null)
        const data = await api.getJob(expandedLogJobId, afterLogId)
        if (stopped) return
        if (data.logs.length > 0) {
          lastLogIds.current[expandedLogJobId] = data.logs[data.logs.length - 1].id
        }
        setJobLogs(current => ({
          ...current,
          [expandedLogJobId]: [...(current[expandedLogJobId] || []), ...data.logs],
        }))
        setJobs(current => current.map(job => (job.id === data.job.id ? data.job : job)))
      } catch (err) {
        if (!stopped) setLogError(err instanceof Error ? err.message : 'Failed to load job logs')
      } finally {
        if (!stopped && !silent) setLogsLoading(false)
      }
    }

    void loadLogs()
    const timer = window.setInterval(() => {
      void loadLogs(true)
    }, 2000)

    return () => {
      stopped = true
      window.clearInterval(timer)
    }
  }, [expandedLogJobId])

  async function loadJobs(silent = false) {
    try {
      if (!silent) setLoading(true)
      setError(null)
      const data = await api.getJobs()
      setJobs(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load jobs')
    } finally {
      if (!silent) setLoading(false)
    }
  }

  function toggleLogs(jobId: number) {
    setLogError(null)
    setExpandedLogJobId(current => (current === jobId ? null : jobId))
  }

  function formatDate(dateStr: string | null) {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString()
  }

  const jobsSorted = useMemo(() => {
    return [...jobs].sort((a, b) => b.id - a.id)
  }, [jobs])

  const filteredJobs = useMemo(() => {
    const q = query.trim().toLowerCase()
    return jobsSorted.filter(job => {
      if (statusFilter !== 'all' && job.status !== statusFilter) return false
      if (!q) return true
      const serverLabel = job.server_name
        ? `${job.server_name}${job.server_host ? ` (${job.server_host})` : ''}`
        : `Server #${job.server_id}`
      const haystack = `${job.id} ${job.status} ${serverLabel} ${job.summary || ''}`.toLowerCase()
      return haystack.includes(q)
    })
  }, [jobsSorted, query, statusFilter])

  const stats = useMemo(() => {
    const base = {
      total: jobs.length,
      queued: 0,
      running: 0,
      success: 0,
      failed: 0,
    }
    for (const j of jobs) {
      if (j.status === 'queued') base.queued += 1
      if (j.status === 'running') base.running += 1
      if (j.status === 'success') base.success += 1
      if (j.status === 'failed') base.failed += 1
    }
    return base
  }, [jobs])

  function JobLogPanel({ jobId }: { jobId: number }) {
    const logs = jobLogs[jobId] || []
    const scrollerRef = useRef<HTMLDivElement | null>(null)
    const latestLog = logs.length > 0 ? logs[logs.length - 1] : null

    function jumpToLatest() {
      const el = scrollerRef.current
      if (!el) return
      el.scrollTop = el.scrollHeight
    }

    return (
      <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
        <div className="mb-2 flex items-center justify-between gap-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-400">Live scan log</div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={jumpToLatest}
              className="rounded border border-slate-800 bg-slate-900/50 px-2 py-1 text-xs font-semibold text-slate-300 hover:bg-slate-800"
            >
              Jump latest
            </button>
            <div className="text-xs text-slate-500">{logs.length} entries</div>
          </div>
        </div>
        {latestLog ? (
          <div className="mb-2 rounded border border-slate-800 bg-slate-900/40 px-3 py-2 text-xs text-slate-300">
            <span className="text-slate-500">Latest: </span>
            {latestLog.message}
          </div>
        ) : null}
        {logError ? (
          <div className="rounded border border-red-900 bg-red-950/30 px-3 py-2 text-xs text-red-300">{logError}</div>
        ) : null}
        {logsLoading && logs.length === 0 ? (
          <div className="text-sm text-slate-500">Loading logs...</div>
        ) : logs.length === 0 ? (
          <div className="text-sm text-slate-500">No logs yet.</div>
        ) : (
          <div ref={scrollerRef} className="max-h-80 overflow-auto rounded border border-slate-900 bg-black/20 p-3 font-mono text-xs leading-5 text-slate-300">
            {logs.map(log => (
              <div key={log.id} className="whitespace-pre-wrap break-words">
                <span className="text-slate-600">{formatDate(log.timestamp)}</span>
                <span className="text-slate-700"> | </span>
                <span>{log.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Jobs"
        subtitle="Scan and analysis job history"
        actions={
          <button
            type="button"
            onClick={() => void loadJobs()}
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Refresh
          </button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <div className={panelClass({ padded: false }) + ' p-3'}>
          <div className="text-xs text-slate-500">Total</div>
          <div className="mt-1 text-lg font-bold text-slate-100">{stats.total}</div>
        </div>
        <div className={panelClass({ padded: false }) + ' p-3'}>
          <div className="text-xs text-slate-500">Queued</div>
          <div className="mt-1 text-lg font-bold text-slate-200">{stats.queued}</div>
        </div>
        <div className={panelClass({ padded: false }) + ' p-3'}>
          <div className="text-xs text-slate-500">Running</div>
          <div className="mt-1 text-lg font-bold text-blue-300">{stats.running}</div>
        </div>
        <div className={panelClass({ padded: false }) + ' p-3'}>
          <div className="text-xs text-slate-500">Success</div>
          <div className="mt-1 text-lg font-bold text-green-300">{stats.success}</div>
        </div>
        <div className={panelClass({ padded: false }) + ' p-3'}>
          <div className="text-xs text-slate-500">Failed</div>
          <div className="mt-1 text-lg font-bold text-red-300">{stats.failed}</div>
        </div>
      </div>

      <div className={panelClass({ padded: false }) + ' p-3'}>
        <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
          <div className="flex-1">
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search by job id, server, status, or summary"
              className={inputClass()}
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className={selectClass()}
            >
              <option value="all">All statuses</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="success">Success</option>
              <option value="failed">Failed</option>
              <option value="cancel_requested">Cancel requested</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
        </div>
        <div className="mt-2 text-xs text-slate-500">
          Showing {filteredJobs.length}/{jobs.length}
        </div>
      </div>

      {loading && (
        <div className={panelClass() + ' p-6'}>
          <div className="text-slate-400">Loading jobs...</div>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-400">
          Error: {error}
        </div>
      )}

      {!loading && !error && jobs.length === 0 ? (
        <div className={panelClass() + ' p-8 text-center'}>
          <p className="text-slate-400">No jobs yet.</p>
          <p className="mt-1 text-sm text-slate-500">Run a scan from the Servers or Daemon page.</p>
        </div>
      ) : null}

      {!loading && !error && jobs.length > 0 && filteredJobs.length === 0 ? (
        <div className={panelClass() + ' p-6'}>
          <div className="text-slate-300 font-medium">No jobs match your filters.</div>
          <div className="mt-1 text-sm text-slate-500">Try clearing the search query or selecting “All statuses”.</div>
        </div>
      ) : null}

      {!loading && !error && filteredJobs.length > 0 ? (
        <>
          <div className="space-y-3 lg:hidden">
            {filteredJobs.map(job => {
              const canViewReport = job.status === 'success' || job.status === 'failed'
              const serverLabel = job.server_name
                ? `${job.server_name}${job.server_host ? ` (${job.server_host})` : ''}`
                : `Server #${job.server_id}`
              const progressValue = typeof job.progress === 'number' ? job.progress : null
              return (
                <div key={job.id} className={panelClass() + ' p-4'}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-mono text-xs text-slate-500">Job #{job.id}</div>
                      <div className="mt-1 font-semibold text-slate-100">{serverLabel}</div>
                      {job.summary && <div className="mt-1 text-xs text-slate-500">{job.summary}</div>}
                      {job.phases && job.phases.length > 0 && (
                        <div className="mt-2 text-xs text-slate-500">
                          {job.phases.find((phase) => phase.status === 'running')?.label || job.phases.at(-1)?.label}
                        </div>
                      )}
                    </div>
                    <StatusBadge status={job.status} />
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <div className="text-xs text-slate-500">Score</div>
                      <div className="mt-0.5 font-semibold">
                        {job.score !== null ? (
                          <span className={job.score >= 80 ? 'text-green-400' : job.score >= 50 ? 'text-yellow-400' : 'text-red-400'}>
                            {job.score}
                          </span>
                        ) : (
                          <span className="text-slate-500">-</span>
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500">Progress</div>
                      <div className="mt-1">
                        {progressValue === null ? (
                          <span className="text-slate-500">-</span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-24 overflow-hidden rounded bg-slate-800">
                              <div
                                className="h-2 bg-sky-600"
                                style={{ width: `${Math.max(0, Math.min(100, progressValue))}%` }}
                              />
                            </div>
                            <span className="text-xs text-slate-400">{progressValue}%</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500">Created</div>
                      <div className="mt-0.5 text-xs text-slate-300">{formatDate(job.created_at)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500">Finished</div>
                      <div className="mt-0.5 text-xs text-slate-300">{formatDate(job.finished_at)}</div>
                    </div>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => toggleLogs(job.id)}
                      className={buttonClass({ variant: 'default', size: 'md' })}
                    >
                      {expandedLogJobId === job.id ? 'Hide Logs' : 'View Logs'}
                    </button>
                    {canViewReport ? (
                      <Link
                        to={`/reports/${job.id}`}
                        className={buttonClass({ variant: 'default', size: 'md' })}
                      >
                        View Report
                      </Link>
                    ) : (
                      <button
                        type="button"
                        disabled
                        className={buttonClass({ variant: 'default', size: 'md' }) + ' text-slate-400 opacity-60'}
                        title="Report becomes available when the job finishes"
                      >
                        View Report
                      </button>
                    )}
                  </div>
                  {expandedLogJobId === job.id ? <JobLogPanel jobId={job.id} /> : null}
                </div>
              )
            })}
          </div>

          <div className={'hidden lg:block ' + tableShellClass()}>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-slate-800/50 text-slate-400">
                  <tr>
                    <th className="px-4 py-3 text-left">ID</th>
                    <th className="px-4 py-3 text-left">Server</th>
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left">Score</th>
                    <th className="px-4 py-3 text-left">Progress</th>
                    <th className="px-4 py-3 text-left">Created</th>
                    <th className="px-4 py-3 text-left">Finished</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {filteredJobs.map((job, idx) => {
                    const canViewReport = job.status === 'success' || job.status === 'failed'
                    const serverLabel = job.server_name
                      ? `${job.server_name}${job.server_host ? ` (${job.server_host})` : ''}`
                      : `Server #${job.server_id}`
                    const progressValue = typeof job.progress === 'number' ? job.progress : null
                    return (
                      <Fragment key={job.id}>
                        <tr className={`${idx % 2 === 0 ? 'bg-transparent' : 'bg-slate-950/10'} hover:bg-slate-800/30`}>
                          <td className="px-4 py-3 font-mono text-xs">#{job.id}</td>
                          <td className="px-4 py-3">
                            <div className="font-medium text-slate-100">{serverLabel}</div>
                            {job.summary && <div className="mt-0.5 text-xs text-slate-500">{job.summary}</div>}
                            {job.phases && job.phases.length > 0 && (
                              <div className="mt-0.5 text-xs text-slate-500">
                                {job.phases.find((phase) => phase.status === 'running')?.label || job.phases.at(-1)?.label}
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <StatusBadge status={job.status} />
                          </td>
                          <td className="px-4 py-3">
                            {job.score !== null ? (
                              <span className={job.score >= 80 ? 'text-green-400' : job.score >= 50 ? 'text-yellow-400' : 'text-red-400'}>
                                {job.score}
                              </span>
                            ) : (
                              <span className="text-slate-500">-</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            {progressValue === null ? (
                              <span className="text-slate-500">-</span>
                            ) : (
                              <div className="flex items-center gap-2">
                                <div className="h-2 w-28 overflow-hidden rounded bg-slate-800">
                                  <div
                                    className="h-2 bg-sky-600"
                                    style={{ width: `${Math.max(0, Math.min(100, progressValue))}%` }}
                                  />
                                </div>
                                <span className="text-xs text-slate-400">{progressValue}%</span>
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-400">{formatDate(job.created_at)}</td>
                          <td className="px-4 py-3 text-slate-400">{formatDate(job.finished_at)}</td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                type="button"
                                onClick={() => toggleLogs(job.id)}
                                className={buttonClass({ variant: 'default', size: 'md' })}
                              >
                                {expandedLogJobId === job.id ? 'Hide Logs' : 'Logs'}
                              </button>
                              {canViewReport ? (
                                <Link
                                  to={`/reports/${job.id}`}
                                  className={buttonClass({ variant: 'default', size: 'md' })}
                                >
                                  View Report
                                </Link>
                              ) : (
                                <button
                                  type="button"
                                  disabled
                                  className={buttonClass({ variant: 'default', size: 'md' }) + ' text-slate-400 opacity-60'}
                                  title="Report becomes available when the job finishes"
                                >
                                  View Report
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                        {expandedLogJobId === job.id ? (
                          <tr key={`${job.id}-logs`} className={idx % 2 === 0 ? 'bg-transparent' : 'bg-slate-950/10'}>
                            <td colSpan={8} className="px-4 pb-4 pt-0">
                              <JobLogPanel jobId={job.id} />
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </div>
  )
}
