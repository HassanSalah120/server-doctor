import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, inputClass, panelClass } from '../components/ui/styles'
import { api, type Server, type Job, type DaemonStatus } from '../services/api'

function StatCard({ label, value, color = 'text-slate-100' }: { label: string; value: string | number; color?: string }) {
  return (
    <div className={panelClass()}>
      <div className="text-sm text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  )
}

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${running ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
      {running ? '● Running' : '○ Stopped'}
    </span>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [servers, setServers] = useState<Server[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [daemonStatus, setDaemonStatus] = useState<DaemonStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [scanServerId, setScanServerId] = useState<number | null>(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [scanOptions, setScanOptions] = useState({
    repo_scan_paths: '',
  })
  const [showScanOptions, setShowScanOptions] = useState(false)

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true)
        const [serversData, jobsData, daemonData] = await Promise.all([
          api.getServers(),
          api.getJobs(),
          api.getDaemonStatus(),
        ])
        setServers(serversData)
        setJobs(jobsData)
        setDaemonStatus(daemonData)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load data')
      } finally {
        setLoading(false)
      }
    }
    loadData()
  }, [])

  async function refresh() {
    try {
      setError(null)
      setBanner(null)
      setLoading(true)
      const [serversData, jobsData, daemonData] = await Promise.all([
        api.getServers(),
        api.getJobs(),
        api.getDaemonStatus(),
      ])
      setServers(serversData)
      setJobs(jobsData)
      setDaemonStatus(daemonData)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }

  const runningJobs = jobs.filter(j => j.status === 'running').length
  const completedJobs = jobs.filter(j => j.status === 'success').length
  const failedJobs = jobs.filter(j => j.status === 'failed').length

  const latestJob = useMemo(() => {
    if (jobs.length === 0) return null
    return [...jobs].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0]
  }, [jobs])

  async function handleStartScan() {
    if (!scanServerId) {
      setBanner({ type: 'error', message: 'Select a server to scan.' })
      return
    }
    try {
      setBanner(null)
      setScanLoading(true)
      const res = await api.startScan(scanServerId, {
        repo_scan_paths: scanOptions.repo_scan_paths || undefined,
      })
      setBanner({ type: 'success', message: `Scan started. Job #${res.job_id} queued. DevOps checks are included by default.` })
    } catch (err) {
      setBanner({ type: 'error', message: err instanceof Error ? err.message : 'Failed to start scan' })
    } finally {
      setScanLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-400">
        <div className="flex items-start justify-between gap-3">
          <div>Error: {error}</div>
          <button type="button" onClick={() => setError(null)} className="text-red-300/80 hover:text-red-200">
            Dismiss
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        subtitle="Overview of your infrastructure and monitoring status"
        actions={
          <button
            type="button"
            onClick={refresh}
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Refresh
          </button>
        }
      />

      {banner && (
        <div
          className={`rounded-lg border p-4 ${
            banner.type === 'success'
              ? 'border-green-800 bg-green-950/30 text-green-400'
              : 'border-red-800 bg-red-950/30 text-red-400'
          }`}
        >
          <div className="flex items-center justify-between gap-4">
            <div>{banner.message}</div>
            <div className="flex items-center gap-2">
              {banner.type === 'success' && (
                <button
                  onClick={() => navigate('/jobs')}
                  className="rounded-md bg-slate-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-600"
                >
                  View Jobs
                </button>
              )}
              <button
                type="button"
                onClick={() => setBanner(null)}
                className={
                  banner.type === 'success'
                    ? 'text-green-300/80 hover:text-green-200'
                    : 'text-red-300/80 hover:text-red-200'
                }
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Servers" value={servers.length} />
        <StatCard label="Total Jobs" value={jobs.length} />
        <StatCard label="Running Jobs" value={runningJobs} color="text-blue-400" />
        <StatCard
          label="Daemon Status"
          value={daemonStatus?.running ? 'Running' : 'Stopped'}
          color={daemonStatus?.running ? 'text-green-400' : 'text-slate-400'}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <div className={panelClass()}>
          <h3 className="font-medium">Job Summary</h3>
          <div className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">Completed</span>
              <span className="text-green-400">{completedJobs}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Failed</span>
              <span className="text-red-400">{failedJobs}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Queued</span>
              <span className="text-slate-300">{jobs.filter(j => j.status === 'queued').length}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Running</span>
              <span className="text-blue-400">{runningJobs}</span>
            </div>
          </div>
        </div>

        <div className={panelClass()}>
          <h3 className="font-medium">Quick Scan</h3>
          <p className="mt-1 text-sm text-slate-400">Start an on-demand scan for a server.</p>

          <div className="mt-4 space-y-3">
            <select
              value={scanServerId ?? ''}
              onChange={e => setScanServerId(e.target.value ? Number(e.target.value) : null)}
              className={inputClass()}
            >
              <option value="">Select server...</option>
              {servers.map(s => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.host})
                </option>
              ))}
            </select>

            <button
              onClick={() => setShowScanOptions(!showScanOptions)}
              className={buttonClass({ variant: 'default', size: 'md' }) + ' w-full'}
            >
              {showScanOptions ? 'Hide Options' : 'Scan Options'}
            </button>

            {showScanOptions && (
              <div className={panelClass() + ' space-y-3'}>
                <div className="text-sm text-slate-300">
                  DevOps checks are always enabled for every scan.
                </div>
                <div className="mt-2">
                  <label className="block text-xs text-slate-400">Repo paths (optional, comma-separated)</label>
                  <input
                    type="text"
                    value={scanOptions.repo_scan_paths}
                    onChange={e => setScanOptions({ ...scanOptions, repo_scan_paths: e.target.value })}
                    placeholder="e.g. /var/www/, /home/kingof30/ChatDuelForm"
                    className={inputClass() + ' mt-1 text-xs'}
                  />
                  <p className="mt-1 text-xs text-slate-500">Leave empty to auto-discover repo paths from nginx roots, Docker mounts, and running app paths.</p>
                </div>
              </div>
            )}

            <button
              onClick={handleStartScan}
              disabled={scanLoading || servers.length === 0}
              className={buttonClass({ variant: 'primary', size: 'md' }) + ' w-full'}
            >
              {scanLoading ? 'Starting...' : 'Start Scan'}
            </button>

            {servers.length === 0 && (
              <div className="rounded-md border border-slate-800 bg-slate-950/30 p-3 text-xs text-slate-500">
                Add a server first to enable Quick Scan.
              </div>
            )}

            {latestJob && (
              <div className="text-xs text-slate-400">
                Latest job: #{latestJob.id} ({latestJob.status})
              </div>
            )}
          </div>
        </div>

        <div className={panelClass()}>
          <h3 className="font-medium">Daemon Monitoring</h3>
          <div className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">Status</span>
              <StatusBadge running={daemonStatus?.running ?? false} />
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Interval</span>
              <span>{daemonStatus?.interval ?? 3600}s</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Monitored Servers</span>
              <span>{daemonStatus?.servers?.length ?? 0}</span>
            </div>
          </div>
        </div>

        <div className={panelClass()}>
          <h3 className="font-medium">Quick Links</h3>
          <div className="mt-3 space-y-2">
            <Link to="/servers" className={buttonClass({ variant: 'default', size: 'md' }) + ' w-full justify-start'}>
              Manage Servers
            </Link>
            <Link to="/jobs" className={buttonClass({ variant: 'default', size: 'md' }) + ' w-full justify-start'}>
              View Jobs
            </Link>
            <Link to="/settings/daemon" className={buttonClass({ variant: 'default', size: 'md' }) + ' w-full justify-start'}>
              Configure Daemon
            </Link>
            <Link
              to="/settings/integrations"
              className={buttonClass({ variant: 'default', size: 'md' }) + ' w-full justify-start'}
            >
              Integrations
            </Link>
          </div>
        </div>
      </div>

      {servers.length === 0 && (
        <div className={panelClass() + ' p-6 text-center'}>
          <p className="text-slate-400">No servers configured yet.</p>
          <div className="mt-3 flex justify-center">
            <Link to="/servers" className={buttonClass({ variant: 'primary', size: 'md' })}>
              Add your first server
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
