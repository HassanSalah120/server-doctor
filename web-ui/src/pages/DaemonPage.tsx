import { useEffect, useState } from 'react'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, inputClass, panelClass, tableShellClass } from '../components/ui/styles'
import { api, type DaemonHistoryEntry, type DaemonStatus, type Server } from '../services/api'

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-medium ${running ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-300'}`}
    >
      {running ? '● Running' : '○ Stopped'}
    </span>
  )
}

export default function DaemonPage() {
  const [status, setStatus] = useState<DaemonStatus | null>(null)
  const [history, setHistory] = useState<DaemonHistoryEntry[]>([])
  const [servers, setServers] = useState<Server[]>([])
  const [scanInterval, setScanInterval] = useState(3600)
  const [selectedServers, setSelectedServers] = useState<number[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [])

  useEffect(() => {
    if (!status?.running) return
    const intervalId = setInterval(loadData, 5000)
    return () => clearInterval(intervalId)
  }, [status?.running])

  async function loadData() {
    try {
      const [statusData, serversData, historyData] = await Promise.all([
        api.getDaemonStatus(),
        api.getServers(),
        api.getDaemonHistory(25),
      ])
      setStatus(statusData)
      setHistory(historyData)
      setServers(serversData)
      if (Array.isArray(statusData.servers) && statusData.servers.length > 0) {
        setSelectedServers(statusData.servers)
      } else if (statusData.running) {
        setSelectedServers(serversData.map(s => s.id))
      }
      if (statusData.interval) {
        setScanInterval(statusData.interval)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load daemon status')
    } finally {
      setLoading(false)
    }
  }

  function dismissMessages() {
    setError(null)
    setMessage(null)
  }

  async function handleStart() {
    try {
      setActionLoading(true)
      await api.startDaemon(scanInterval, selectedServers.length > 0 ? selectedServers : servers.map(s => s.id))
      setMessage('Daemon started successfully')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start daemon')
    } finally {
      setActionLoading(false)
    }
  }

  async function handleStop() {
    try {
      setActionLoading(true)
      await api.stopDaemon()
      setMessage('Daemon stopped successfully')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop daemon')
    } finally {
      setActionLoading(false)
    }
  }

  async function handleScanNow() {
    try {
      setActionLoading(true)
      await api.triggerScan()
      setMessage('Scan triggered')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trigger scan')
    } finally {
      setActionLoading(false)
    }
  }

  function toggleServer(id: number) {
    setSelectedServers(prev =>
      prev.includes(id) ? prev.filter(sid => sid !== id) : [...prev, id]
    )
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Daemon"
        subtitle="Background monitoring and scheduled scans"
        actions={
          <button
            type="button"
            onClick={() => {
              dismissMessages()
              loadData()
            }}
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Refresh
          </button>
        }
      />

      {message && (
        <div className="rounded-lg border border-green-800 bg-green-950/30 p-3 text-green-400">
          <div className="flex items-start justify-between gap-3">
            <div>{message}</div>
            <button type="button" onClick={() => setMessage(null)} className="text-green-300/80 hover:text-green-200">
              Dismiss
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-red-400">
          <div className="flex items-start justify-between gap-3">
            <div>{error}</div>
            <button type="button" onClick={() => setError(null)} className="text-red-300/80 hover:text-red-200">
              Dismiss
            </button>
          </div>
        </div>
      )}

      {!status?.running && (
        <div className={panelClass()}>
          <div className="text-sm text-slate-200">Daemon is not running</div>
          <div className="mt-1 text-sm text-slate-400">
            Start the daemon to enable scheduled scans. You can also trigger scans manually from the Servers page.
          </div>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className={panelClass()}>
          <h3 className="font-medium">Status</h3>
          <div className="mt-4 flex items-center gap-4">
            <StatusBadge running={status?.running ?? false} />
            {status?.pid && <span className="text-sm text-slate-400">PID: {status.pid}</span>}
          </div>
          <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-slate-400">Scan Interval</span>
              <p className="font-medium">{status?.interval ?? 3600}s</p>
            </div>
            <div>
              <span className="text-slate-400">Total Scans</span>
              <p className="font-medium">{status?.scan_count ?? 0}</p>
            </div>
            <div>
              <span className="text-slate-400">Last Scan</span>
              <p className="font-medium">{status?.last_scan ? new Date(status.last_scan).toLocaleString() : '—'}</p>
            </div>
            <div>
              <span className="text-slate-400">Next Scan</span>
              <p className="font-medium">{status?.next_scan ? new Date(status.next_scan).toLocaleString() : '—'}</p>
            </div>
            <div>
              <span className="text-slate-400">Started At</span>
              <p className="font-medium">{status?.started_at ? new Date(status.started_at).toLocaleString() : '—'}</p>
            </div>
            <div>
              <span className="text-slate-400">Errors</span>
              <p className="font-medium">{status?.error_count ?? 0}</p>
            </div>
          </div>
        </div>

        <div className={panelClass()}>
          <h3 className="font-medium">Actions</h3>
          <div className="mt-4 space-y-3">
            {status?.running ? (
              <>
                <button
                  onClick={handleStop}
                  disabled={actionLoading}
                  className={buttonClass({ variant: 'danger', size: 'md' }) + ' w-full'}
                >
                  {actionLoading ? 'Stopping...' : 'Stop Daemon'}
                </button>

                <div className={panelClass()}>
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-slate-200">Manual scan</div>
                      <div className="mt-0.5 text-xs text-slate-500">Triggers a scan cycle for monitored servers.</div>
                    </div>
                    <button
                      onClick={handleScanNow}
                      disabled={actionLoading}
                      className={buttonClass({ variant: 'primary', size: 'md' })}
                    >
                      {actionLoading ? 'Triggering...' : 'Scan Now'}
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <button
                onClick={handleStart}
                disabled={actionLoading || servers.length === 0}
                className={buttonClass({ variant: 'primary', size: 'md' }) + ' w-full'}
              >
                {actionLoading ? 'Starting...' : 'Start Daemon'}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className={panelClass()}>
        <h3 className="font-medium">Configuration</h3>
        <div className="mt-4 space-y-4">
          <div>
            <label className="block text-sm text-slate-400">Scan Interval (seconds)</label>

            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setScanInterval(900)}
                disabled={status?.running}
                className={buttonClass({ variant: 'default', size: 'sm' })}
              >
                15m
              </button>
              <button
                type="button"
                onClick={() => setScanInterval(3600)}
                disabled={status?.running}
                className={buttonClass({ variant: 'default', size: 'sm' })}
              >
                1h
              </button>
              <button
                type="button"
                onClick={() => setScanInterval(21600)}
                disabled={status?.running}
                className={buttonClass({ variant: 'default', size: 'sm' })}
              >
                6h
              </button>
              <button
                type="button"
                onClick={() => setScanInterval(86400)}
                disabled={status?.running}
                className={buttonClass({ variant: 'default', size: 'sm' })}
              >
                24h
              </button>
            </div>

            <input
              type="number"
              value={scanInterval}
              onChange={e => setScanInterval(parseInt(e.target.value) || 3600)}
              disabled={status?.running}
              className={inputClass() + ' mt-1 disabled:opacity-50'}
              placeholder="3600"
            />
            {status?.running && <div className="mt-1 text-xs text-slate-500">Stop the daemon to change configuration.</div>}
          </div>

          <div>
            <label className="block text-sm text-slate-400">Monitored Servers</label>
            <div className="mt-2 space-y-2">
              {servers.length === 0 ? (
                <p className="text-sm text-slate-500">No servers configured. Add servers first.</p>
              ) : (
                servers.map(server => (
                  <label key={server.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selectedServers.includes(server.id)}
                      onChange={() => toggleServer(server.id)}
                      disabled={status?.running}
                      className="rounded border-slate-600 bg-slate-700"
                    />
                    <span>{server.name}</span>
                    <span className="text-slate-500">({server.host})</span>
                  </label>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      <div className={panelClass()}>
        <h3 className="font-medium">Recent Activity</h3>
        {history.length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">No daemon activity recorded yet.</p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <div className={tableShellClass()}>
              <table className="w-full text-sm">
                <thead className="bg-slate-800/50 text-slate-400">
                <tr>
                  <th className="px-3 py-2 text-left">Time</th>
                  <th className="px-3 py-2 text-left">Server</th>
                  <th className="px-3 py-2 text-left">Status</th>
                  <th className="px-3 py-2 text-left">Summary</th>
                </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                {history.map((entry, idx) => (
                  <tr key={`${entry.timestamp}-${entry.server}-${idx}`} className="hover:bg-slate-800/30">
                    <td className="px-3 py-2 text-slate-300">{new Date(entry.timestamp).toLocaleString()}</td>
                    <td className="px-3 py-2 text-slate-200">{entry.server}</td>
                    <td className={`px-3 py-2 ${entry.status === 'success' ? 'text-green-400' : 'text-red-400'}`}>{entry.status}</td>
                    <td className="px-3 py-2 text-slate-400">
                      {entry.message ||
                        (entry.status === 'success'
                          ? `${entry.new_findings ?? 0} new, ${entry.resolved_findings ?? 0} resolved, ${entry.findings_total ?? 0} total`
                          : '—')}
                    </td>
                  </tr>
                ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
