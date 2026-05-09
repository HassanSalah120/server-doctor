import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, inputClass, panelClass, tableShellClass } from '../components/ui/styles'
import { api, type Server } from '../services/api'

export default function ServersPage() {
  const navigate = useNavigate()
  const [servers, setServers] = useState<Server[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [scanningServerId, setScanningServerId] = useState<number | null>(null)
  const [scanOptions, setScanOptions] = useState({
    repo_scan_paths: '',
    one_time_password: '',
    one_time_key_passphrase: '',
  })
  const [showScanOptions, setShowScanOptions] = useState(false)
  const [showAddForm, setShowAddForm] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    host: '',
    port: 22,
    username: 'root',
    password: '',
    key_path: '',
    key_passphrase: '',
    tags: '',
  })

  useEffect(() => {
    loadServers()
  }, [])

  async function loadServers() {
    try {
      setLoading(true)
      const data = await api.getServers()
      setServers(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load servers')
    } finally {
      setLoading(false)
    }
  }

  async function refresh() {
    setBanner(null)
    setError(null)
    await loadServers()
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await api.createServer(formData)
      setShowAddForm(false)
      setFormData({ name: '', host: '', port: 22, username: 'root', password: '', key_path: '', key_passphrase: '', tags: '' })
      loadServers()
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to create server')
    }
  }

  async function handleDelete(id: number) {
    if (!confirm('Are you sure you want to delete this server?')) return
    try {
      await api.deleteServer(id)
      loadServers()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to delete server'
      if (message.includes('existing scan jobs')) {
        const cascade = confirm(
          'This server has scan history. Delete the server and its associated scan jobs?',
        )
        if (!cascade) return
        try {
          await api.deleteServer(id, true)
          loadServers()
          return
        } catch (cascadeErr) {
          alert(cascadeErr instanceof Error ? cascadeErr.message : 'Failed to delete server')
          return
        }
      }
      alert(message)
    }
  }

  async function handleScan(serverId: number) {
    try {
      setBanner(null)
      setScanningServerId(serverId)
      const res = await api.startScan(serverId, {
        repo_scan_paths: scanOptions.repo_scan_paths || undefined,
        one_time_password: scanOptions.one_time_password || undefined,
        one_time_key_passphrase: scanOptions.one_time_key_passphrase || undefined,
      })
      setBanner({ type: 'success', message: `Scan started. Job #${res.job_id} queued. DevOps checks are included by default.` })
    } catch (err) {
      setBanner({ type: 'error', message: err instanceof Error ? err.message : 'Failed to start scan' })
    } finally {
      setScanningServerId(null)
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
    <div className="space-y-4">
      <PageHeader
        title="Servers"
        subtitle="Manage your infrastructure servers"
        actions={
          <>
            <button
              type="button"
              onClick={refresh}
              className={buttonClass({ variant: 'default', size: 'sm' })}
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={() => setShowAddForm(!showAddForm)}
              className={buttonClass({ variant: 'primary', size: 'sm' })}
            >
              {showAddForm ? 'Cancel' : 'Add Server'}
            </button>
          </>
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

      {showAddForm && (
        <form onSubmit={handleSubmit} className={panelClass() + ' space-y-3'}>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="block text-sm text-slate-400">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="Production Server"
                required
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Host</label>
              <input
                type="text"
                value={formData.host}
                onChange={e => setFormData({ ...formData, host: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="192.168.1.100 or server.example.com"
                required
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Port</label>
              <input
                type="number"
                value={formData.port}
                onChange={e => setFormData({ ...formData, port: parseInt(e.target.value) })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Username</label>
              <input
                type="text"
                value={formData.username}
                onChange={e => setFormData({ ...formData, username: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SSH/Sudo Password (optional)</label>
              <input
                type="password"
                value={formData.password}
                onChange={e => setFormData({ ...formData, password: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="Used for password login or sudo"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SSH Key Path (optional)</label>
              <input
                type="text"
                value={formData.key_path}
                onChange={e => setFormData({ ...formData, key_path: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="~/.ssh/id_rsa"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SSH Key Passphrase (optional)</label>
              <input
                type="password"
                value={formData.key_passphrase}
                onChange={e => setFormData({ ...formData, key_passphrase: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="Stored in OS keyring"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm text-slate-400">Tags (comma separated)</label>
              <input
                type="text"
                value={formData.tags}
                onChange={e => setFormData({ ...formData, tags: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="production, nginx, web"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className={buttonClass({ variant: 'primary', size: 'md' })}
            >
              Create Server
            </button>
          </div>
        </form>
      )}

      {servers.length === 0 ? (
        <div className={panelClass() + ' p-8 text-center'}>
          <p className="text-slate-400">No servers configured yet.</p>
          <button
            onClick={() => setShowAddForm(true)}
            className={buttonClass({ variant: 'primary', size: 'md' }) + ' mt-3'}
          >
            Add your first server
          </button>
        </div>
      ) : (
        <div className={tableShellClass()}>
          <table className="w-full text-sm">
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3 text-left">Host</th>
                <th className="px-4 py-3 text-left">Username</th>
                <th className="px-4 py-3 text-left">Tags</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {servers.map(server => (
                <tr key={server.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-medium">{server.name}</td>
                  <td className="px-4 py-3 text-slate-400">{server.host}:{server.port}</td>
                  <td className="px-4 py-3 text-slate-400">{server.username}</td>
                  <td className="px-4 py-3">
                    {server.tags && (
                      <span className="inline-flex gap-1">
                        {server.tags.split(',').map((tag, i) => (
                          <span key={i} className="rounded bg-slate-700 px-2 py-0.5 text-xs">{tag.trim()}</span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-3">
                      <button
                        onClick={() => setShowScanOptions(!showScanOptions)}
                        className={buttonClass({ variant: 'default', size: 'sm' })}
                        title="Scan options"
                      >
                        Options
                      </button>
                      <button
                        onClick={() => handleScan(server.id)}
                        disabled={scanningServerId === server.id}
                        className={buttonClass({ variant: 'default', size: 'sm' })}
                      >
                        {scanningServerId === server.id ? 'Starting...' : 'Scan now'}
                      </button>
                      <button
                        onClick={() => handleDelete(server.id)}
                        className={buttonClass({ variant: 'default', size: 'sm' }) + ' text-red-300'}
                      >
                        Delete
                      </button>
                    </div>
                    {showScanOptions && (
                      <div className={panelClass() + ' mt-3 text-left'}>
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
                        <div className="mt-2">
                          <label className="block text-xs text-slate-400">One-time sudo password (optional)</label>
                          <input
                            type="password"
                            value={scanOptions.one_time_password}
                            onChange={e => setScanOptions({ ...scanOptions, one_time_password: e.target.value })}
                            placeholder="Used for this scan only"
                            className={inputClass() + ' mt-1 text-xs'}
                          />
                        </div>
                        <div className="mt-2">
                          <label className="block text-xs text-slate-400">One-time key passphrase (optional)</label>
                          <input
                            type="password"
                            value={scanOptions.one_time_key_passphrase}
                            onChange={e => setScanOptions({ ...scanOptions, one_time_key_passphrase: e.target.value })}
                            placeholder="Used for this scan only"
                            className={inputClass() + ' mt-1 text-xs'}
                          />
                        </div>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
