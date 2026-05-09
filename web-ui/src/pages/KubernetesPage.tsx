import { useState } from 'react'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, inputClass, panelClass, tableShellClass } from '../components/ui/styles'

interface K8sScanResult {
  findings_count: number
  ingresses: Array<{
    name: string
    namespace: string
    host: string
    tls_configured: boolean
    issues: string[]
  }>
  certificates: Array<{
    name: string
    namespace: string
    status: string
    expiry: string
  }>
  findings: Array<{
    id: string
    severity: string
    condition: string
    cause: string
    treatment: string
  }>
}

const API_BASE = '/api'

export default function KubernetesPage() {
  const [kubeconfig, setKubeconfig] = useState('')
  const [context, setContext] = useState('')
  const [namespace, setNamespace] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<K8sScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  function reset() {
    setError(null)
    setResult(null)
  }

  async function handleScan() {
    try {
      setLoading(true)
      setError(null)
      const response = await fetch(`${API_BASE}/k8s/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kubeconfig: kubeconfig || null,
          context: context || null,
          namespace: namespace || null,
        }),
      })
      if (!response.ok) {
        const err = await response.json()
        throw new Error(err.detail || 'Scan failed')
      }
      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  function getSeverityColor(severity: string) {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-red-400'
      case 'high':
        return 'text-orange-400'
      case 'medium':
        return 'text-yellow-400'
      default:
        return 'text-slate-400'
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Kubernetes"
        subtitle="Analyze K8s ingress, certificates, and nginx-ingress"
        actions={
          <button
            type="button"
            onClick={reset}
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Clear
          </button>
        }
      />

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

      <div className={panelClass() + ' space-y-4'}>
        <h3 className="font-medium">Scan Configuration</h3>

        <div className="grid gap-4 md:grid-cols-3">
          <div>
            <label className="block text-sm text-slate-400">Kubeconfig Path (optional)</label>
            <input
              type="text"
              value={kubeconfig}
              onChange={e => setKubeconfig(e.target.value)}
              className={inputClass() + ' mt-1'}
              placeholder="~/.kube/config"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400">Context (optional)</label>
            <input
              type="text"
              value={context}
              onChange={e => setContext(e.target.value)}
              className={inputClass() + ' mt-1'}
              placeholder="default"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400">Namespace (optional)</label>
            <input
              type="text"
              value={namespace}
              onChange={e => setNamespace(e.target.value)}
              className={inputClass() + ' mt-1'}
              placeholder="all-namespaces"
            />
          </div>
        </div>

        <button
          onClick={handleScan}
          disabled={loading}
          className={buttonClass({ variant: 'primary', size: 'md' })}
        >
          {loading ? 'Scanning...' : 'Scan Kubernetes'}
        </button>

        {!result && (
          <div className="rounded-md border border-slate-800 bg-slate-950/30 p-3 text-xs text-slate-500">
            Tip: leave all fields empty to scan the default context/namespace configured on the backend.
          </div>
        )}
      </div>

      {!result && (
        <div className={panelClass() + ' p-6 text-center'}>
          <div className="text-sm text-slate-300">No scan results yet</div>
          <div className="mt-1 text-sm text-slate-500">Run a scan to view ingresses, certificates, and findings.</div>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className={panelClass()}>
              <div className="text-sm text-slate-400">Findings</div>
              <div className={`mt-1 text-2xl font-semibold ${result.findings_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                {result.findings_count}
              </div>
            </div>
            <div className={panelClass()}>
              <div className="text-sm text-slate-400">Ingresses</div>
              <div className="mt-1 text-2xl font-semibold text-slate-100">
                {result.ingresses.length}
              </div>
            </div>
            <div className={panelClass()}>
              <div className="text-sm text-slate-400">Certificates</div>
              <div className="mt-1 text-2xl font-semibold text-slate-100">
                {result.certificates.length}
              </div>
            </div>
          </div>

          {result.findings.length > 0 && (
            <div className={panelClass()}>
              <h3 className="font-medium">Findings</h3>
              <div className="mt-4 space-y-2">
                {result.findings.map((finding, idx) => (
                  <div key={idx} className="rounded border border-slate-800 bg-slate-800/50 p-3">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-medium ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className="text-sm text-slate-300">{finding.condition}</span>
                    </div>
                    <p className="mt-1 text-xs text-slate-400">{finding.cause}</p>
                    <p className="mt-1 text-xs text-blue-400">Fix: {finding.treatment}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.findings.length === 0 && (
            <div className={panelClass()}>
              <h3 className="font-medium">Findings</h3>
              <div className="mt-2 text-sm text-slate-400">No findings were reported.</div>
            </div>
          )}

          {result.ingresses.length > 0 && (
            <div className={panelClass()}>
              <h3 className="font-medium">Ingresses</h3>
              <div className="mt-4 overflow-x-auto">
                <div className={tableShellClass()}>
                  <table className="w-full text-sm">
                    <thead className="bg-slate-800/50 text-slate-400">
                    <tr>
                      <th className="px-4 py-2 text-left">Name</th>
                      <th className="px-4 py-2 text-left">Namespace</th>
                      <th className="px-4 py-2 text-left">Host</th>
                      <th className="px-4 py-2 text-left">TLS</th>
                      <th className="px-4 py-2 text-left">Issues</th>
                    </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                    {result.ingresses.map((ing, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="px-4 py-2">{ing.name}</td>
                        <td className="px-4 py-2 text-slate-400">{ing.namespace}</td>
                        <td className="px-4 py-2">{ing.host}</td>
                        <td className="px-4 py-2">
                          <span className={ing.tls_configured ? 'text-green-400' : 'text-red-400'}>
                            {ing.tls_configured ? 'Yes' : 'No'}
                          </span>
                        </td>
                        <td className="px-4 py-2">
                          {ing.issues.length > 0 ? (
                            <span className="text-red-400">{ing.issues.length} issues</span>
                          ) : (
                            <span className="text-green-400">OK</span>
                          )}
                        </td>
                      </tr>
                    ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {result.certificates.length > 0 && (
            <div className={panelClass()}>
              <h3 className="font-medium">Certificates</h3>
              <div className="mt-4 overflow-x-auto">
                <div className={tableShellClass()}>
                  <table className="w-full text-sm">
                    <thead className="bg-slate-800/50 text-slate-400">
                    <tr>
                      <th className="px-4 py-2 text-left">Name</th>
                      <th className="px-4 py-2 text-left">Namespace</th>
                      <th className="px-4 py-2 text-left">Status</th>
                      <th className="px-4 py-2 text-left">Expiry</th>
                    </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                    {result.certificates.map((cert, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="px-4 py-2">{cert.name}</td>
                        <td className="px-4 py-2 text-slate-400">{cert.namespace}</td>
                        <td className="px-4 py-2">
                          <span className={cert.status === 'Ready' ? 'text-green-400' : 'text-red-400'}>
                            {cert.status}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-slate-400">{cert.expiry}</td>
                      </tr>
                    ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
