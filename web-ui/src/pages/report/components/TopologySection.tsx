import type { TopologyData } from '../../../services/api'
import { CardSection } from './Primitives'

interface TopologySectionProps {
  topology: TopologyData | undefined
}

function appCardClass(type: string): string {
  if (type === 'docker') return 'bg-blue-500/10 border-blue-500/30'
  if (type === 'systemd') return 'bg-purple-500/10 border-purple-500/30'
  if (type === 'php-fpm') return 'bg-cyan-500/10 border-cyan-500/30'
  return 'bg-orange-500/10 border-orange-500/30'
}

function appTypeClass(type: string): string {
  if (type === 'docker') return 'bg-blue-500/20 text-blue-400'
  if (type === 'systemd') return 'bg-purple-500/20 text-purple-400'
  if (type === 'php-fpm') return 'bg-cyan-500/20 text-cyan-400'
  return 'bg-orange-500/20 text-orange-400'
}

export function TopologySection({ topology }: TopologySectionProps) {
  if (!topology?.has_data) return null

  const apps = topology.apps || []
  const databases = topology.databases || []
  const network = topology.network || []

  return (
    <CardSection title="Infrastructure Topology">
      <div className="flex flex-col gap-4">
        <div className="flex items-center gap-3 rounded-lg border border-green-500/30 bg-green-500/10 p-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-500/20">
            <svg className="h-5 w-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-bold text-green-400">Nginx {topology.nginx?.version || 'unknown'}</p>
            <p className="text-[10px] text-slate-400">{topology.nginx?.mode || 'unknown'} - {topology.nginx?.server_count ?? 0} servers</p>
          </div>
        </div>

        <div className="flex justify-center">
          <div className="h-6 w-0.5 bg-slate-700" />
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
          {apps.map((app) => (
            <div key={`${app.type}-${app.name}`} className={`rounded-lg border p-3 ${appCardClass(app.type)}`}>
              <div className="mb-2 flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${app.status === 'running' ? 'bg-green-500' : 'bg-yellow-500'}`} />
                <span className="text-sm font-medium text-slate-200">{app.name}</span>
              </div>
              <div className="space-y-1 text-[10px] text-slate-400">
                {app.image && <p>Image: {app.image}</p>}
                {Array.isArray(app.targets) && <p>Targets: {app.targets.slice(0, 2).join(', ')}{app.targets.length > 2 ? '...' : ''}</p>}
                {Array.isArray(app.ports) && app.ports.length > 0 && <p>Ports: {app.ports.join(', ')}</p>}
                {Array.isArray(app.versions) && app.versions.length > 0 && <p>PHP {app.versions.join(', ')}</p>}
                {Array.isArray(app.sockets) && app.sockets.length > 0 && <p className="truncate">{app.sockets[0]}</p>}
                <p className={`inline-block rounded px-1.5 py-0.5 ${appTypeClass(app.type)}`}>{app.type}</p>
              </div>
            </div>
          ))}
        </div>

        {databases.length > 0 && (
          <>
            <div className="flex justify-center">
              <div className="h-6 w-0.5 bg-slate-700" />
            </div>
            <div className="flex flex-wrap gap-3">
              {databases.map((db) => (
                <div key={`${db.type}-${db.version}`} className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/30 px-3 py-2">
                  <div>
                    <p className="text-sm font-bold capitalize text-slate-200">{db.type}</p>
                    <p className="text-[10px] text-slate-400">{db.version}</p>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {network.length > 0 && (
          <>
            <div className="flex justify-center">
              <div className="h-6 w-0.5 bg-slate-700" />
            </div>
            <div className="flex flex-wrap gap-2">
              {network.map((endpoint) => (
                <div key={`${endpoint.protocol}-${endpoint.address}-${endpoint.port}`} className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/30 px-3 py-2">
                  <div className="flex h-6 w-6 items-center justify-center rounded bg-slate-700">
                    <svg className="h-3 w-3 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                  <div>
                    <p className="font-mono text-xs text-slate-300">{endpoint.address}:{endpoint.port}</p>
                    <p className="text-[10px] uppercase text-slate-500">{endpoint.protocol}</p>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </CardSection>
  )
}
