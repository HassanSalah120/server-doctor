import { panelClass } from '../../../components/ui/styles'
import type { TopologyNode } from '../../../services/api'

const STATUS_BADGE: Record<string, string> = {
  ok: 'bg-green-500/20 text-green-400 border-green-500/30',
  warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
}

const KIND_BADGE: Record<string, string> = {
  server_block: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  domain: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
  location: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
}

function kindBadge(kind: string) {
  return KIND_BADGE[kind] || 'bg-gray-500/10 text-gray-400 border-gray-500/20'
}

function displayLabel(node: TopologyNode): string {
  if (node.kind === 'server_block') {
    const name = node.label || 'default'
    return name === '_' ? 'Default server (_)' : name
  }
  return node.label
}

export function NginxTopologyPanel({ nodes }: { nodes?: TopologyNode[] }) {
  if (!nodes || nodes.length === 0) {
    return <div className={panelClass() + ' text-slate-400'}>No Nginx topology data.</div>
  }
  return (
    <div className={panelClass() + ' space-y-4'}>
      <div className="font-semibold text-slate-100">Nginx Topology</div>
      {nodes.map((node) => (
        node.kind === 'server_block' ? (
          <ServerBlockCard key={node.id} node={node} />
        ) : (
          <TreeItem key={node.id} node={node} depth={0} />
        )
      ))}
    </div>
  )
}

function ServerBlockCard({ node }: { node: TopologyNode }) {
  const name = node.label || 'default'
  const displayName = name === '_' ? 'Default server (_)' : name
  const source = node.metadata?.source_file ? String(node.metadata.source_file) : null
  const root = node.metadata?.root ? String(node.metadata.root) : null

  const domains = node.children.filter(c => c.kind === 'domain')
  const routes = node.children.filter(c => c.kind !== 'domain')

  return (
    <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-slate-100">{displayName}</span>
          <span className={`rounded border px-1.5 py-0.5 text-[10px] uppercase ${STATUS_BADGE[node.status] || STATUS_BADGE.unknown}`}>
            {node.status}
          </span>
        </div>
      </div>

      {source && <div className="mb-1 text-xs text-slate-500">Source: {source}</div>}
      {root && <div className="mb-1 text-xs text-slate-500">Root: {root}</div>}

      {domains.length > 0 && (
        <div className="mb-2">
          <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-indigo-400/70">Domains</div>
          <div className="flex flex-wrap gap-1">
            {domains.map(d => (
              <span key={d.id} className="rounded bg-indigo-500/10 px-1.5 py-0.5 text-xs text-indigo-300">
                {d.label}
              </span>
            ))}
          </div>
        </div>
      )}

      {routes.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Routes</div>
          <div className="space-y-0.5">
            {routes.map(r => (
              <TreeItem key={r.id} node={r} depth={0} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function TreeItem({ node, depth }: { node: TopologyNode; depth: number }) {
  const indent = depth * 14
  const label = displayLabel(node)
  const showKind = node.kind !== 'domain' && node.kind !== 'server_block'

  return (
    <div>
      <div
        className="flex items-center gap-2 py-0.5 text-sm"
        style={{ marginLeft: indent }}
      >
        {depth > 0 && <span className="text-slate-600 select-none">└</span>}
        <span className="text-slate-200">{label}</span>
        {showKind && (
          <span className={`rounded border px-1.5 py-0.5 text-[10px] ${kindBadge(node.kind)}`}>
            {node.kind.replace(/_/g, ' ')}
          </span>
        )}
      </div>
      {node.children.length > 0 && (
        <div>
          {node.children.map(child => (
            <TreeItem key={child.id} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}
