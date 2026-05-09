import type { KernelLimitsData } from '../../../services/api'
import { CardSection } from './Primitives'

interface KernelLimitsSectionProps {
  kernelLimits: KernelLimitsData | undefined
}

function statusBadgeClass(status: KernelLimitsData['status']): string {
  if (status === 'critical') return 'border-red-500/40 bg-red-500/15 text-red-300'
  if (status === 'warning') return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300'
  return 'border-green-500/40 bg-green-500/15 text-green-300'
}

function metricValue(value: number | null | undefined): string {
  return value != null ? String(value) : 'n/a'
}

export function KernelLimitsSection({ kernelLimits }: KernelLimitsSectionProps) {
  if (!kernelLimits?.has_data) return null

  const notes: string[] = []
  const collectionStatus = kernelLimits.collection_status || {}
  const collectionNotes = kernelLimits.collection_notes || {}
  const probeErrors = Object.entries(collectionStatus).filter(([, value]) => {
    const key = String(value || '').toLowerCase()
    return key === 'error' || key === 'timeout' || key === 'insufficient_permissions'
  })
  if (kernelLimits.nofile_soft != null && kernelLimits.nofile_soft < 32768) {
    notes.push(`low nofile soft limit (${kernelLimits.nofile_soft})`)
  }
  if (
    kernelLimits.nginx_worker_connections != null &&
    kernelLimits.nofile_soft != null &&
    kernelLimits.nginx_worker_connections > kernelLimits.nofile_soft
  ) {
    notes.push('worker_connections exceeds nofile soft limit')
  }
  if (kernelLimits.ip_local_port_range_width != null && kernelLimits.ip_local_port_range_width < 20000) {
    notes.push(`narrow local port range (${kernelLimits.ip_local_port_range_width})`)
  }
  if (kernelLimits.somaxconn != null && kernelLimits.somaxconn < 1024) {
    notes.push(`somaxconn below common baseline (${kernelLimits.somaxconn})`)
  }
  if (probeErrors.length > 0) {
    notes.push(`collection errors on ${probeErrors.length} kernel probe(s)`)
  }

  return (
    <CardSection
      title="Kernel Limits"
      right={(
        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide ${statusBadgeClass(kernelLimits.status)}`}>
          {kernelLimits.status || 'healthy'}
        </span>
      )}
    >
      <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">nofile soft</div>
          <div className="mt-1 font-semibold text-slate-200">{metricValue(kernelLimits.nofile_soft)}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">nofile hard</div>
          <div className="mt-1 font-semibold text-slate-200">{metricValue(kernelLimits.nofile_hard)}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">fs.file-max</div>
          <div className="mt-1 font-semibold text-slate-200">{metricValue(kernelLimits.fs_file_max)}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">somaxconn</div>
          <div className="mt-1 font-semibold text-slate-200">{metricValue(kernelLimits.somaxconn)}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">tcp_max_syn_backlog</div>
          <div className="mt-1 font-semibold text-slate-200">{metricValue(kernelLimits.tcp_max_syn_backlog)}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">port range</div>
          <div className="mt-1 font-semibold text-slate-200">
            {kernelLimits.ip_local_port_range_start != null && kernelLimits.ip_local_port_range_end != null
              ? `${kernelLimits.ip_local_port_range_start}-${kernelLimits.ip_local_port_range_end}`
              : 'n/a'}
          </div>
        </div>
      </div>

      <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-[11px] text-slate-300">
        <p>
          nginx workers: <span className="text-slate-200">{metricValue(kernelLimits.nginx_worker_processes)}</span> | worker connections:{' '}
          <span className="text-slate-200">{metricValue(kernelLimits.nginx_worker_connections)}</span> | fd budget:{' '}
          <span className="text-slate-200">{metricValue(kernelLimits.nginx_worker_fd_budget)}</span>
        </p>
        <p className="mt-1 text-slate-400">
          tcp_fin_timeout: {metricValue(kernelLimits.tcp_fin_timeout)} | netdev_max_backlog: {metricValue(kernelLimits.netdev_max_backlog)}
        </p>
      </div>

      {notes.length > 0 && (
        <div className="mt-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-[11px] text-yellow-200">
          {notes.slice(0, 4).map((note, idx) => (
            <p key={`${note}-${idx}`}>{note}</p>
          ))}
          {probeErrors.length > 0 && (
            <p className="mt-1 truncate text-yellow-100">
              detail: {collectionNotes[probeErrors[0][0]] || `${probeErrors[0][0]}=${probeErrors[0][1]}`}
            </p>
          )}
        </div>
      )}
    </CardSection>
  )
}
