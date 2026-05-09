import type { ResourcesPressureData } from '../../../services/api'
import { CardSection, ProgressBar } from './Primitives'

interface ResourcesPressureSectionProps {
  resources: ResourcesPressureData | undefined
}

function statusClass(status: ResourcesPressureData['status']): string {
  if (status === 'critical') return 'border-red-500/40 bg-red-500/15 text-red-300'
  if (status === 'warning') return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300'
  return 'border-green-500/40 bg-green-500/15 text-green-300'
}

function progressState(percent: number | null | undefined): 'critical' | 'warning' | 'healthy' | 'unknown' {
  if (percent == null) return 'unknown'
  if (percent >= 90) return 'critical'
  if (percent >= 75) return 'warning'
  return 'healthy'
}

export function ResourcesPressureSection({ resources }: ResourcesPressureSectionProps) {
  if (!resources?.has_data) return null

  const topCpu = Array.isArray(resources.top_cpu_processes) ? resources.top_cpu_processes : []
  const topMem = Array.isArray(resources.top_mem_processes) ? resources.top_mem_processes : []

  return (
    <CardSection
      title="Resources Pressure"
      right={(
        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide ${statusClass(resources.status)}`}>
          {resources.status || 'healthy'}
        </span>
      )}
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-500">CPU load pressure</div>
          <div className="mt-1 flex items-baseline gap-2 text-sm font-semibold text-slate-200">
            <span>{resources.load_percent != null ? `${resources.load_percent}%` : 'n/a'}</span>
            {resources.cpu_cores != null ? (
              <span className="text-[11px] font-normal text-slate-500">{resources.cpu_cores} cores</span>
            ) : null}
          </div>
          {resources.load_percent != null ? (
            <div className="mt-2">
              <ProgressBar percent={resources.load_percent} status={progressState(resources.load_percent)} />
            </div>
          ) : (
            <div className="mt-2 h-2 rounded-full bg-slate-800" />
          )}
          <div className="mt-2 text-[10px] text-slate-500">
            load: {resources.load_1 ?? '-'} / {resources.load_5 ?? '-'} / {resources.load_15 ?? '-'}
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-500">Memory pressure</div>
          <div className="mt-1 text-sm font-semibold text-slate-200">
            {resources.mem_used_percent != null ? `${resources.mem_used_percent}%` : 'n/a'}
          </div>
          {resources.mem_used_percent != null ? (
            <div className="mt-2">
              <ProgressBar percent={resources.mem_used_percent} status={progressState(resources.mem_used_percent)} />
            </div>
          ) : (
            <div className="mt-2 h-2 rounded-full bg-slate-800" />
          )}
          <div className="mt-2 text-[10px] text-slate-500">
            {resources.mem_used_mb != null && resources.mem_total_mb != null
              ? `${resources.mem_used_mb} / ${resources.mem_total_mb} MB`
              : 'memory n/a'}
          </div>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">OOM (24h)</div>
          <div className={`mt-1 text-sm font-semibold ${(resources.oom_events_24h || 0) > 0 ? 'text-yellow-300' : 'text-slate-200'}`}>
            {resources.oom_events_24h ?? '0'}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">PSI CPU</div>
          <div className="mt-1 text-sm font-semibold text-slate-200">{resources.psi_cpu_some_avg10 ?? 'n/a'}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">PSI Memory</div>
          <div className={`mt-1 text-sm font-semibold ${(resources.psi_memory_some_avg10 || 0) >= 2 ? 'text-yellow-300' : 'text-slate-200'}`}>
            {resources.psi_memory_some_avg10 ?? 'n/a'}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">PSI IO</div>
          <div className={`mt-1 text-sm font-semibold ${(resources.psi_io_some_avg10 || 0) >= 2 ? 'text-yellow-300' : 'text-slate-200'}`}>
            {resources.psi_io_some_avg10 ?? 'n/a'}
          </div>
        </div>
      </div>

      {(topCpu.length > 0 || topMem.length > 0) && (
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
            <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-400">Top CPU processes</div>
            <div className="space-y-1 text-[11px] text-slate-300">
              {topCpu.slice(0, 3).map((line, idx) => (
                <p key={`cpu-${idx}`} className="truncate font-mono">{line}</p>
              ))}
              {topCpu.length === 0 && <p className="text-slate-500">No samples.</p>}
            </div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
            <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-400">Top memory processes</div>
            <div className="space-y-1 text-[11px] text-slate-300">
              {topMem.slice(0, 3).map((line, idx) => (
                <p key={`mem-${idx}`} className="truncate font-mono">{line}</p>
              ))}
              {topMem.length === 0 && <p className="text-slate-500">No samples.</p>}
            </div>
          </div>
        </div>
      )}
    </CardSection>
  )
}
