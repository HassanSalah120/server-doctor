import type { TelemetryData } from '../../../services/api'
import { CardSection, ProgressBar } from './Primitives'

interface ResourceMetricsSectionProps {
  telemetry: TelemetryData | undefined
}

function cpuStatusClass(status: string): string {
  if (status === 'critical') return 'text-red-400'
  if (status === 'warning') return 'text-yellow-400'
  if (status === 'unknown') return 'text-slate-500'
  return 'text-green-400'
}

function memoryStatusClass(status: string): string {
  if (status === 'critical') return 'text-red-400'
  if (status === 'warning') return 'text-yellow-400'
  if (status === 'unknown') return 'text-slate-500'
  return 'text-green-400'
}

function diskStatusClass(status: string): string {
  if (status === 'critical') return 'text-red-400'
  if (status === 'warning') return 'text-yellow-400'
  return 'text-green-400'
}

function diskBarClass(status: string): string {
  if (status === 'critical') return 'bg-red-500'
  if (status === 'warning') return 'bg-yellow-500'
  return 'bg-green-500'
}

export function ResourceMetricsSection({ telemetry }: ResourceMetricsSectionProps) {
  if (!telemetry?.has_data) return null

  const cpu = telemetry.cpu
  const memory = telemetry.memory
  const disks = telemetry.disks || []

  return (
    <CardSection title="Resource Metrics">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {cpu && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/30 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/20">
                  <svg className="h-4 w-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-bold text-slate-300">CPU Usage</p>
                  <p className="text-[10px] text-slate-500">{cpu.cores != null ? `${cpu.cores} cores` : 'N/A cores'}</p>
                </div>
              </div>
              <span className={`text-lg font-black ${cpuStatusClass(cpu.status)}`}>
                {cpu.usage_percent != null ? `${cpu.usage_percent}%` : 'N/A'}
              </span>
            </div>
            {cpu.usage_percent != null ? <ProgressBar percent={cpu.usage_percent} status={cpu.status} /> : <div className="h-2 rounded-full bg-slate-800" />}
            <div className="mt-2 flex justify-between text-[10px] text-slate-500">
              <span>Load: {cpu.load_1 ?? 'N/A'}</span>
              <span>
                {cpu.load_5 ?? '-'} / {cpu.load_15 ?? '-'}
              </span>
            </div>
          </div>
        )}

        {memory?.total_gb != null && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/30 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-500/20">
                  <svg className="h-4 w-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-bold text-slate-300">Memory</p>
                  <p className="text-[10px] text-slate-500">{memory.total_gb} GB total</p>
                </div>
              </div>
              <span className={`text-lg font-black ${memoryStatusClass(memory.status)}`}>
                {memory.used_percent != null ? `${memory.used_percent}%` : 'N/A'}
              </span>
            </div>
            {memory.used_percent != null ? <ProgressBar percent={memory.used_percent} status={memory.status} /> : <div className="h-2 rounded-full bg-slate-800" />}
            <div className="mt-2 flex justify-between text-[10px] text-slate-500">
              <span>{memory.used_gb != null ? `${memory.used_gb} GB used` : '-'}</span>
              <span>{memory.available_gb != null ? `${memory.available_gb} GB free` : '-'}</span>
            </div>
          </div>
        )}

        {disks.length > 0 && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/30 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-500/20">
                  <svg className="h-4 w-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-bold text-slate-300">Disk Usage</p>
                  <p className="text-[10px] text-slate-500">{disks.length} mounts</p>
                </div>
              </div>
              <span className={`text-lg font-black ${diskStatusClass(disks[0].status)}`}>{disks[0].used_percent}%</span>
            </div>
            <div className="max-h-24 space-y-2 overflow-y-auto">
              {disks.slice(0, 4).map((disk) => (
                <div key={disk.mount} className="flex items-center justify-between text-xs">
                  <span className="truncate font-mono text-slate-400" style={{ maxWidth: '80px' }}>
                    {disk.mount}
                  </span>
                  <div className="ml-2 flex flex-1 items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                      <div className={`h-full rounded-full ${diskBarClass(disk.status)}`} style={{ width: `${disk.used_percent}%` }} />
                    </div>
                    <span className="w-8 text-right text-slate-500">{disk.used_percent}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </CardSection>
  )
}
