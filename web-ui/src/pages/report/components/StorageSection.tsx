import type { StorageData } from '../../../services/api'
import { CardSection } from './Primitives'

interface StorageSectionProps {
  storage: StorageData | undefined
}

function statusLabelClass(status: StorageData['status']): string {
  if (status === 'critical') return 'border-red-500/40 bg-red-500/15 text-red-300'
  if (status === 'warning') return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300'
  return 'border-green-500/40 bg-green-500/15 text-green-300'
}

function mountBarClass(status: 'critical' | 'warning' | 'healthy'): string {
  if (status === 'critical') return 'bg-red-500'
  if (status === 'warning') return 'bg-yellow-500'
  return 'bg-green-500'
}

export function StorageSection({ storage }: StorageSectionProps) {
  if (!storage?.has_data) return null

  const mounts = Array.isArray(storage.mounts) ? storage.mounts : []
  const readOnlyMounts = Array.isArray(storage.read_only_mounts) ? storage.read_only_mounts : []
  const failedMountUnits = Array.isArray(storage.failed_mount_units) ? storage.failed_mount_units : []
  const ioErrors = Array.isArray(storage.io_error_samples) ? storage.io_error_samples : []
  const diskProbeNote =
    typeof storage.collection_notes?.['storage.df_disk'] === 'string'
      ? storage.collection_notes['storage.df_disk']
      : ''
  const diskProbeStatus =
    typeof storage.collection_status?.['storage.df_disk'] === 'string'
      ? storage.collection_status['storage.df_disk']
      : ''

  return (
    <CardSection
      title="Storage Health"
      right={(
        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide ${statusLabelClass(storage.status)}`}>
          {storage.status || 'healthy'}
        </span>
      )}
    >
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">Mounts</div>
          <div className="mt-1 text-base font-semibold text-slate-200">{mounts.length}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">Read-only</div>
          <div className={`mt-1 text-base font-semibold ${readOnlyMounts.length > 0 ? 'text-yellow-300' : 'text-slate-200'}`}>
            {readOnlyMounts.length}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">IO wait</div>
          <div className={`mt-1 text-base font-semibold ${(storage.io_wait_percent || 0) >= 20 ? 'text-yellow-300' : 'text-slate-200'}`}>
            {storage.io_wait_percent != null ? `${storage.io_wait_percent}%` : 'n/a'}
          </div>
        </div>
      </div>

      <div className="mt-3 space-y-2">
        {mounts.slice(0, 6).map((mount, idx) => (
          <div key={`${mount.mount}-${idx}`} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
            <div className="mb-1 flex items-center justify-between gap-2 text-xs">
              <span className="truncate font-mono text-slate-300">{mount.mount}</span>
              <span className="text-slate-300">{mount.used_percent}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
              <div className={`h-full rounded-full ${mountBarClass(mount.status)}`} style={{ width: `${Math.min(100, Math.max(0, mount.used_percent))}%` }} />
            </div>
            <div className="mt-1 flex justify-between text-[10px] text-slate-500">
              <span>{mount.used_gb} / {mount.total_gb} GB</span>
              <span>{mount.inode_used_percent != null ? `inode ${mount.inode_used_percent}%` : 'inode n/a'}</span>
            </div>
          </div>
        ))}
        {mounts.length === 0 && (
          <div className="space-y-1 text-xs">
            <p className="text-slate-500">No mount metrics captured.</p>
            {diskProbeNote && diskProbeStatus !== 'collected' ? (
              <p className="text-yellow-300">
                Disk usage probe unavailable: {diskProbeNote}
              </p>
            ) : null}
          </div>
        )}
      </div>

      {(failedMountUnits.length > 0 || ioErrors.length > 0) && (
        <div className="mt-3 space-y-1 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-[11px] text-slate-300">
          {failedMountUnits.length > 0 && (
            <p className="truncate">
              failed units: <span className="text-yellow-300">{failedMountUnits.slice(0, 3).join(', ')}</span>
            </p>
          )}
          {ioErrors.slice(0, 1).map((line) => (
            <p key={line} className="truncate">io error: {line}</p>
          ))}
        </div>
      )}
    </CardSection>
  )
}
