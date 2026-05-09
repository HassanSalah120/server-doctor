import type { LogsData } from '../../../services/api'
import { CardSection } from './Primitives'

interface LogsSectionProps {
  logs: LogsData | undefined
}

function badgeClass(status: LogsData['status']): string {
  if (status === 'critical') return 'border-red-500/40 bg-red-500/15 text-red-300'
  if (status === 'warning') return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300'
  return 'border-green-500/40 bg-green-500/15 text-green-300'
}

function sumCounts(counts: Record<string, number> | undefined): number {
  if (!counts) return 0
  return Object.values(counts).reduce((acc, value) => acc + value, 0)
}

export function LogsSection({ logs }: LogsSectionProps) {
  if (!logs?.has_data) return null

  const nginxTotal = sumCounts(logs.nginx_error_counts)
  const phpTotal = sumCounts(logs.php_fpm_error_counts)
  const crashloops = Array.isArray(logs.docker_crashloop_containers) ? logs.docker_crashloop_containers : []
  const nginxSamples = Array.isArray(logs.nginx_error_samples) ? logs.nginx_error_samples : []
  const phpSamples = Array.isArray(logs.php_fpm_error_samples) ? logs.php_fpm_error_samples : []
  const dockerSamples = Array.isArray(logs.docker_error_samples) ? logs.docker_error_samples : []

  return (
    <CardSection
      title="Logs & Incidents"
      right={(
        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide ${badgeClass(logs.status)}`}>
          {logs.status || 'healthy'}
        </span>
      )}
    >
      <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">Journal err (24h)</div>
          <div className="mt-1 text-base font-semibold text-slate-200">{logs.journal_errors_24h ?? 'n/a'}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">Log scanner OOM</div>
          <div className={`mt-1 text-base font-semibold ${(logs.journal_oom_events_24h || 0) > 0 ? 'text-yellow-300' : 'text-slate-200'}`}>
            {logs.journal_oom_events_24h ?? 'n/a'}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">Nginx error hits</div>
          <div className={`mt-1 text-base font-semibold ${nginxTotal > 0 ? 'text-yellow-300' : 'text-slate-200'}`}>{nginxTotal}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
          <div className="text-slate-500">Crashloop containers</div>
          <div className={`mt-1 text-base font-semibold ${crashloops.length > 0 ? 'text-yellow-300' : 'text-slate-200'}`}>{crashloops.length}</div>
        </div>
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-400">Nginx / PHP samples</div>
          <div className="space-y-1 text-[11px] text-slate-300">
            {nginxSamples.slice(0, 2).map((line) => (
              <p key={`ngx-${line}`} className="truncate">{line}</p>
            ))}
            {phpSamples.slice(0, 2).map((line) => (
              <p key={`php-${line}`} className="truncate">{line}</p>
            ))}
            {nginxSamples.length === 0 && phpSamples.length === 0 && <p className="text-slate-500">No recent error samples.</p>}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-slate-400">Docker incidents</div>
          <div className="space-y-1 text-[11px] text-slate-300">
            {crashloops.slice(0, 3).map((name) => (
              <p key={name} className="truncate">
                crashloop: <span className="font-mono">{name}</span>
              </p>
            ))}
            {dockerSamples.slice(0, 2).map((line) => (
              <p key={`docker-${line}`} className="truncate">{line}</p>
            ))}
            {crashloops.length === 0 && dockerSamples.length === 0 && <p className="text-slate-500">No container restart signals.</p>}
          </div>
        </div>
      </div>

      {phpTotal > 0 && (
        <div className="mt-3 text-[11px] text-slate-400">
          PHP-FPM error matches: <span className="text-slate-200">{phpTotal}</span>
        </div>
      )}
    </CardSection>
  )
}
