import type { ReactNode } from 'react'
import type { SSLCertificate } from '../../../services/api'

interface CardSectionProps {
  title: string
  right?: ReactNode
  children: ReactNode
}

export function CardSection({ title, right, children }: CardSectionProps) {
  return (
    <section className="relative z-0 rounded-2xl border border-slate-700/70 bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-slate-950/95 shadow-[0_10px_40px_-20px_rgba(15,23,42,0.8)]">
      <div className="border-b border-slate-800/80 px-4 py-3 sm:px-5">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-slate-200">{title}</h3>
          {right}
        </div>
      </div>
      <div className="p-4 sm:p-5">{children}</div>
    </section>
  )
}

export function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400',
    high: 'bg-orange-500/20 text-orange-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
    medium: 'bg-yellow-500/20 text-yellow-400',
    low: 'bg-blue-500/20 text-blue-400',
    info: 'bg-slate-700 text-slate-300',
  }

  const key = severity.toLowerCase()
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${styles[key] || styles.info}`}>
      {severity}
    </span>
  )
}

export function SeverityPill({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-300 border-red-900/50',
    high: 'bg-orange-500/20 text-orange-300 border-orange-900/50',
    warning: 'bg-yellow-500/20 text-yellow-300 border-yellow-900/50',
    medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-900/50',
    low: 'bg-blue-500/20 text-blue-300 border-blue-900/50',
    info: 'bg-slate-800 text-slate-200 border-slate-700',
  }

  const key = severity.toLowerCase()
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${styles[key] || styles.info}`}>
      {severity}
    </span>
  )
}

export function EffortPill({ effort }: { effort: string }) {
  const styles: Record<string, string> = {
    low: 'bg-green-500/15 text-green-300 border-green-900/50',
    medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-900/50',
    high: 'bg-red-500/15 text-red-300 border-red-900/50',
  }

  const key = effort.toLowerCase()
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${styles[key] || 'bg-slate-800 text-slate-200 border-slate-700'}`}>
      {effort}
    </span>
  )
}

export function YesNoPill({ value, yesLabel, noLabel }: { value: boolean; yesLabel: string; noLabel: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${
        value ? 'bg-green-500/15 text-green-300 border-green-900/50' : 'bg-slate-800 text-slate-200 border-slate-700'
      }`}
    >
      {value ? yesLabel : noLabel}
    </span>
  )
}

export function PhasePill({ phase }: { phase: number }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-200">
      Phase {phase}
    </span>
  )
}

export function ProgressBar({ percent, status }: { percent: number; status: 'critical' | 'warning' | 'healthy' | 'unknown' }) {
  const colorClasses = {
    critical: 'bg-red-500',
    warning: 'bg-yellow-500',
    healthy: 'bg-green-500',
    unknown: 'bg-slate-500',
  }

  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
      <div className={`h-full rounded-full transition-all duration-500 ${colorClasses[status]}`} style={{ width: `${Math.min(100, Math.max(0, percent))}%` }} />
    </div>
  )
}

export function SSLCountdownBadge({ cert }: { cert: Pick<SSLCertificate, 'days_remaining' | 'color' | 'urgent'> }) {
  const colorClasses: Record<string, string> = {
    red: 'bg-red-500/20 text-red-400 border-red-500/30',
    orange: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    yellow: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    green: 'bg-green-500/20 text-green-400 border-green-500/30',
    gray: 'bg-slate-700 text-slate-400',
  }

  const days = cert.days_remaining
  const label = days === null ? 'n/a' : days === 0 ? 'EXPIRED' : `${days} days`

  return (
    <div className="flex flex-col items-start gap-1">
      <span className={`inline-flex items-center rounded-lg border px-3 py-1.5 text-xs font-bold uppercase tracking-wide ${colorClasses[cert.color] || colorClasses.gray}`}>
        {label}
      </span>
      {cert.urgent && (
        <span className="text-[10px] text-red-400">
          {days !== null && days <= 7 ? 'Expires within a week' : 'Expires soon'}
        </span>
      )}
    </div>
  )
}

export function SeverityPieChart({ data }: { data: Record<string, number> }) {
  const colors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    warning: '#eab308',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#64748b',
  }

  const entries = Object.entries(data).filter(([, value]) => value > 0)
  const total = entries.reduce((sum, [, value]) => sum + value, 0)
  if (total <= 0) return null

  let currentAngle = 0
  const slices = entries.map(([severity, count]) => {
    const percentage = count / total
    const angle = percentage * 360
    const startAngle = currentAngle
    const endAngle = currentAngle + angle
    currentAngle = endAngle

    const startRad = (startAngle * Math.PI) / 180
    const endRad = (endAngle * Math.PI) / 180
    const radius = 40
    const cx = 50
    const cy = 50

    const x1 = cx + radius * Math.cos(startRad)
    const y1 = cy + radius * Math.sin(startRad)
    const x2 = cx + radius * Math.cos(endRad)
    const y2 = cy + radius * Math.sin(endRad)

    const largeArc = angle > 180 ? 1 : 0
    const path = `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`

    return {
      severity,
      count,
      path,
      color: colors[severity.toLowerCase()] || colors.info,
    }
  })

  return (
    <div className="flex items-center gap-6">
      <svg viewBox="0 0 100 100" className="h-24 w-24">
        {slices.map((slice) => (
          <path key={slice.severity} d={slice.path} fill={slice.color} stroke="#1e293b" strokeWidth="2" />
        ))}
        <circle cx="50" cy="50" r="20" fill="#0f172a" />
        <text x="50" y="50" textAnchor="middle" dominantBaseline="middle" className="fill-slate-200 text-[10px] font-bold">
          {total}
        </text>
      </svg>
      <div className="flex flex-wrap gap-2">
        {slices.map((slice) => (
          <div key={`${slice.severity}-legend`} className="flex items-center gap-1.5 text-xs">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: slice.color }} />
            <span className="capitalize text-slate-300">{slice.severity}</span>
            <span className="text-slate-500">({slice.count})</span>
          </div>
        ))}
      </div>
    </div>
  )
}
