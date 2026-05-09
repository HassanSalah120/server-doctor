import { Link } from 'react-router-dom'
import { PageHeader } from '../../../components/PageHeader'
import { buttonClass } from '../../../components/ui/styles'

interface ReportHeaderProps {
  jobId: number
  onRefresh: () => void
  onScanAgain?: () => void
  isScanAgainPending?: boolean
}

export function ReportHeader({
  jobId,
  onRefresh,
  onScanAgain,
  isScanAgainPending = false,
}: ReportHeaderProps) {
  return (
    <PageHeader
      eyebrow="ServerDoctor Analysis"
      title="Infrastructure Report"
      subtitle={`Job #${jobId}`}
      actions={
        <>
          {onScanAgain ? (
            <button
              type="button"
              onClick={onScanAgain}
              disabled={isScanAgainPending}
              className={buttonClass({ variant: 'primary', size: 'sm' })}
            >
              {isScanAgainPending ? 'Starting...' : 'Scan Again'}
            </button>
          ) : null}
          <button
            type="button"
            onClick={onRefresh}
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Refresh
          </button>
          <Link
            to="/jobs"
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Back
          </Link>
        </>
      }
    />
  )
}

interface JobSummaryProps {
  status: string
  score: number | null
  findingsCount: number
}

export function JobSummaryCards({ status, score, findingsCount }: JobSummaryProps) {
  const statusClass =
    status === 'success'
      ? 'text-green-300 border-green-500/30 bg-green-500/10'
      : status === 'failed'
        ? 'text-red-300 border-red-500/30 bg-red-500/10'
        : 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10'

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className={`rounded-xl border p-4 ${statusClass}`}>
        <div className="text-[11px] uppercase tracking-[0.14em] text-slate-300/90">Status</div>
        <div className="mt-2 text-xl font-semibold">{status}</div>
      </div>
      <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4">
        <div className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Score</div>
        <div className="mt-2 text-2xl font-semibold text-slate-100">{score ?? '-'}</div>
      </div>
      <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4">
        <div className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Findings</div>
        <div className="mt-2 text-2xl font-semibold text-slate-100">{findingsCount}</div>
      </div>
    </div>
  )
}
