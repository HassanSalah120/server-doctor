import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { buttonClass, panelClass } from '../components/ui/styles'
import { api, type DeploymentReadiness, type ReportResponse } from '../services/api'
import { parseDiagnosis } from './report/diagnosis'
import { DiagnosisSection } from './report/components/DiagnosisSection'
import { DriftPanel } from './report/components/DriftPanel'
import { ApiSurfacePanel } from './report/components/ApiSurfacePanel'
import { EndpointProbePanel } from './report/components/EndpointProbePanel'
import { FindingEvidencePanel } from './report/components/FindingEvidencePanel'
import { FindingsSection } from './report/components/FindingsSection'
import { HostSecurityPanel } from './report/components/HostSecurityPanel'
import { SecurityHeadersPanel } from './report/components/SecurityHeadersPanel'
import { JobSummaryCards, ReportHeader } from './report/components/Header'
import { KernelLimitsSection } from './report/components/KernelLimitsSection'
import { LogsSection } from './report/components/LogsSection'
import { NginxTopologyPanel } from './report/components/NginxTopologyPanel'
import { PortMapSection } from './report/components/PortMapSection'
import { ReadinessSummaryCard } from './report/components/ReadinessSummaryCard'
import { ResourceMetricsSection } from './report/components/ResourceMetricsSection'
import { ResourcesPressureSection } from './report/components/ResourcesPressureSection'
import { RootCausePanel } from './report/components/RootCausePanel'
import { SSLSection } from './report/components/SSLSection'
import { SafeActionsPanel } from './report/components/SafeActionsPanel'
import { ServiceHealthSection } from './report/components/ServiceHealthSection'
import { StorageSection } from './report/components/StorageSection'
import { SupportPackSection } from './report/components/SupportPackSection'
import { TopologySection } from './report/components/TopologySection'
import { asArray, sortServiceHealthRows } from './report/utils'

export default function ReportPage() {
  const params = useParams()
  const navigate = useNavigate()
  const jobId = params.jobId ? Number(params.jobId) : Number.NaN

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [report, setReport] = useState<ReportResponse | null>(null)
  const [readiness, setReadiness] = useState<DeploymentReadiness | null | undefined>(undefined)
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [scanAgainPending, setScanAgainPending] = useState(false)

  const load = useCallback(async () => {
    if (!Number.isFinite(jobId)) {
      setError('Invalid job id')
      setLoading(false)
      return
    }

    try {
      setLoading(true)
      setError(null)
      const data = await api.getReport(jobId)
      setReport(data)
      try {
        setReadiness(await api.getReadiness(jobId))
      } catch {
        setReadiness(null)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load report')
    } finally {
      setLoading(false)
    }
  }, [jobId])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (import.meta.env.VITE_DEBUG_TELEMETRY !== '1') return
    if (!report) return

    console.log('[telemetry] report.telemetry', report.telemetry)
    console.log('[telemetry] cpu', report.telemetry?.cpu)
    console.log('[telemetry] memory', report.telemetry?.memory)
  }, [report])

  const serviceHealthRows = useMemo(
    () => sortServiceHealthRows(asArray(report?.service_health)),
    [report?.service_health],
  )

  const handleScanAgain = useCallback(async () => {
    if (!report?.job?.server_id || scanAgainPending) {
      return
    }

    try {
      setScanAgainPending(true)
      setError(null)
      const nextJob = await api.startScan(report.job.server_id, {
        repo_scan_paths: report.job.repo_scan_paths || undefined,
      })
      navigate(`/reports/${nextJob.job_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan')
    } finally {
      setScanAgainPending(false)
    }
  }, [navigate, report, scanAgainPending])

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-400">Error: {error}</div>
        <Link to="/jobs" className={buttonClass({ variant: 'default', size: 'sm' })}>
          Back to Jobs
        </Link>
      </div>
    )
  }

  if (!report) {
    return (
      <div className={panelClass() + ' p-6'}>
        <div className="text-slate-400">No report data.</div>
      </div>
    )
  }

  const diagnosis = parseDiagnosis(report.diagnosis)
  const findings = asArray(report.findings)
  const sslStatus = asArray(report.ssl_status)
  const portMap = asArray(report.port_map)
  const isPending = report.job.status === 'queued' || report.job.status === 'running'
  const criticalCount = findings.filter((finding) => (finding.severity || '').toLowerCase() === 'critical').length
  const warningCount = findings.filter((finding) => {
    const key = (finding.severity || '').toLowerCase()
    return key === 'warning' || key === 'high' || key === 'medium'
  }).length
  const autoFixCount = diagnosis ? diagnosis.remediationPlan.filter((item) => item.isAutoFixable === true).length : 0
  const downtimeCount = (report.normalized_findings || []).filter(
    (f) =>
      f.downtime_impact === 'possible_downtime' ||
      f.downtime_impact === 'restart_service' ||
      f.downtime_impact === 'app_deploy_required',
  ).length

  return (
    <div className="space-y-5">
      <ReportHeader
        jobId={report.job.id}
        onRefresh={load}
        onScanAgain={handleScanAgain}
        isScanAgainPending={scanAgainPending}
      />

      <div className="overflow-hidden rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-cyan-500/10 via-slate-900/80 to-slate-950/95 p-5">
        <div className="grid gap-4 lg:grid-cols-[1.3fr,1fr] lg:items-end">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300/80">Execution Snapshot</p>
            <h2 className="text-2xl font-semibold text-slate-100">
              {isPending ? 'Scan still in progress' : 'Scan completed'}
            </h2>
            <p className="text-sm text-slate-300/80">
              Mode: {report.topology?.nginx?.mode || 'unknown'} | Nginx: {report.topology?.nginx?.version || 'unknown'}
            </p>
          </div>
          <JobSummaryCards status={report.job.status} score={report.job.score} findingsCount={findings.length} />
        </div>
      </div>

      {report.message && (
        <div className={panelClass() + ' text-slate-300'}>
          {report.message}
        </div>
      )}

      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.12em] text-red-200/90">Critical</div>
          <div className="text-lg font-semibold text-red-200">{criticalCount}</div>
        </div>
        <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.12em] text-yellow-200/90">Warnings</div>
          <div className="text-lg font-semibold text-yellow-200">{warningCount}</div>
        </div>
        <div className="rounded-xl border border-green-500/30 bg-green-500/10 px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.12em] text-green-200/90">Auto-fixable</div>
          <div className="text-lg font-semibold text-green-200">{autoFixCount}</div>
        </div>
        <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.12em] text-orange-200/90">Needs downtime</div>
          <div className="text-lg font-semibold text-orange-200">{downtimeCount}</div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.65fr,1fr]">
        <div>
          <FindingsSection
            findings={findings}
            isPending={isPending}
            categoryFilter={categoryFilter}
            onCategoryFilterChange={setCategoryFilter}
          />
        </div>

        <div className="space-y-5">
          <ResourceMetricsSection telemetry={report.telemetry} />
          <ReadinessSummaryCard readiness={readiness} />
          <RootCausePanel rootCauses={report.root_causes || []} />
          <EndpointProbePanel findings={findings} />
          <SecurityHeadersPanel findings={findings} />
          <ApiSurfacePanel findings={findings} />
          <HostSecurityPanel findings={findings} />
          <ResourcesPressureSection resources={report.resources} />
          <StorageSection storage={report.storage} />
          <LogsSection logs={report.logs} />
          <KernelLimitsSection kernelLimits={report.kernel_limits} />
          <ServiceHealthSection rows={serviceHealthRows} />
          <TopologySection topology={report.topology} />
          <NginxTopologyPanel nodes={report.nginx_topology} />
          <DriftPanel jobId={report.job.id} />
          <SafeActionsPanel serverId={report.job.server_id} />
          <SSLSection sslStatus={sslStatus} topology={report.topology} />
          <PortMapSection portMap={portMap} />
        </div>
      </div>

      <DiagnosisSection diagnosisRaw={report.diagnosis} diagnosis={diagnosis} />
      <FindingEvidencePanel findings={report.normalized_findings} />
      <SupportPackSection supportPack={report.support_pack} />
    </div>
  )
}
