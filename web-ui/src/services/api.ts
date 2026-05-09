const API_BASE = '/api'
let csrfToken: string | null = null

export interface Server {
  id: number
  name: string
  host: string
  port: number
  username: string
  tags: string
  created_at: string
  password?: boolean
  password_storage?: string
  key_passphrase?: boolean
  key_passphrase_storage?: string
}

export interface CreateServerInput {
  name: string
  host: string
  port: number
  username: string
  password?: string
  key_path?: string
  key_passphrase?: string
  tags: string
}

export interface AuthStatusResponse {
  authenticated: boolean
  csrf_token?: string | null
}

export type ScanPhase = {
  key: string
  label: string
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped' | 'cancelled'
  progress: number
  started_at?: string | null
  finished_at?: string | null
  error?: string | null
}

export interface Job {
  id: number
  server_id: number
  repo_scan_paths?: string | null
  status: 'queued' | 'running' | 'success' | 'failed' | 'cancelled' | 'cancel_requested'
  score: number | null
  summary: string | null
  progress?: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  server_name?: string | null
  server_host?: string | null
  phases?: ScanPhase[]
}

export interface JobLog {
  id: number
  job_id: number
  timestamp: string
  message: string
}

export interface JobDetailResponse {
  job: Job
  logs: JobLog[]
}

export interface DaemonStatus {
  running: boolean
  pid: number | null
  interval: number
  servers: number[]
  started_at: string | null
  last_scan: string | null
  next_scan: string | null
  scan_count: number
  error_count: number
}

export interface DaemonHistoryEntry {
  timestamp: string
  server: string
  status: string
  message?: string
  new_findings?: number
  resolved_findings?: number
  findings_total?: number
}

export interface StartScanResponse {
  job_id: number
  status: 'queued'
}

export interface Finding {
  id: number
  job_id: number
  rule_id: string
  category: string | null
  component: string | null
  severity: string
  title: string
  description: string | null
  evidence_ref: string | null
  evidence_json: string | null
  recommendation: string | null
  created_at: string
  is_regression?: boolean
  resolved_in_job_id?: number | null
  regressed_in_job_id?: number | null
  regression_count?: number
  first_seen_at?: string | null
  last_resolved_at?: string | null
}

export type EvidenceView = {
  source_file?: string | null
  line_number?: number | null
  excerpt?: string | null
  command?: string | null
}

export type FindingView = {
  id: number
  rule_id: string
  severity: 'critical' | 'warning' | 'info'
  title: string
  description?: string | null
  recommendation?: string | null
  impact?: string | null
  component?: string | null
  affected_target?: string | null
  fix_priority: number
  evidence: EvidenceView[]
  evidence_warning?: string | null
  downtime_impact?: string | null
  is_regression?: boolean
  resolved_in_job_id?: number | null
  regressed_in_job_id?: number | null
  regression_count?: number
  first_seen_at?: string | null
  last_resolved_at?: string | null
}

export type FixCommand = {
  label: string
  command: string
  requires_sudo: boolean
}

export type FixPlan = {
  finding_id: number
  rule_id: string
  can_auto_fix: boolean
  risk: 'low' | 'medium' | 'high' | 'unknown'
  summary: string
  files_affected: string[]
  backup_commands: FixCommand[]
  apply_commands: FixCommand[]
  validate_commands: FixCommand[]
  rollback_commands: FixCommand[]
  warnings: string[]
}

export type DriftItem = {
  kind: string
  severity: string
  title: string
  before?: string | null
  after?: string | null
}

export type ReportCompareResponse = {
  current_job_id: number
  previous_job_id: number | null
  score_delta: number | null
  new_findings: string[]
  resolved_findings: string[]
  drift: DriftItem[]
}

export type TopologyNode = {
  id: string
  label: string
  kind: 'domain' | 'server_block' | 'location' | 'php_fpm' | 'proxy' | 'upstream' | 'project'
  status: 'ok' | 'warning' | 'critical' | 'unknown'
  metadata: Record<string, string | number | boolean | null>
  children: TopologyNode[]
}

export type RootCause = {
  id: string
  title: string
  severity: 'critical' | 'warning' | 'info'
  confidence: number
  hypothesis: string
  supporting_rule_ids: string[]
  evidence_summary: string[]
  recommended_next_steps: string[]
  affected_targets: string[]
}

export type ReadinessCheck = {
  key: string
  label: string
  status: 'pass' | 'warn' | 'fail' | 'unknown'
  blockers: string[]
  evidence: string[]
}

export type DeploymentReadiness = {
  job_id: number
  ready: boolean
  score: number
  blockers: string[]
  warnings: string[]
  checks: ReadinessCheck[]
  needs_verification?: string[]
  score_explanation?: string[]
}

export type SafeActionResponse = {
  action_id: string
  mode: 'preview' | 'run'
  command: string
  risk: string
  requires_confirmation: boolean
  output?: string | null
  error?: string | null
}

export type ValidateFindingResponse = {
  finding_id: number
  rule_id: string
  can_validate: boolean
  command?: string | null
  expected: string
  status: 'preview' | 'resolved' | 'still_failing' | 'not_validatable' | 'error'
  observed?: string | null
  error?: string | null
  attempt_id?: number | null
}

export type SafeApplySensitivePathResponse = {
  finding_id: number
  rule_id: string
  mode: 'preview' | 'apply'
  can_apply: boolean
  status: 'preview' | 'resolved' | 'still_failing' | 'not_applicable' | 'error'
  expected: string
  nginx_file?: string | null
  target_url?: string | null
  patch_preview?: string | null
  backup_path?: string | null
  observed?: string | null
  error?: string | null
  rollback_performed: boolean
  attempt_id?: number | null
}

export type AcceptedRisk = {
  id: number
  server_id: number
  rule_id: string
  finding_title?: string | null
  reason: string
  accepted_by: string
  expires_at?: string | null
  created_at: string
}

export interface ReportResponse {
  job: Job
  findings: Finding[]
  normalized_findings?: FindingView[]
  diagnosis: unknown
  message?: string
  ssl_status?: SSLCertificate[]
  telemetry?: TelemetryData
  logs?: LogsData
  storage?: StorageData
  resources?: ResourcesPressureData
  kernel_limits?: KernelLimitsData
  topology?: TopologyData
  port_map?: PortMapping[]
  service_health?: ServiceHealthItem[]
  support_pack?: ReportSupportPack
  nginx_topology?: TopologyNode[]
  root_causes?: RootCause[]
}

export interface ReportSupportPack {
  runtime_context: {
    job_id: number | null
    status: string
    doctor_version: string
    doctor_build: string
    mode: string
    os: string
    nginx: string
    target_host: string
    runner: string
    install_hint: string
    started_at: string | null
    finished_at: string | null
    generated_at: string
  }
  raw_diagnosis: unknown
  reproduction_commands: {
    title: string
    command: string
    expected: string
    observed: string
  }[]
  evidence_snippets: {
    topic: string
    command: string
    snippet: string
  }[]
  path_notes: string[]
  coverage_matrix: {
    check: string
    status: 'collected' | 'not_observed' | 'not_accessible' | 'not_applicable' | 'error'
    detail: string
  }[]
  expected_behavior: string[]
}

export interface TopologyData {
  has_data: boolean
  nginx?: {
    version: string
    mode: string
    server_count: number
  }
  apps?: {
    name: string
    type: 'upstream' | 'docker' | 'systemd' | 'php-fpm'
    targets?: string[]
    image?: string
    status?: string
    ports?: number[]
    versions?: string[]
    sockets?: string[]
  }[]
  databases?: {
    type: 'mysql' | 'mariadb' | 'postgresql' | 'mongodb' | 'redis' | 'elasticsearch' | string
    version: string
    status: string
  }[]
  network?: {
    address: string
    port: number
    protocol: string
  }[]
  certbot?: {
    installed: boolean
    service_failed: boolean
    domains: string[]
    expiry_days: number[]
  } | null
}

export interface PortMapping {
  port: number
  service: string
  type: 'tcp' | 'docker'
  status: 'open' | 'closed'
  container_port?: number
}

export interface ServiceHealthItem {
  name: string
  state: string
  sub_state?: string
  restart_count: number
  health: 'healthy' | 'unhealthy'
  ports: number[]
  type?: 'docker'
}

export interface SSLCertificate {
  path: string
  issuer: string
  subject: string
  expires_at: string
  days_remaining: number | null
  sans: string[]
  status: 'critical' | 'warning' | 'caution' | 'healthy' | 'unknown'
  color: 'red' | 'orange' | 'yellow' | 'green' | 'gray'
  urgent: boolean
}

export interface TelemetryData {
  has_data: boolean
  cpu?: {
    cores: number | null
    load_1: number | null
    load_5: number | null
    load_15: number | null
    usage_percent: number | null
    status: 'critical' | 'warning' | 'healthy' | 'unknown'
  }
  memory?: {
    total_gb: number
    available_gb: number | null
    used_gb: number | null
    used_percent: number | null
    status: 'critical' | 'warning' | 'healthy' | 'unknown'
  }
  disks?: {
    mount: string
    total_gb: number
    used_gb: number
    used_percent: number
    status: 'critical' | 'warning' | 'healthy'
  }[]
}

export interface LogsData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  journal_errors_24h?: number | null
  journal_oom_events_24h?: number | null
  nginx_error_counts?: Record<string, number>
  nginx_error_samples?: string[]
  php_fpm_error_counts?: Record<string, number>
  php_fpm_error_samples?: string[]
  docker_crashloop_containers?: string[]
  docker_error_samples?: string[]
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

export interface StorageData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  mounts?: {
    mount: string
    total_gb: number
    used_gb: number
    used_percent: number
    inode_used_percent: number | null
    read_only: boolean
    status: 'critical' | 'warning' | 'healthy'
  }[]
  read_only_mounts?: string[]
  failed_mount_units?: string[]
  io_wait_percent?: number | null
  io_error_samples?: string[]
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

export interface ResourcesPressureData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  cpu_cores?: number | null
  load_1?: number | null
  load_5?: number | null
  load_15?: number | null
  load_percent?: number | null
  mem_total_mb?: number | null
  mem_available_mb?: number | null
  mem_used_mb?: number | null
  mem_used_percent?: number | null
  swap_total_mb?: number | null
  swap_free_mb?: number | null
  swap_used_mb?: number | null
  swap_used_percent?: number | null
  oom_events_24h?: number | null
  psi_cpu_some_avg10?: number | null
  psi_memory_some_avg10?: number | null
  psi_io_some_avg10?: number | null
  top_cpu_processes?: string[]
  top_mem_processes?: string[]
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

export interface KernelLimitsData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  nofile_soft?: number | null
  nofile_hard?: number | null
  fs_file_max?: number | null
  somaxconn?: number | null
  tcp_max_syn_backlog?: number | null
  ip_local_port_range_start?: number | null
  ip_local_port_range_end?: number | null
  ip_local_port_range_width?: number | null
  tcp_fin_timeout?: number | null
  netdev_max_backlog?: number | null
  nginx_worker_connections?: number | null
  nginx_worker_processes?: number | null
  nginx_worker_fd_budget?: number | null
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

class ApiService {
  private async fetch<T>(path: string, options?: RequestInit): Promise<T> {
    const method = (options?.method || 'GET').toUpperCase()
    const headers = new Headers(options?.headers)
    if (method !== 'GET' && method !== 'HEAD' && csrfToken) {
      headers.set('x-serverdoctor-csrf', csrfToken)
    }
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      credentials: 'same-origin',
      headers,
    })
    if (!response.ok) {
      let message = `API error: ${response.status}`
      try {
        const data: unknown = await response.json()
        if (data && typeof data === 'object') {
          const maybeDetail = (data as { detail?: unknown }).detail
          const maybeMessage = (data as { message?: unknown }).message
          const detailText = typeof maybeDetail === 'string' ? maybeDetail : null
          const messageText = typeof maybeMessage === 'string' ? maybeMessage : null
          message = detailText || messageText || message
        }
      } catch {
        // ignore JSON parse errors
      }
      throw new Error(message)
    }
    return response.json()
  }

  setCsrfToken(token: string | null) {
    csrfToken = token
  }

  async login(password: string): Promise<AuthStatusResponse> {
    const data = await this.fetch<AuthStatusResponse>('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
    csrfToken = data.csrf_token || null
    return data
  }

  async logout(): Promise<void> {
    await this.fetch<AuthStatusResponse>('/auth/logout', { method: 'POST' })
    csrfToken = null
  }

  async authStatus(): Promise<AuthStatusResponse> {
    const data = await this.fetch<AuthStatusResponse>('/auth/status')
    csrfToken = data.csrf_token || null
    return data
  }

  async getServers(): Promise<Server[]> {
    const data = await this.fetch<{ servers: Server[] }>('/servers')
    return data.servers || []
  }

  async createServer(server: CreateServerInput): Promise<Server> {
    const data = await this.fetch<{ server: Server }>('/servers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(server),
    })
    return data.server
  }

  async deleteServer(id: number, cascade = false): Promise<void> {
    const suffix = cascade ? '?cascade=true' : ''
    await this.fetch(`/servers/${id}${suffix}`, { method: 'DELETE' })
  }

  async getJobs(): Promise<Job[]> {
    const data = await this.fetch<{ jobs: Job[] }>('/jobs')
    return data.jobs || []
  }

  async getJob(jobId: number, afterLogId = 0): Promise<JobDetailResponse> {
    return this.fetch<JobDetailResponse>(`/scan/jobs/${encodeURIComponent(String(jobId))}?after_log_id=${encodeURIComponent(String(afterLogId))}`)
  }

  async startScan(serverId: number, options?: { repo_scan_paths?: string; one_time_password?: string; one_time_key_passphrase?: string }): Promise<StartScanResponse> {
    return this.fetch<StartScanResponse>('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server_id: serverId,
        repo_scan_paths: options?.repo_scan_paths || undefined,
        one_time_password: options?.one_time_password || undefined,
        one_time_key_passphrase: options?.one_time_key_passphrase || undefined,
      }),
    })
  }

  async getReport(jobId: number): Promise<ReportResponse> {
    return this.fetch<ReportResponse>(`/reports/${jobId}`)
  }

  async getReportCompare(jobId: number): Promise<ReportCompareResponse> {
    return this.fetch<ReportCompareResponse>(`/reports/${jobId}/compare`)
  }

  async previewFixes(jobId: number): Promise<{ job_id: number; plans: FixPlan[] }> {
    return this.fetch<{ job_id: number; plans: FixPlan[] }>(`/fixes/preview?job_id=${encodeURIComponent(String(jobId))}`, {
      method: 'POST',
    })
  }

  async validateFinding(
    findingId: number,
    mode: 'preview' | 'run' = 'preview',
  ): Promise<ValidateFindingResponse> {
    return this.fetch<ValidateFindingResponse>('/fixes/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId, mode }),
    })
  }

  async safeApplySensitivePath(
    findingId: number,
    mode: 'preview' | 'apply' = 'preview',
    confirmation?: string,
    ackBackup = false,
    ackRisk = false,
  ): Promise<SafeApplySensitivePathResponse> {
    return this.fetch<SafeApplySensitivePathResponse>('/fixes/safe-apply/sensitive-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_id: findingId,
        mode,
        confirmation,
        ack_backup: ackBackup,
        ack_risk: ackRisk,
      }),
    })
  }

  async acceptRisk(
    findingId: number,
    reason: string,
    expiresAt?: string | null,
  ): Promise<AcceptedRisk> {
    return this.fetch<AcceptedRisk>('/baseline/accept', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_id: findingId,
        reason,
        expires_at: expiresAt || undefined,
      }),
    })
  }

  async getAcceptedRisks(serverId: number): Promise<AcceptedRisk[]> {
    return this.fetch<AcceptedRisk[]>(`/baseline/servers/${serverId}`)
  }

  async getReadiness(jobId: number): Promise<DeploymentReadiness> {
    return this.fetch<DeploymentReadiness>(`/readiness/${jobId}`)
  }

  async safeAction(
    serverId: number,
    actionId: string,
    mode: 'preview' | 'run' = 'preview',
  ): Promise<SafeActionResponse> {
    return this.fetch<SafeActionResponse>('/actions/safe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server_id: serverId, action_id: actionId, mode }),
    })
  }

  async getDaemonStatus(): Promise<DaemonStatus> {
    return this.fetch<DaemonStatus>('/daemon/status')
  }

  async getDaemonHistory(limit = 20): Promise<DaemonHistoryEntry[]> {
    return this.fetch<DaemonHistoryEntry[]>(`/daemon/history?limit=${encodeURIComponent(String(limit))}`)
  }

  async startDaemon(interval: number, serverIds: number[]): Promise<void> {
    await this.fetch('/daemon/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interval, server_ids: serverIds }),
    })
  }

  async stopDaemon(): Promise<void> {
    await this.fetch('/daemon/stop', { method: 'POST' })
  }

  async triggerScan(): Promise<void> {
    await this.fetch('/daemon/scan-now', { method: 'POST' })
  }
}

export const api = new ApiService()
