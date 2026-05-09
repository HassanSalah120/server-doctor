param(
    [switch]$DebugTelemetry
)

$ErrorActionPreference = 'Stop'

function Set-EnvDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace((Get-Item -Path "Env:$Name" -ErrorAction SilentlyContinue).Value)) {
        Set-Item -Path "Env:$Name" -Value $Value
    }
}

function Stop-Tree {
    param([int]$ProcessId)

    try {
        if ($ProcessId -le 0) { return }
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) { return }

        # Try graceful first
        try { Stop-Process -Id $ProcessId -ErrorAction SilentlyContinue } catch {}

        Start-Sleep -Milliseconds 300

        # Ensure children are gone (best-effort)
        try {
            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" -ErrorAction SilentlyContinue
            foreach ($c in ($children | ForEach-Object { $_.ProcessId })) {
                try { Stop-Process -Id $c -Force -ErrorAction SilentlyContinue } catch {}
            }
        } catch {}
    } catch {}
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$webUi = Join-Path $root 'web-ui'

if (-not (Test-Path $webUi)) {
    throw "web-ui folder not found at: $webUi"
}

$pythonExe = (Get-Command python -ErrorAction Stop).Source

# On Windows, npm is typically a cmd shim (npm.cmd). Start-Process works more reliably with full path.
$npmExe = $null
try {
    $npmExe = (Get-Command npm.cmd -ErrorAction Stop).Source
} catch {
    $npmExe = (Get-Command npm -ErrorAction Stop).Source
}

$apiOut = Join-Path $root '.dev-api.out.log'
$apiErr = Join-Path $root '.dev-api.err.log'
$uiOut = Join-Path $root '.dev-ui.out.log'
$uiErr = Join-Path $root '.dev-ui.err.log'

"" | Out-File -FilePath $apiOut -Encoding utf8
"" | Out-File -FilePath $apiErr -Encoding utf8
"" | Out-File -FilePath $uiOut -Encoding utf8
"" | Out-File -FilePath $uiErr -Encoding utf8

# Scan performance defaults (override by pre-setting env vars before running this script)
Set-EnvDefault -Name 'server_doctor_JOB_TIMEOUT' -Value '0'
Set-EnvDefault -Name 'server_doctor_SSH_MAX_PARALLEL' -Value '1'
Set-EnvDefault -Name 'server_doctor_SSH_CHANNEL_RETRIES' -Value '6'
Set-EnvDefault -Name 'server_doctor_SSH_KEEPALIVE_SEC' -Value '20'
Set-EnvDefault -Name 'server_doctor_SCAN_SECONDARY_WORKERS' -Value '1'
Set-EnvDefault -Name 'server_doctor_SCAN_RUNTIME_WORKERS' -Value '1'
Set-EnvDefault -Name 'server_doctor_SCAN_NGINX_WORKERS' -Value '1'
Set-EnvDefault -Name 'server_doctor_SCAN_PROJECT_WORKERS' -Value '1'
Set-EnvDefault -Name 'server_doctor_REPO_SCAN_WORKERS' -Value '1'
Set-EnvDefault -Name 'server_doctor_TLS_MAX_TARGETS' -Value '8'
Set-EnvDefault -Name 'server_doctor_TLS_PROBE_TIMEOUT' -Value '3'
Set-EnvDefault -Name 'server_doctor_CERTBOT_DRY_RUN' -Value '0'
Set-EnvDefault -Name 'server_doctor_DEPENDENCY_OUTDATED_TIMEOUT' -Value '15'
Set-EnvDefault -Name 'server_doctor_DEPENDENCY_AUDIT_TIMEOUT' -Value '20'
Set-EnvDefault -Name 'server_doctor_LOG_JOURNAL_MAX_LINES' -Value '2000'
Set-EnvDefault -Name 'server_doctor_LOG_NGINX_TAIL_LINES' -Value '400'
Set-EnvDefault -Name 'server_doctor_LOG_PHP_TAIL_LINES' -Value '250'
Set-EnvDefault -Name 'server_doctor_LOG_DOCKER_TAIL_LINES' -Value '60'
Set-EnvDefault -Name 'server_doctor_STORAGE_DMESG_TAIL_LINES' -Value '20'
Set-EnvDefault -Name 'server_doctor_RESOURCES_TOP_PROCESS_ROWS' -Value '8'
Set-EnvDefault -Name 'server_doctor_LOG_JOURNAL_WARN_COUNT' -Value '120'
Set-EnvDefault -Name 'server_doctor_LOG_JOURNAL_CRIT_COUNT' -Value '500'
Set-EnvDefault -Name 'server_doctor_STORAGE_DISK_WARN_PERCENT' -Value '92'
Set-EnvDefault -Name 'server_doctor_STORAGE_DISK_CRIT_PERCENT' -Value '97'
Set-EnvDefault -Name 'server_doctor_RESOURCES_PSI_MEM_WARN' -Value '2'
Set-EnvDefault -Name 'server_doctor_RESOURCES_PSI_MEM_CRIT' -Value '6'
Set-EnvDefault -Name 'server_doctor_OOM_CRIT_COUNT' -Value '3'

Write-Host ("Scan perf defaults: timeout={0}, ssh_parallel={1}, repo_workers={2}, tls_targets={3}, tls_timeout={4}s, certbot_dry_run={5}, dep_outdated_timeout={6}s, dep_audit_timeout={7}s" -f `
    $env:server_doctor_JOB_TIMEOUT, `
    $env:server_doctor_SSH_MAX_PARALLEL, `
    $env:server_doctor_REPO_SCAN_WORKERS, `
    $env:server_doctor_TLS_MAX_TARGETS, `
    $env:server_doctor_TLS_PROBE_TIMEOUT, `
    $env:server_doctor_CERTBOT_DRY_RUN, `
    $env:server_doctor_DEPENDENCY_OUTDATED_TIMEOUT, `
    $env:server_doctor_DEPENDENCY_AUDIT_TIMEOUT) -ForegroundColor DarkCyan
Write-Host ("SSH resiliency: channel_retries={0}, keepalive={1}s" -f `
    $env:server_doctor_SSH_CHANNEL_RETRIES, `
    $env:server_doctor_SSH_KEEPALIVE_SEC) -ForegroundColor DarkCyan
Write-Host ("Scan worker limits: secondary={0}, runtime={1}, nginx={2}, project={3}" -f `
    $env:server_doctor_SCAN_SECONDARY_WORKERS, `
    $env:server_doctor_SCAN_RUNTIME_WORKERS, `
    $env:server_doctor_SCAN_NGINX_WORKERS, `
    $env:server_doctor_SCAN_PROJECT_WORKERS) -ForegroundColor DarkCyan

Write-Host ("Scan guardrails: journal_max={0}, nginx_tail={1}, php_tail={2}, docker_tail={3}, dmesg_tail={4}, top_rows={5}" -f `
    $env:server_doctor_LOG_JOURNAL_MAX_LINES, `
    $env:server_doctor_LOG_NGINX_TAIL_LINES, `
    $env:server_doctor_LOG_PHP_TAIL_LINES, `
    $env:server_doctor_LOG_DOCKER_TAIL_LINES, `
    $env:server_doctor_STORAGE_DMESG_TAIL_LINES, `
    $env:server_doctor_RESOURCES_TOP_PROCESS_ROWS) -ForegroundColor DarkCyan

if ($DebugTelemetry) {
    $env:VITE_DEBUG_TELEMETRY = '1'
    $env:server_doctor_DEBUG_TELEMETRY = '1'
    Write-Host "Telemetry debug enabled (VITE_DEBUG_TELEMETRY=1, server_doctor_DEBUG_TELEMETRY=1)" -ForegroundColor Yellow
}

# Load SERVER_DOCTOR_WEB_PASSWORD from .env if not already set
if (-not $env:SERVER_DOCTOR_WEB_PASSWORD) {
    $envFile = Join-Path $root '.env'
    if (Test-Path $envFile) {
        $match = Select-String -Path $envFile -Pattern '^SERVER_DOCTOR_WEB_PASSWORD=(.+)'
        if ($match) {
            $env:SERVER_DOCTOR_WEB_PASSWORD = $match.Matches.Groups[1].Value
        }
    }
}

Write-Host "Starting FastAPI on http://127.0.0.1:8765 ..."
$api = Start-Process -FilePath $pythonExe -ArgumentList @('-m','server_doctor','web','--port','8765') -WorkingDirectory $root -PassThru -RedirectStandardOutput $apiOut -RedirectStandardError $apiErr

Write-Host "Starting React dev server (Vite) ..."
$ui = Start-Process -FilePath $npmExe -ArgumentList @('run','dev') -WorkingDirectory $webUi -PassThru -RedirectStandardOutput $uiOut -RedirectStandardError $uiErr

Write-Host ""
Write-Host "Dev stack is running:" -ForegroundColor Green
Write-Host "- FastAPI: http://127.0.0.1:8765 (API only)"
Write-Host "- React UI: http://localhost:5173 (development)" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Open http://localhost:5173 for development (live reload)"
Write-Host "API endpoints are at http://127.0.0.1:8765/api/"
Write-Host ""
Write-Host "Press Ctrl+C to stop both." 

try {
    while ($true) {
        Start-Sleep -Seconds 1

        if ($api.HasExited) {
            Write-Host "FastAPI process exited." -ForegroundColor Red
            if (Test-Path $apiErr) {
                Write-Host "--- FastAPI stderr (tail) ---" -ForegroundColor Yellow
                Get-Content -Path $apiErr -Tail 60 | ForEach-Object { Write-Host $_ }
            }
            if (Test-Path $apiOut) {
                Write-Host "--- FastAPI stdout (tail) ---" -ForegroundColor Yellow
                Get-Content -Path $apiOut -Tail 60 | ForEach-Object { Write-Host $_ }
            }
            break
        }

        if ($ui.HasExited) {
            Write-Host "Vite dev server exited." -ForegroundColor Red

            if (Test-Path $uiErr) {
                Write-Host "--- Vite stderr (tail) ---" -ForegroundColor Yellow
                Get-Content -Path $uiErr -Tail 80 | ForEach-Object { Write-Host $_ }
            }
            if (Test-Path $uiOut) {
                Write-Host "--- Vite stdout (tail) ---" -ForegroundColor Yellow
                Get-Content -Path $uiOut -Tail 80 | ForEach-Object { Write-Host $_ }
            }
            break
        }
    }
}
finally {
    Write-Host "Stopping dev stack..." -ForegroundColor Yellow
    Stop-Tree -ProcessId $ui.Id
    Stop-Tree -ProcessId $api.Id
}
