# server-doctor Architecture Notes

## Overview

server-doctor is a modular SSH-based server diagnostic tool that scans Nginx configurations, PHP installations, and Laravel projects to identify misconfigurations and security issues.

## Core Components

```
src/server_doctor/
├── cli.py              # Click-based CLI entrypoint
├── config.py           # Server profile management
├── connector/          # SSH connection handling
├── scanner/            # Data collection (runs commands)
├── parser/             # Parses raw output into models
├── model/              # Dataclasses (ServerModel, Finding, Evidence)
├── analyzer/           # Diagnostics (no commands, only reasoning)
├── actions/            # Output formatting and reporting
├── engine/             # Orchestration layer
└── templates/          # HTML report templates
```

## Data Flow

```
SSH Connection → Scanners → Parsers → ServerModel → Analyzers → Findings → ReportAction
```

1. **Scanners** (read-only): Run shell commands via SSH
   - `NginxScanner`: `nginx -T`, `nginx -v`
   - `PHPScanner`: PHP versions, FPM pools, sockets
   - `FilesystemScanner`: Project detection in `/var/www`

2. **Parsers**: Convert raw output to structured data
   - `NginxConfigParser`: Parse nginx -T into ServerBlock/LocationBlock

3. **Model** (single source of truth):
   - `ServerModel`: Complete server state
   - `NginxInfo`: Servers, upstreams, includes
   - `Finding`: Diagnosis result with evidence
   - `Evidence`: File/line/command proof

4. **Analyzers**: Reason about model, emit Findings
   - `ServerDoctorAnalyzer`: Core config checks
   - `ServerAuditor`: Security/sanity checks
   - `WSSAuditor`: WebSocket-specific checks

## Finding Schema

```python
@dataclass
class Finding:
    id: str               # e.g., "NGX-PERF-1"
    severity: Severity    # CRITICAL, WARNING, INFO
    confidence: float     # 0.0 - 1.0
    condition: str        # Short title
    cause: str            # Why this exists
    evidence: list[Evidence]  # REQUIRED, never empty
    treatment: str        # Recommended fix
    impact: list[str]     # What happens if ignored
    derived_from: str | None  # Parent finding ID
```

```python
@dataclass
class Evidence:
    source_file: str      # e.g., /etc/nginx/sites-enabled/app.conf
    line_number: int
    excerpt: str          # The problematic line(s)
    command: str          # e.g., "nginx -T"
```

## Current Checks

### ServerDoctorAnalyzer (server_doctor.py)

| ID     | Check                                |
| ------ | ------------------------------------ |
| NGX001 | Backup files in sites-enabled        |
| NGX002 | Laravel root not pointing to /public |
| NGX003 | Missing try_files for PHP            |
| NGX004 | PHP socket mismatch                  |
| NGX005 | Duplicate server_name                |
| NGX006 | Dynamic nginx paths warning          |

### ServerAuditor (server_auditor.py)

| ID     | Check                   |
| ------ | ----------------------- |
| NGX200 | .env file exposure risk |
| NGX201 | SSL certificate issues  |
| NGX202 | PHP version consistency |

### WSSAuditor (wss_auditor.py)

| ID              | Check                          |
| --------------- | ------------------------------ |
| NGX-WSS-001–010 | WebSocket configuration checks |

## Output Formats

- `rich`: Terminal tables/panels (default for TTY)
- `plain`: Plain text (pipe-friendly)
- `json`: Machine-parseable
- `html`: Standalone HTML report

## CLI Commands

| Command     | Description                   |
| ----------- | ----------------------------- |
| `scan`      | Build ServerModel (read-only) |
| `diagnose`  | Full diagnostic with findings |
| `discover`  | Filesystem project discovery  |
| `recommend` | Ranked solutions              |
| `generate`  | Create nginx configs          |
| `apply`     | Apply configs (with backup)   |
| `check`     | CI/CD one-shot command        |

## Extension Points

To add a new check category:

1. Create `analyzer/{category}_auditor.py`
2. Implement `audit() -> list[Finding]`
3. Call from `cli.py diagnose()` command
4. Findings are merged with other auditors
