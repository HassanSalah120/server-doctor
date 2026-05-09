# Changelog

All notable changes to this project will be documented in this file.

## [1.7.0] - 2026-02-06

### Added

- **Modular Audit System**: Introduced a standardized plugin architecture for server audits.
- **Laravel Readiness Scanner**: Automated verification of `APP_DEBUG`, directory permissions, and background services (Scheduler, Queue).
- **Port Usage Analyzer**: Real-time cross-referencing of Nginx proxy targets with system listening ports.
- **Security Auditor Enhancements**:
  - Recursive security header verification for nested location blocks.
  - Automatic `autoindex` (directory listing) detection and reporting.
  - Improved dotfile and Sensitive file (e.g., `.env`) leakage checks.
- **Safe-Fix Framework**: Advanced remediation system with backup creation, `nginx -t` validation, and safe dry-run modes.
- **Dynamic Scoring**: New 0-100 server health scoring based on finding weight and severity.
- **HTML Report Generation**: Premiuminteractive HTML dashboards with `--format html`.

### Changed

- **Model Refactoring**: `LocationBlock` and `ServerBlock` models now support nested structures and advanced metadata.
- **CLI Intelligence**: Added `--explain` flag for deep-dive diagnostics and `--score` for quick health checks.
- **Mocking Strategy**: Standardized testing mocks for CLI and Action components.

### Fixed

- Resolved recursive location block traversal logic in security audits.
- Fixed `AttributeError` in `LocationBlock` when accessing `autoindex`.
- Improved Windows console compatibility for Unicode/emoji output.

## [1.6.0] - 2026-02-06

### Added

- **WebSocket (WSS) Auditor**: Comprehensive auditing for WebSocket endpoints with 9 specialized checks:
  - `NGX-WSS-001`: Missing `proxy_http_version 1.1`
  - `NGX-WSS-002`: Missing `Upgrade` header
  - `NGX-WSS-003`: Missing `Connection` header
  - `NGX-WSS-004`: Proxy buffering enabled for WS
  - `NGX-WSS-005`: Low `proxy_read_timeout` (<60s)
  - `NGX-WSS-006`: Missing `X-Forwarded-*` headers
  - `NGX-WSS-007`: CORS wildcard on WS endpoint
  - `NGX-WSS-008`: WS on wildcard/default server
  - `NGX-WSS-010`: Missing dotfile protection
- **WSS Inventory Table**: Visual inventory of all detected WebSocket locations in both CLI and HTML reports.
- **Upstream Parsing**: Parser now extracts `upstream {}` blocks for advanced routing analysis.
- **WS Directive Parsing**: Location blocks now capture `proxy_http_version`, `proxy_set_header`, `proxy_buffering`, and timeout directives.

### Changed

- **Model Extensions**: `LocationBlock` extended with WebSocket-relevant fields; new `UpstreamBlock` dataclass.
- **NginxInfo**: Now stores raw `nginx -T` output and tracks `has_connection_upgrade_map` for best-practice detection.

## [1.5.0] - 2026-02-06

### Added

- **Filesystem Discovery Mode**: New `discover` command to audit the filesystem for orphaned projects not served by Nginx.
- **Web View Report**: Added `--format html` support to generate beautiful, interactive HTML dashboards for both diagnosis and inventory tasks.
- **Output Formats**: Added `--format` flag supporting `rich` (default for TTY), `plain` (text-only, pipe-friendly), `json` (machine-readable), and `html`.
- **Auto-Plain Mode**: Automatically switches to plain text output when redirection or piping is detected.

### Changed

- **Security Check Refinement (NGX200)**: logic for checking `.env` exposure is now smarter. It checks the _effective_ Nginx root and respects explicit `deny` rules, significantly reducing false positives.
- **ReportAction**: Refactored to support pluggable output formats and cleaner separation of concerns.
- **Evidence Formatting**: "Plain" mode ensures evidence references are strictly single-line for easier log parsing.
- **Remediation**: improved generation of remediation commands, particularly for moving backup files (NGX001).

### Fixed

- Fixed an `IndentationError` in `ReportAction`.
- Fixed `NameError` for `contextlib` in CLI.
- Resolved false positives for identifying project roots by strictly correlating with Nginx config.

## [1.4.0] - Previous Version

- Initial release of diagnosis and scanning features.
