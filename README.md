# 🩺 server-doctor

> **SSH-based Server Intelligence System for Nginx + PHP Applications**

**Not just configs. Not just auditing. It understands intent.**

**server-doctor** is not simply a configuration linter. It is an intelligent diagnostic tool that scans remote servers via SSH, builds a comprehensive model of your Nginx configuration, PHP-FPM environment, and local web applications, then cross-references them to find breaking misconfigurations.

## 🚀 Key Features

- **🔍 Automatic App Detection**: Identifies Laravel, PHP MVC, SPA (Vue/React), and Static sites based on filesystem fingerprints.
- **🩺 Intelligent Diagnostics**: 20+ specialized checks including:
  - PHP-FPM socket mismatches.
  - Laravel root misconfigurations (missing `/public`).
  - Missing `try_files` for framework routing.
  - Duplicate `server_name` declarations (including hidden backup files).
- **📂 Filesystem Discovery**: Audits your server to find "orphaned" projects that exist on disk but are not served by Nginx.
- **🔗 Root Cause Chaining**: Detects when one issue (like an enabled `.bak` file) causes many others and groups them logically.
- **🛠️ Actionable Recommendations**: Every finding includes copy-pasteable shell commands (`sudo mv`, `sudo rm`) to fix the issue.
- **📊 Professional Reporting**: Beautiful terminal output leveraging the `rich` library, with support for `plain` text and `json` output for CI/CD.
- **🛡️ Security Auditor**: Checks for exposed `.env` files, valid root directives, and safe permission settings.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/HassanSalah120/server-doctor.git
cd server-doctor

# Install in development mode
pip install -e .
```

If you are running from a source checkout and want the React operator console, build the frontend once:

```bash
cd web-ui
npm ci
npm run build
cd ..
```

## 📋 Quick Start

### 1. Configure a Server Profile

Store your connection details (SSH key based auth recommended):

```bash
python -m server_doctor config add prod-server --host 1.2.3.4 --user root
```

### 2. Run a Health Check (Diagnose)

Run a full scan to find misconfigurations and security risks:

```bash
python -m server_doctor diagnose prod-server
```

### 3. Audit Filesystem (Discover)

Find "orphaned" projects that take up space but aren't active in Nginx:

```bash
python -m server_doctor discover prod-server
```

### 4. CI/CD Integration

Use plain text or JSON output formats for scripts:

```bash
# JSON output
python -m server_doctor diagnose prod-server --format json > report.json

# Clean text for logs
python -m server_doctor diagnose prod-server --format plain
```

### 5. Project Setup Wizard (Web UI)

Start the local web wizard to configure new Nginx projects:

```bash
server-doctor web --port 8765
```

Then open: **http://127.0.0.1:8765/wizard**

## Docker

Build and run the local operator console in Docker:

```bash
docker build -t server-doctor .
docker run --rm -p 8765:8765 server-doctor
```

The wizard provides a 5-step flow:

1. **Connect** - SSH into your server
2. **Domain** - Select target domain from detected server_names
3. **Project** - Define path, type (Laravel/Static/Proxy), and options
4. **Preview** - Dry-run validation and generated config snippet
5. **Apply** - Safely apply with backup + nginx -t + rollback

**Security Features:**

- 🔒 Runs on localhost only (127.0.0.1)
- 🔐 Uses your existing SSH credentials
- 📝 Typed confirmation required for apply
- 💾 Automatic backup before any change
- ↩️ Automatic rollback on nginx -t failure

## 🛠️ Diagnostic Rule IDs

| ID         | Description                                                 | Severity |
| ---------- | ----------------------------------------------------------- | -------- |
| **NGX001** | Backup configuration files are enabled (causing duplicates) | WARNING  |
| **NGX002** | Duplicate `server_name` declaration                         | INFO     |
| **NGX003** | PHP-FPM socket not found                                    | CRITICAL |
| **NGX004** | Laravel root misconfigured (`/public` missing)              | CRITICAL |
| **NGX005** | Missing `try_files` for framework routing                   | WARNING  |
| **NGX200** | `.env` file exposure risk                                   | WARNING  |

## 🛡️ Safety & Reliability

- **Non-Destructive**: Scans are strictly read-only. We use `nginx -T`, `ls`, and `cat` (for config/json files only).
- **Evidence-Based**: We don't just say "it's broken". We show you the exact file, line number, and config excerpt.
- **Compliance Aware**: Exit codes (`0`=Clean, `1`=Warning, `2`=Critical) allow easy integration into pipelines.

## 🤝 Community & Contributing

We welcome contributions of all kinds!

- **🐛 Report a Bug**: [Open an issue](https://github.com/HassanSalah120/server-doctor/issues/new?template=bug_report.md)
- **💡 Suggest a Feature**: [Request a feature](https://github.com/HassanSalah120/server-doctor/issues/new?template=feature_request.md)
- **📜 Guidelines**: Read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
- **🔒 Security**: Report vulnerabilities via our [Security Policy](SECURITY.md).

## 📜 License

Distributed under the [MIT License](LICENSE).
