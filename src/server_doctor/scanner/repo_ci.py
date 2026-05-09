from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Callable

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    DependencyManagerStatus,
    SupplyChainModel,
    SupplyChainRepoModel,
)


@dataclass(frozen=True)
class DependencyManagerRule:
    manager: str
    ecosystem: str
    indicators: tuple[str, ...]
    command: str | None
    binary: str | None
    audit_command: str | None = None


DEPENDENCY_MANAGER_RULES: tuple[DependencyManagerRule, ...] = (
    DependencyManagerRule(
        manager="npm",
        ecosystem="Node.js / JavaScript",
        indicators=("package.json", "**/package.json", "package-lock.json", "**/package-lock.json", "npm-shrinkwrap.json", "**/npm-shrinkwrap.json"),
        command="npm outdated --json",
        binary="npm",
        audit_command="npm audit --omit=dev --json",
    ),
    DependencyManagerRule(
        manager="yarn",
        ecosystem="Node.js / JavaScript",
        indicators=("yarn.lock", "**/yarn.lock", ".yarnrc", "**/.yarnrc"),
        command="yarn outdated --json",
        binary="yarn",
    ),
    DependencyManagerRule(
        manager="pnpm",
        ecosystem="Node.js / JavaScript",
        indicators=("pnpm-lock.yaml", "**/pnpm-lock.yaml", "pnpm-workspace.yaml", "**/pnpm-workspace.yaml"),
        command="pnpm outdated --format json",
        binary="pnpm",
    ),
    DependencyManagerRule(
        manager="composer",
        ecosystem="PHP",
        indicators=("composer.json", "**/composer.json", "composer.lock", "**/composer.lock"),
        command="composer outdated --format=json --direct",
        binary="composer",
    ),
    DependencyManagerRule(
        manager="pip",
        ecosystem="Python",
        indicators=("requirements.txt", "**/requirements.txt", "requirements/*.txt", "**/requirements/*.txt", "setup.py", "**/setup.py", "pyproject.toml", "**/pyproject.toml"),
        command="python -m pip list --outdated --format=json",
        binary="python",
    ),
    DependencyManagerRule(
        manager="pipenv",
        ecosystem="Python",
        indicators=("Pipfile", "**/Pipfile", "Pipfile.lock", "**/Pipfile.lock"),
        command="pipenv run pip list --outdated --format=json",
        binary="pipenv",
    ),
    DependencyManagerRule(
        manager="poetry",
        ecosystem="Python",
        indicators=("poetry.lock", "**/poetry.lock", "pyproject.toml", "**/pyproject.toml"),
        command="poetry show --outdated --format json",
        binary="poetry",
    ),
    DependencyManagerRule(
        manager="cargo",
        ecosystem="Rust",
        indicators=("Cargo.toml", "**/Cargo.toml", "Cargo.lock", "**/Cargo.lock"),
        command="cargo outdated --format json",
        binary="cargo",
    ),
    DependencyManagerRule(
        manager="gem",
        ecosystem="Ruby",
        indicators=("Gemfile", "**/Gemfile", "*.gemspec", "**/*.gemspec"),
        command="gem outdated",
        binary="gem",
    ),
    DependencyManagerRule(
        manager="bundler",
        ecosystem="Ruby",
        indicators=("Gemfile.lock", "**/Gemfile.lock", "Gemfile", "**/Gemfile"),
        command="bundle outdated --parseable",
        binary="bundle",
    ),
    DependencyManagerRule(
        manager="nuget",
        ecosystem=".NET",
        indicators=("*.sln", "**/*.sln", "*.csproj", "**/*.csproj", "packages.config", "**/packages.config", "Directory.Packages.props", "**/Directory.Packages.props"),
        command="dotnet list package --outdated --format json",
        binary="dotnet",
    ),
    DependencyManagerRule(
        manager="go modules",
        ecosystem="Go",
        indicators=("go.mod", "**/go.mod", "go.sum", "**/go.sum"),
        command="go list -m -u -json all",
        binary="go",
    ),
    DependencyManagerRule(
        manager="maven",
        ecosystem="Java",
        indicators=("pom.xml", "**/pom.xml"),
        command="mvn -q versions:display-dependency-updates",
        binary="mvn",
    ),
    DependencyManagerRule(
        manager="gradle",
        ecosystem="Java / Kotlin",
        indicators=("build.gradle", "**/build.gradle", "build.gradle.kts", "**/build.gradle.kts", "settings.gradle", "**/settings.gradle", "settings.gradle.kts", "**/settings.gradle.kts"),
        command="./gradlew -q dependencyUpdates",
        binary="sh",
    ),
    DependencyManagerRule(
        manager="ant",
        ecosystem="Java",
        indicators=("build.xml", "**/build.xml"),
        command=None,
        binary=None,
    ),
    DependencyManagerRule(
        manager="vcpkg",
        ecosystem="C++",
        indicators=("vcpkg.json", "**/vcpkg.json", "vcpkg-configuration.json", "**/vcpkg-configuration.json"),
        command="vcpkg update",
        binary="vcpkg",
    ),
    DependencyManagerRule(
        manager="conan",
        ecosystem="C++",
        indicators=("conanfile.py", "**/conanfile.py", "conanfile.txt", "**/conanfile.txt"),
        command="conan outdated . --format json",
        binary="conan",
    ),
    DependencyManagerRule(
        manager="dart pub",
        ecosystem="Dart / Flutter",
        indicators=("pubspec.yaml", "**/pubspec.yaml", "pubspec.lock", "**/pubspec.lock"),
        command="dart pub outdated --json",
        binary="dart",
    ),
    DependencyManagerRule(
        manager="swift package",
        ecosystem="Swift",
        indicators=("Package.swift", "**/Package.swift"),
        command="swift package update --dry-run",
        binary="swift",
    ),
    DependencyManagerRule(
        manager="cocoapods",
        ecosystem="iOS / Swift / Objective-C",
        indicators=("Podfile", "**/Podfile", "Podfile.lock", "**/Podfile.lock"),
        command="pod outdated --no-ansi",
        binary="pod",
    ),
    DependencyManagerRule(
        manager="carthage",
        ecosystem="iOS / Swift / Objective-C",
        indicators=("Cartfile", "**/Cartfile", "Cartfile.resolved", "**/Cartfile.resolved"),
        command="carthage outdated",
        binary="carthage",
    ),
    DependencyManagerRule(
        manager="homebrew",
        ecosystem="macOS system packages",
        indicators=("Brewfile", "**/Brewfile"),
        command="brew outdated --json=v2",
        binary="brew",
    ),
    DependencyManagerRule(
        manager="apt",
        ecosystem="Debian / Ubuntu Linux",
        indicators=("debian/control", "**/debian/control", "debian/changelog", "**/debian/changelog"),
        command="apt list --upgradable 2>/dev/null",
        binary="apt",
    ),
    DependencyManagerRule(
        manager="dnf",
        ecosystem="Fedora / RHEL",
        indicators=("*.spec", "**/*.spec"),
        command="dnf -q check-update",
        binary="dnf",
    ),
    DependencyManagerRule(
        manager="pacman",
        ecosystem="Arch Linux",
        indicators=("PKGBUILD", "**/PKGBUILD"),
        command="checkupdates",
        binary="checkupdates",
    ),
    DependencyManagerRule(
        manager="choco",
        ecosystem="Windows",
        indicators=("*.nuspec", "**/*.nuspec", "chocolateyinstall.ps1", "**/chocolateyinstall.ps1"),
        command="choco outdated --limit-output",
        binary="choco",
    ),
    DependencyManagerRule(
        manager="scoop",
        ecosystem="Windows",
        indicators=("scoop.json", "**/scoop.json", "bucket/*.json", "**/bucket/*.json"),
        command="scoop status",
        binary="scoop",
    ),
    DependencyManagerRule(
        manager="winget",
        ecosystem="Windows",
        indicators=("winget-manifest.yaml", "**/winget-manifest.yaml", "winget.yaml", "**/winget.yaml", "*.installer.yaml", "**/*.installer.yaml", "*.version.yaml", "**/*.version.yaml"),
        command="winget upgrade --accept-source-agreements --disable-interactivity",
        binary="winget",
    ),
)


@dataclass
class RepoCIScanner:
    ssh: SSHConnector
    log_fn: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        self._command_cache: dict[str, bool] = {}

    def _log(self, msg: str) -> None:
        if self.log_fn:
            self.log_fn(msg)

    def _repo_scan_workers(self) -> int:
        try:
            default = getattr(self.ssh, "_max_parallel_commands", 1) or 1
            return max(1, int(os.getenv("server_doctor_REPO_SCAN_WORKERS", str(default))))
        except ValueError:
            default = getattr(self.ssh, "_max_parallel_commands", 1) or 1
            return max(1, int(default))

    @staticmethod
    def _outdated_timeout() -> float:
        try:
            return max(5.0, float(os.getenv("server_doctor_DEPENDENCY_OUTDATED_TIMEOUT", "20")))
        except ValueError:
            return 20.0

    @staticmethod
    def _audit_timeout() -> float:
        try:
            return max(5.0, float(os.getenv("server_doctor_DEPENDENCY_AUDIT_TIMEOUT", "25")))
        except ValueError:
            return 25.0

    def _is_likely_repo(self, path: str) -> bool:
        """Check if a path looks like a code repository."""
        indicators = [
            ".git",
            ".github",
            "package.json",
            "composer.json",
            "pyproject.toml",
            "go.mod",
            "requirements.txt",
            "Dockerfile",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Cargo.toml",
            "pom.xml",
            "build.gradle",
            "Gemfile",
            "pubspec.yaml",
        ]
        checks = " || ".join(
            f"[ -e {self._shell_quote(path.rstrip('/') + '/' + indicator)} ]"
            for indicator in indicators
        )
        result = self.ssh.run(
            f"sh -lc \"{checks} && echo yes || echo no\"",
            timeout=6,
            use_sudo=False,
        )
        verdict = (result.stdout or "").strip().lower()
        if verdict.endswith("yes"):
            return True
        if verdict.endswith("no"):
            return False

        # Fallback for restricted shells / mocked environments.
        for indicator in indicators:
            candidate = f"{path.rstrip('/')}/{indicator}"
            if self.ssh.file_exists(candidate) or self.ssh.dir_exists(candidate):
                return True
        return False

    def _expand_parent_path(self, parent_path: str) -> list[str]:
        """Expand a parent directory into list of repo subdirectories."""
        try:
            quoted = self._shell_quote(parent_path.rstrip("/"))
            result = self.ssh.run(
                f"find {quoted} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null",
                timeout=8,
                use_sudo=False,
            )
            entries = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
            if not entries:
                entries = self.ssh.list_dir(parent_path)
            repos = []
            for entry in entries:
                if entry.startswith(".") or entry in {"lost+found", "tmp", "temp", "cache"}:
                    continue
                full_path = f"{parent_path.rstrip('/')}/{entry}"
                if self._is_likely_repo(full_path):
                    repos.append(full_path)
            return repos
        except Exception:
            return []

    def scan(self, repo_paths: list[str]) -> SupplyChainModel:
        enabled = bool(repo_paths)
        model = SupplyChainModel(enabled=enabled, repo_paths=repo_paths)
        targets: list[str] = []
        seen: set[str] = set()

        for raw_path in repo_paths:
            path = (raw_path or "").strip()
            if not path:
                continue

            try:
                if not self.ssh.dir_exists(path):
                    model.errors.append(f"Repo path not found or not a directory: {path}")
                    continue

                if self._is_likely_repo(path):
                    if path not in seen:
                        targets.append(path)
                        seen.add(path)
                else:
                    sub_repos = self._expand_parent_path(path)
                    if sub_repos:
                        model.notes.append(f"Auto-discovered {len(sub_repos)} repos in {path}")
                        for sub_path in sub_repos:
                            if sub_path not in seen:
                                targets.append(sub_path)
                                seen.add(sub_path)
                    else:
                        if path not in seen:
                            targets.append(path)
                            seen.add(path)

            except Exception as e:
                model.errors.append(f"Repo scan error for {path}: {e}")

        if targets:
            workers = min(self._repo_scan_workers(), len(targets))
            self._log(f"  - Supply-chain scanning {len(targets)} repo(s) with {workers} worker(s)")
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_path = {executor.submit(self._scan_single_repo, path): path for path in targets}
                for future in as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        repo = future.result()
                        model.repos.append(repo)
                        self._log(f"    - repo scanned: {path}")
                    except Exception as e:
                        model.errors.append(f"Repo scan error for {path}: {e}")
                        self._log(f"    - repo scan failed: {path}")

        return model

    def _scan_single_repo(self, path: str) -> SupplyChainRepoModel:
        """Scan a single repository path."""
        repo = SupplyChainRepoModel(path=path)
        root = path.rstrip("/")
        files = self._list_repo_files(path)
        file_set = set(files)

        for rel in files:
            lower_rel = rel.lower()
            if lower_rel.startswith(".github/workflows/") and (lower_rel.endswith(".yml") or lower_rel.endswith(".yaml")):
                repo.ci_workflows.append(f"{root}/{rel}")

        for ci_file in [".gitlab-ci.yml", "Jenkinsfile"]:
            if ci_file in file_set:
                repo.ci_system_files.append(f"{root}/{ci_file}")

        for lockfile in [
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "composer.lock",
            "poetry.lock",
            "Pipfile.lock",
            "Cargo.lock",
            "Gemfile.lock",
            "go.sum",
            "Podfile.lock",
            "Cartfile.resolved",
            "pubspec.lock",
        ]:
            if lockfile in file_set:
                repo.lockfiles.append(f"{root}/{lockfile}")

        for manifest in [
            "package.json",
            "composer.json",
            "pyproject.toml",
            "requirements.txt",
            "go.mod",
            "Cargo.toml",
            "Gemfile",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "Pipfile",
            "pubspec.yaml",
            "Package.swift",
            "Podfile",
            "Cartfile",
        ]:
            if manifest in file_set:
                repo.manifests.append(f"{root}/{manifest}")

        for rel in files:
            if "/" in rel:
                continue
            if rel.startswith("Dockerfile"):
                repo.docker_files.append(f"{root}/{rel}")
            if rel.startswith("docker-compose") and (rel.endswith(".yml") or rel.endswith(".yaml")):
                repo.docker_files.append(f"{root}/{rel}")

        self._scan_dependency_managers(path, repo, files=files)

        if not repo.ci_workflows and not repo.ci_system_files:
            repo.notes.append("No CI workflow files detected")

        return repo

    def _scan_dependency_managers(
        self,
        repo_path: str,
        repo: SupplyChainRepoModel,
        *,
        files: list[str] | None = None,
    ) -> None:
        files = files if files is not None else self._list_repo_files(repo_path)
        if not files:
            return

        detected = self._detect_dependency_managers(repo_path, files)
        if not detected:
            return

        checks_enabled = self._dependency_checks_enabled()
        for rule in DEPENDENCY_MANAGER_RULES:
            rel_files = detected.get(rule.manager)
            if not rel_files:
                continue

            status = DependencyManagerStatus(
                manager=rule.manager,
                ecosystem=rule.ecosystem,
                detected_files=sorted(rel_files),
                status="detected",
                check_command=rule.command,
                audit_command=rule.audit_command,
            )

            if not checks_enabled:
                status.error = "dependency upgrade checks disabled via server_doctor_DEPENDENCY_CHECKS=0"
                repo.dependency_managers.append(status)
                continue

            if not rule.command:
                status.status = "unsupported"
                status.error = "No standardized outdated command for this manager"
                repo.dependency_managers.append(status)
                continue

            if rule.binary and not self._command_exists(rule.binary):
                status.status = "unavailable"
                status.error = f"Command not found: {rule.binary}"
                repo.dependency_managers.append(status)
                continue

            target_dirs = self._manager_target_dirs(repo_path, status.detected_files, rule.manager)
            outdated_total = 0
            outdated_samples: list[str] = []
            check_errors: list[str] = []
            checked_targets = 0

            for target_dir in target_dirs:
                result = self._run_repo_command(
                    target_dir,
                    rule.command,
                    timeout=self._outdated_timeout(),
                )
                output = self._result_output(rule.manager, rule.command, result)
                expected_nonzero = self._is_expected_nonzero(rule.manager, rule.command, result.exit_code)

                if not output and not (result.success or expected_nonzero):
                    check_errors.append((result.stderr or "outdated check failed").strip()[:140])
                    continue

                count, sample = self._parse_outdated(rule.manager, output)
                if count is None and not (result.success or expected_nonzero):
                    check_errors.append((result.stderr or "outdated check failed").strip()[:140])
                    continue

                checked_targets += 1
                outdated_total += count or 0
                outdated_samples.extend(sample or [])

            if checked_targets == 0:
                status.status = "error"
                status.error = "; ".join(err for err in check_errors if err)[:220] or "outdated check failed"
                repo.dependency_managers.append(status)
                continue

            status.status = "checked"
            status.outdated_count = outdated_total
            status.sample = sorted(set(outdated_samples))[:5]
            if check_errors:
                status.error = "; ".join(err for err in check_errors if err)[:220]

            if rule.audit_command:
                vuln_total = 0
                vuln_samples: list[str] = []
                severity_rollup: dict[str, int] = {}
                audit_errors: list[str] = []
                audited_targets = 0

                for target_dir in target_dirs:
                    result = self._run_repo_command(
                        target_dir,
                        rule.audit_command,
                        timeout=self._audit_timeout(),
                    )
                    output = self._result_output(rule.manager, rule.audit_command, result)
                    expected_nonzero = self._is_expected_nonzero(
                        rule.manager,
                        rule.audit_command,
                        result.exit_code,
                    )

                    if not output and not (result.success or expected_nonzero):
                        audit_errors.append((result.stderr or "audit check failed").strip()[:140])
                        continue

                    count, summary, sample = self._parse_audit(rule.manager, output)
                    if count is None:
                        if not (result.success or expected_nonzero):
                            audit_errors.append((result.stderr or "audit check failed").strip()[:140])
                        continue

                    audited_targets += 1
                    vuln_total += count
                    vuln_samples.extend(sample or [])
                    for sev, val in self._parse_severity_summary(summary).items():
                        severity_rollup[sev] = severity_rollup.get(sev, 0) + val

                if audited_targets > 0:
                    status.vulnerability_count = vuln_total
                    status.vulnerability_sample = sorted(set(vuln_samples))[:5]
                    status.vulnerability_summary = self._format_severity_summary(severity_rollup)

                if audit_errors:
                    joined = "; ".join(err for err in audit_errors if err)[:220]
                    status.error = f"{status.error}; {joined}"[:220] if status.error else joined

            repo.dependency_managers.append(status)

        if repo.dependency_managers:
            managers = ", ".join(item.manager for item in repo.dependency_managers)
            repo.notes.append(f"Dependency managers detected: {managers}")

    def _list_repo_files(self, repo_path: str) -> list[str]:
        quoted = self._shell_quote(repo_path)
        cmd = (
            f"find {quoted} -maxdepth 4 "
            "\\( -type d \\( -name .git -o -name node_modules -o -name vendor -o -name .venv -o -name venv "
            "-o -name dist -o -name build -o -name target \\) -prune \\) -o "
            "-type f -print 2>/dev/null"
        )
        result = self.ssh.run(cmd, timeout=8, use_sudo=False)
        if not result.success:
            return []

        files: list[str] = []
        prefix = repo_path.rstrip("/") + "/"
        for raw in result.stdout.splitlines():
            path = raw.strip()
            if not path:
                continue
            if path.startswith(prefix):
                rel = path[len(prefix):]
            elif path == repo_path.rstrip("/"):
                continue
            else:
                rel = path.lstrip("./")
            rel = rel.replace("\\", "/").lstrip("./")
            if rel:
                files.append(rel)

        return sorted(set(files))

    def _detect_dependency_managers(
        self, repo_path: str, relative_files: list[str]
    ) -> dict[str, list[str]]:
        detected: dict[str, list[str]] = {}
        lower_paths = {path: path.lower() for path in relative_files}

        for rule in DEPENDENCY_MANAGER_RULES:
            for original, lowered in lower_paths.items():
                for pattern in rule.indicators:
                    if fnmatch(lowered, pattern.lower()):
                        detected.setdefault(rule.manager, []).append(original)
                        break

        if "npm" in detected and ("yarn" in detected or "pnpm" in detected):
            npm_files = detected["npm"]
            has_npm_lock = any(
                f.lower().endswith("package-lock.json") or f.lower().endswith("npm-shrinkwrap.json")
                for f in npm_files
            )
            if not has_npm_lock:
                detected.pop("npm", None)

        if "poetry" in detected and "pip" in detected:
            pip_files = detected["pip"]
            non_pyproject = [f for f in pip_files if not f.lower().endswith("pyproject.toml")]
            if not non_pyproject:
                detected.pop("pip", None)

        return {
            manager: sorted(
                {f"{repo_path.rstrip('/')}/{rel}" for rel in rels}
            )
            for manager, rels in detected.items()
        }

    def _dependency_checks_enabled(self) -> bool:
        value = (os.getenv("server_doctor_DEPENDENCY_CHECKS") or "1").strip().lower()
        return value not in {"0", "false", "no", "off"}

    def _command_exists(self, command: str) -> bool:
        cached = self._command_cache.get(command)
        if cached is not None:
            return cached
        result = self.ssh.run(f"command -v {command} >/dev/null 2>&1", timeout=3, use_sudo=False)
        exists = result.success
        self._command_cache[command] = exists
        return exists

    def _run_repo_command(self, repo_path: str, command: str, timeout: float = 20) -> object:
        quoted = self._shell_quote(repo_path)
        return self.ssh.run(f"cd {quoted} && {command}", timeout=timeout, use_sudo=False)

    def _manager_target_dirs(
        self,
        repo_path: str,
        detected_files: list[str],
        manager: str,
    ) -> list[str]:
        repo_root = repo_path.rstrip("/")
        system_scoped = {"apt", "dnf", "pacman", "homebrew", "choco", "scoop", "winget"}
        if manager in system_scoped:
            return [repo_root]

        dirs = {
            (file_path.rsplit("/", 1)[0] if "/" in file_path else repo_root)
            for file_path in detected_files
        }
        cleaned = sorted(d for d in dirs if d)
        return cleaned[:6] if cleaned else [repo_root]

    @staticmethod
    def _is_expected_nonzero(manager: str, command: str, exit_code: int) -> bool:
        if exit_code == 0:
            return False
        command_l = (command or "").lower()
        manager_l = (manager or "").lower()
        if manager_l == "npm" and ("outdated" in command_l or "audit" in command_l):
            return exit_code == 1
        if manager_l == "yarn" and "outdated" in command_l:
            return exit_code == 1
        return False

    def _result_output(self, manager: str, command: str, result: object) -> str:
        stdout_text = (getattr(result, "stdout", "") or "").strip()
        stderr_text = (getattr(result, "stderr", "") or "").strip()
        if stdout_text:
            return stdout_text + ("\n" + stderr_text if stderr_text else "")

        expected_nonzero = self._is_expected_nonzero(
            manager,
            command,
            int(getattr(result, "exit_code", 0) or 0),
        )
        if expected_nonzero and stderr_text:
            return stderr_text
        return ""

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    def _parse_audit(self, manager: str, output: str) -> tuple[int | None, str | None, list[str]]:
        if manager != "npm":
            return (None, None, [])

        data = self._extract_json(output)
        if not isinstance(data, dict):
            return (None, None, [])

        metadata = data.get("metadata")
        if isinstance(metadata, dict):
            vul = metadata.get("vulnerabilities")
            if isinstance(vul, dict):
                counts = {
                    "critical": int(vul.get("critical") or 0),
                    "high": int(vul.get("high") or 0),
                    "moderate": int(vul.get("moderate") or 0),
                    "low": int(vul.get("low") or 0),
                    "info": int(vul.get("info") or 0),
                }
                total = int(vul.get("total") or sum(counts.values()))
                summary = self._format_severity_summary(counts)
                sample: list[str] = []
                vulnerabilities = data.get("vulnerabilities")
                if isinstance(vulnerabilities, dict):
                    sample = sorted(vulnerabilities.keys())[:5]
                return (total, summary, sample)

        advisories = data.get("advisories")
        if isinstance(advisories, dict):
            counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0}
            sample: list[str] = []
            for _, entry in advisories.items():
                if not isinstance(entry, dict):
                    continue
                sev = str(entry.get("severity") or "").lower()
                if sev in counts:
                    counts[sev] += 1
                name = entry.get("module_name")
                if name:
                    sample.append(str(name))
            total = sum(counts.values())
            if total == 0:
                return (0, "total=0", sorted(set(sample))[:5])
            return (total, self._format_severity_summary(counts), sorted(set(sample))[:5])

        return (None, None, [])

    @staticmethod
    def _parse_severity_summary(summary: str | None) -> dict[str, int]:
        result: dict[str, int] = {}
        if not summary:
            return result
        for part in summary.split(","):
            token = part.strip()
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if not value.isdigit():
                continue
            result[key] = int(value)
        return result

    @staticmethod
    def _format_severity_summary(counts: dict[str, int]) -> str:
        order = ("critical", "high", "moderate", "low", "info")
        parts = [f"{key}={counts.get(key, 0)}" for key in order if counts.get(key, 0) > 0]
        total = sum(counts.values())
        if not parts:
            parts = [f"total={total}"]
        return ", ".join(parts)

    def _parse_outdated(self, manager: str, raw_output: str) -> tuple[int | None, list[str]]:
        output = (raw_output or "").strip()
        if not output:
            return 0, []

        if manager == "npm":
            data = self._extract_json(output)
            if isinstance(data, dict):
                names = sorted(data.keys())
                return len(names), names[:5]
            return self._parse_text_lines(output)

        if manager == "yarn":
            names: list[str] = []
            for line in output.splitlines():
                text = line.strip()
                if not text:
                    continue
                try:
                    node = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if not isinstance(node, dict):
                    continue
                if node.get("type") == "table":
                    rows = ((node.get("data") or {}).get("body") or [])
                    for row in rows:
                        if isinstance(row, list) and row:
                            names.append(str(row[0]))
            if names:
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            return self._parse_text_lines(output)

        if manager in {"pnpm", "composer", "pip", "pipenv", "poetry", "conan", "dart pub", "homebrew", "nuget"}:
            parsed = self._parse_json_manager(manager, output)
            if parsed[0] is not None:
                return parsed
            return self._parse_text_lines(output)

        if manager == "go modules":
            updates = self._parse_go_modules(output)
            if updates:
                return len(updates), updates[:5]
            return self._parse_text_lines(output)

        if manager == "apt":
            names = []
            for line in output.splitlines():
                clean = line.strip()
                if not clean or clean.lower().startswith("listing..."):
                    continue
                if "upgradable from:" not in clean:
                    continue
                pkg = clean.split("/", 1)[0].strip()
                if pkg:
                    names.append(pkg)
            dedup = sorted(set(names))
            return len(dedup), dedup[:5]

        if manager in {"dnf", "pacman", "choco", "scoop", "winget", "gem", "bundler", "maven", "gradle", "vcpkg", "swift package", "cocoapods", "carthage"}:
            return self._parse_text_lines(output)

        return self._parse_text_lines(output)

    def _parse_json_manager(self, manager: str, output: str) -> tuple[int | None, list[str]]:
        data = self._extract_json(output)
        if data is None:
            return (None, [])

        if manager in {"pip", "pipenv"}:
            if isinstance(data, list):
                names = [
                    str(item.get("name"))
                    for item in data
                    if isinstance(item, dict) and item.get("name")
                ]
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            return (None, [])

        if manager == "composer":
            if isinstance(data, dict):
                rows = data.get("installed")
                if isinstance(rows, list):
                    names = [
                        str(item.get("name"))
                        for item in rows
                        if isinstance(item, dict) and item.get("name")
                    ]
                    dedup = sorted(set(names))
                    return len(dedup), dedup[:5]
            return (None, [])

        if manager == "poetry":
            rows = []
            if isinstance(data, dict):
                rows = data.get("data") if isinstance(data.get("data"), list) else []
            elif isinstance(data, list):
                rows = data
            names = [
                str(item.get("name"))
                for item in rows
                if isinstance(item, dict) and item.get("name")
            ]
            dedup = sorted(set(names))
            return len(dedup), dedup[:5]

        if manager == "pnpm":
            if isinstance(data, list):
                names = [
                    str(item.get("name"))
                    for item in data
                    if isinstance(item, dict) and item.get("name")
                ]
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            if isinstance(data, dict):
                rows = data.get("packages") if isinstance(data.get("packages"), list) else []
                names = [
                    str(item.get("name"))
                    for item in rows
                    if isinstance(item, dict) and item.get("name")
                ]
                if names:
                    dedup = sorted(set(names))
                    return len(dedup), dedup[:5]
                keys = [k for k, v in data.items() if isinstance(v, dict)]
                if keys:
                    dedup = sorted(set(keys))
                    return len(dedup), dedup[:5]
            return (None, [])

        if manager == "conan":
            if isinstance(data, list):
                names = []
                for item in data:
                    if isinstance(item, dict):
                        name = item.get("name") or item.get("reference")
                        if name:
                            names.append(str(name))
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            if isinstance(data, dict):
                rows = data.get("results") if isinstance(data.get("results"), list) else []
                names = []
                for item in rows:
                    if isinstance(item, dict):
                        name = item.get("name") or item.get("reference")
                        if name:
                            names.append(str(name))
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            return (None, [])

        if manager == "dart pub":
            if isinstance(data, dict) and isinstance(data.get("packages"), list):
                names = []
                for item in data["packages"]:
                    if isinstance(item, dict) and item.get("package"):
                        names.append(str(item["package"]))
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            return (None, [])

        if manager == "homebrew":
            if isinstance(data, dict):
                names = []
                for key in ("formulae", "casks"):
                    rows = data.get(key)
                    if not isinstance(rows, list):
                        continue
                    for item in rows:
                        if isinstance(item, dict):
                            name = item.get("name")
                            if name:
                                names.append(str(name))
                dedup = sorted(set(names))
                return len(dedup), dedup[:5]
            return (None, [])

        if manager == "nuget":
            if not isinstance(data, dict):
                return (None, [])
            names = []
            for project in data.get("projects", []) or []:
                if not isinstance(project, dict):
                    continue
                for fw in project.get("frameworks", []) or []:
                    if not isinstance(fw, dict):
                        continue
                    for section in ("topLevelPackages", "transitivePackages"):
                        for pkg in fw.get(section, []) or []:
                            if not isinstance(pkg, dict):
                                continue
                            latest = pkg.get("latestVersion")
                            requested = pkg.get("resolvedVersion") or pkg.get("requestedVersion")
                            if latest and requested and str(latest) == str(requested):
                                continue
                            name = pkg.get("id")
                            if name:
                                names.append(str(name))
            dedup = sorted(set(names))
            return len(dedup), dedup[:5]

        return (None, [])

    def _parse_go_modules(self, output: str) -> list[str]:
        names: list[str] = []
        decoder = json.JSONDecoder()
        idx = 0
        text = output.strip()

        while idx < len(text):
            while idx < len(text) and text[idx].isspace():
                idx += 1
            if idx >= len(text):
                break
            try:
                obj, end = decoder.raw_decode(text, idx)
                idx = end
            except json.JSONDecodeError:
                break
            if isinstance(obj, dict) and obj.get("Update"):
                path = obj.get("Path")
                if path:
                    names.append(str(path))

        if names:
            return sorted(set(names))

        updates = []
        for line in output.splitlines():
            clean = line.strip()
            if "=>" in clean or "->" in clean:
                token = clean.split()[0]
                if token:
                    updates.append(token)
        return sorted(set(updates))

    def _parse_text_lines(self, output: str) -> tuple[int, list[str]]:
        lines = []
        for raw in output.splitlines():
            clean = raw.strip()
            if not clean:
                continue
            lowered = clean.lower()
            if lowered.startswith("listing..."):
                continue
            if lowered.startswith("warning:"):
                continue
            if lowered.startswith("note:"):
                continue
            if lowered.startswith("last metadata expiration check"):
                continue
            if lowered.startswith("loaded plugins:"):
                continue
            if set(clean) <= {"-", "=", " ", "\t"}:
                continue
            lines.append(clean)

        if not lines:
            return (0, [])

        names = []
        for line in lines:
            if "|" in line:
                token = line.split("|", 1)[0].strip()
                if token:
                    names.append(token)
                    continue

            token = line.split()[0]
            token = token.split("/", 1)[0]
            token = token.strip()
            if token and token not in {"Name", "Package", "Id"}:
                token = re.sub(r"^[^a-zA-Z0-9]+", "", token)
                if token:
                    names.append(token)

        dedup = sorted(set(names))
        return len(dedup), dedup[:5]

    @staticmethod
    def _extract_json(text: str) -> object | None:
        clean = (text or "").strip()
        if not clean:
            return None

        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            pass

        parsed_rows = []
        for line in clean.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed_rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not parsed_rows:
            return None
        if len(parsed_rows) == 1:
            return parsed_rows[0]
        return parsed_rows


def parse_repo_paths_from_env() -> list[str]:
    raw = (os.getenv("server_doctor_REPO_SCAN_PATHS") or "").strip()
    if raw:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        unique: list[str] = []
        seen = set()
        for p in parts:
            if p not in seen:
                unique.append(p)
                seen.add(p)
        return unique

    single = (os.getenv("server_doctor_REPO_SCAN_PATH") or "").strip()
    return [single] if single else []
