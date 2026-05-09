"""Kernel Limits Auditor - Validates host and nginx limit alignment."""

from __future__ import annotations

from server_doctor.engine.runtime_thresholds import env_int
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class KernelLimitsAuditor:
    """Auditor for ulimit/sysctl/network capacity posture."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model
        self._nofile_warn = env_int("server_doctor_KERNEL_NOFILE_WARN", 32768, min_value=1024, max_value=1_000_000)
        self._nofile_crit = env_int("server_doctor_KERNEL_NOFILE_CRIT", 8192, min_value=256, max_value=self._nofile_warn)
        self._somaxconn_min = env_int("server_doctor_KERNEL_SOMAXCONN_MIN", 1024, min_value=16, max_value=100000)
        self._syn_backlog_min = env_int("server_doctor_KERNEL_SYN_BACKLOG_MIN", 2048, min_value=16, max_value=500000)
        self._ephemeral_width_min = env_int("server_doctor_KERNEL_EPHEMERAL_WIDTH_MIN", 20000, min_value=1000, max_value=60000)

    def audit(self) -> list[Finding]:
        if not hasattr(self.model, "kernel_limits"):
            return []

        findings: list[Finding] = []
        findings.extend(self._check_nofile_limits())
        findings.extend(self._check_queue_backlog())
        findings.extend(self._check_ephemeral_port_range())
        findings.extend(self._check_nginx_vs_nofile_alignment())
        findings.extend(self._check_total_connection_budget())
        return findings

    def _check_nofile_limits(self) -> list[Finding]:
        soft = self.model.kernel_limits.nofile_soft
        if soft is None or soft >= self._nofile_warn:
            return []

        severity = Severity.WARNING if soft >= self._nofile_crit else Severity.CRITICAL
        return [
            Finding(
                id="KERN-1",
                severity=severity,
                confidence=0.86,
                condition=f"Low open-file limit detected (nofile soft={soft})",
                cause="Host/user soft nofile limit is below common production baselines.",
                evidence=[
                    Evidence(
                        source_file="ulimit",
                        line_number=1,
                        excerpt=f"nofile_soft={soft}, nofile_hard={self.model.kernel_limits.nofile_hard}",
                        command="ulimit -Sn; ulimit -Hn",
                    )
                ],
                treatment="Raise nofile limits (ulimit/limits.conf/systemd unit) to match connection workload.",
                impact=[
                    "Risk of `too many open files` under concurrency spikes",
                ],
            )
        ]

    def _check_queue_backlog(self) -> list[Finding]:
        somaxconn = self.model.kernel_limits.somaxconn
        syn = self.model.kernel_limits.tcp_max_syn_backlog
        if somaxconn is None and syn is None:
            return []

        if (somaxconn is None or somaxconn >= self._somaxconn_min) and (syn is None or syn >= self._syn_backlog_min):
            return []

        return [
            Finding(
                id="KERN-2",
                severity=Severity.INFO,
                confidence=0.72,
                condition="Kernel TCP backlog settings are below common production targets",
                cause=(
                    f"somaxconn={somaxconn if somaxconn is not None else 'unknown'}, "
                    f"tcp_max_syn_backlog={syn if syn is not None else 'unknown'}."
                ),
                evidence=[
                    Evidence(
                        source_file="/proc/sys/net",
                        line_number=1,
                        excerpt=f"somaxconn={somaxconn}, tcp_max_syn_backlog={syn}",
                        command="cat /proc/sys/net/core/somaxconn; cat /proc/sys/net/ipv4/tcp_max_syn_backlog",
                    )
                ],
                treatment="Tune backlog-related sysctl values to reduce SYN/drop risk at peak connection rates.",
                impact=[
                    "Higher chance of dropped or delayed connection handshakes",
                ],
            )
        ]

    def _check_ephemeral_port_range(self) -> list[Finding]:
        start = self.model.kernel_limits.ip_local_port_range_start
        end = self.model.kernel_limits.ip_local_port_range_end
        if start is None or end is None or end <= start:
            return []

        width = end - start
        if width >= self._ephemeral_width_min:
            return []

        return [
            Finding(
                id="KERN-3",
                severity=Severity.WARNING,
                confidence=0.78,
                condition=f"Narrow ephemeral port range detected ({start}-{end}, width={width})",
                cause="Limited local source-port pool can constrain high outbound connection churn.",
                evidence=[
                    Evidence(
                        source_file="/proc/sys/net/ipv4/ip_local_port_range",
                        line_number=1,
                        excerpt=f"{start} {end}",
                        command="cat /proc/sys/net/ipv4/ip_local_port_range",
                    )
                ],
                treatment="Expand ephemeral port range and review TIME_WAIT/connection reuse posture.",
                impact=[
                    "Increased risk of outbound connection exhaustion",
                ],
            )
        ]

    def _check_nginx_vs_nofile_alignment(self) -> list[Finding]:
        worker_conn = self.model.kernel_limits.nginx_worker_connections
        nofile_soft = self.model.kernel_limits.nofile_soft
        if worker_conn is None or nofile_soft is None:
            return []
        if worker_conn <= nofile_soft:
            return []

        return [
            Finding(
                id="KERN-4",
                severity=Severity.WARNING,
                confidence=0.84,
                condition="Nginx worker_connections exceeds process open-file limit",
                cause=(
                    f"worker_connections={worker_conn} but nofile_soft={nofile_soft}; "
                    "effective concurrency can be capped by OS file descriptors."
                ),
                evidence=[
                    Evidence(
                        source_file="nginx.conf",
                        line_number=1,
                        excerpt=f"worker_connections={worker_conn}, nofile_soft={nofile_soft}",
                        command="nginx -T; ulimit -Sn",
                    )
                ],
                treatment="Raise nofile limits and/or lower worker_connections to a consistent envelope.",
                impact=[
                    "Connection handling may degrade before configured nginx limits are reached",
                ],
            )
        ]

    def _check_total_connection_budget(self) -> list[Finding]:
        workers = self.model.kernel_limits.nginx_worker_processes
        per_worker = self.model.kernel_limits.nginx_worker_connections
        file_max = self.model.kernel_limits.fs_file_max
        if workers is None or per_worker is None or file_max is None:
            return []

        total_budget = workers * per_worker
        if total_budget <= file_max:
            return []

        return [
            Finding(
                id="KERN-5",
                severity=Severity.INFO,
                confidence=0.68,
                condition="Configured nginx connection budget exceeds fs.file-max",
                cause=f"workers*worker_connections={total_budget} exceeds fs.file-max={file_max}.",
                evidence=[
                    Evidence(
                        source_file="nginx.conf",
                        line_number=1,
                        excerpt=f"workers={workers}, worker_connections={per_worker}, fs.file-max={file_max}",
                        command="nginx -T; cat /proc/sys/fs/file-max",
                    )
                ],
                treatment="Reconcile nginx concurrency settings with host-wide file descriptor capacity.",
                impact=[
                    "Potential global FD pressure during traffic peaks",
                ],
            )
        ]
