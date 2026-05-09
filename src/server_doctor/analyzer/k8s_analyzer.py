"""Kubernetes ingress analyzer for server-doctor.

Analyzes Kubernetes ingress resources, cert-manager certificates, and
nginx-ingress controller configuration.
"""

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from server_doctor.model.finding import Finding
from server_doctor.model.evidence import Evidence, Severity


@dataclass
class K8sIngressInfo:
    """Kubernetes ingress information."""
    name: str
    namespace: str
    host: str
    paths: list[dict] = field(default_factory=list)
    tls_secret: str | None = None
    annotations: dict[str, str] = field(default_factory=dict)
    source_file: str = ""


@dataclass
class K8sCertManagerInfo:
    """cert-manager certificate information."""
    name: str
    namespace: str
    domains: list[str] = field(default_factory=list)
    ready: bool = False
    renewal_time: str | None = None
    issuer: str = ""


class K8sAnalyzer:
    """Analyze Kubernetes ingress and cert-manager configuration."""
    
    def __init__(self, kubeconfig: str | None = None, context: str | None = None):
        self.kubeconfig = kubeconfig
        self.context = context
        self._kubectl_available = self._check_kubectl()
    
    def _check_kubectl(self) -> bool:
        """Check if kubectl is available."""
        try:
            subprocess.run(
                ["kubectl", "version"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _kubectl(self, args: list[str]) -> dict[str, Any] | None:
        """Run kubectl command and return parsed JSON output."""
        if not self._kubectl_available:
            return None
        
        cmd = ["kubectl"]
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            cmd.extend(["--context", self.context])
        cmd.extend(args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        
        return None
    
    def analyze(self) -> list[Finding]:
        """Run full Kubernetes analysis and return findings."""
        findings: list[Finding] = []
        
        if not self._kubectl_available:
            findings.append(Finding(
                id="K8S-001",
                severity=Severity.INFO,
                confidence=0.9,
                condition="kubectl not available",
                cause="kubectl command not found or not configured.",
                evidence=[Evidence(
                    source_file="k8s-analyzer",
                    line_number=1,
                    excerpt="kubectl not in PATH or kubeconfig not set",
                    command="kubectl version",
                )],
                treatment="Install kubectl or configure kubeconfig to enable K8s analysis.",
                impact=["Kubernetes ingress configuration cannot be analyzed"],
            ))
            return findings
        
        # Analyze ingresses
        findings.extend(self._analyze_ingresses())
        
        # Analyze cert-manager certificates
        findings.extend(self._analyze_certificates())
        
        # Analyze nginx-ingress controller
        findings.extend(self._analyze_ingress_controller())
        
        return findings
    
    def _analyze_ingresses(self) -> list[Finding]:
        """Analyze ingress resources."""
        findings: list[Finding] = []
        
        # Get all ingresses
        ingresses = self._kubectl([
            "get", "ingress", "--all-namespaces",
            "-o", "json"
        ])
        
        if not ingresses:
            return findings
        
        for ing in ingresses.get("items", []):
            metadata = ing.get("metadata", {})
            spec = ing.get("spec", {})
            
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            annotations = metadata.get("annotations", {})
            
            # Check for nginx-ingress annotations
            rewrite_target = annotations.get("nginx.ingress.kubernetes.io/rewrite-target")
            ssl_redirect = annotations.get("nginx.ingress.kubernetes.io/ssl-redirect")
            rate_limit = annotations.get("nginx.ingress.kubernetes.io/limit-rps")
            
            # Check rules
            rules = spec.get("rules", [])
            tls = spec.get("tls", [])
            
            for rule in rules:
                host = rule.get("host", "")
                paths = rule.get("http", {}).get("paths", [])
                
                # Check for missing TLS
                has_tls = any(host in tls_entry.get("hosts", []) for tls_entry in tls)
                
                if host and not has_tls:
                    findings.append(Finding(
                        id="K8S-002",
                        severity=Severity.WARNING,
                        confidence=0.85,
                        condition=f"Ingress {name} missing TLS for {host}",
                        cause=f"Ingress defines host {host} but no TLS secret is configured.",
                        evidence=[Evidence(
                            source_file=f"ingress/{namespace}/{name}",
                            line_number=1,
                            excerpt=f"host: {host}, tls: none",
                            command=f"kubectl get ingress {name} -n {namespace}",
                        )],
                        treatment="Add TLS configuration to ingress spec.tls with a valid secretName.",
                        impact=["Unencrypted traffic to production hostname"],
                    ))
                
                # Check for rate limiting
                if not rate_limit and host:
                    findings.append(Finding(
                        id="K8S-003",
                        severity=Severity.INFO,
                        confidence=0.7,
                        condition=f"Ingress {name} has no rate limiting",
                        cause="No nginx.ingress.kubernetes.io/limit-rps annotation set.",
                        evidence=[Evidence(
                            source_file=f"ingress/{namespace}/{name}",
                            line_number=1,
                            excerpt="annotations: " + str(list(annotations.keys())),
                            command=f"kubectl get ingress {name} -n {namespace} -o yaml",
                        )],
                        treatment="Add rate limiting: nginx.ingress.kubernetes.io/limit-rps: '10'",
                        impact=["No DDoS protection on ingress endpoint"],
                    ))
                
                # Check for rewrite-target (potential issues)
                if rewrite_target and rewrite_target != "/":
                    for path in paths:
                        path_value = path.get("path", "")
                        if path_value and not path_value.endswith("/(.*)"):
                            findings.append(Finding(
                                id="K8S-004",
                                severity=Severity.WARNING,
                                confidence=0.75,
                                condition=f"Ingress {name} rewrite-target may misroute",
                                cause=f"rewrite-target={rewrite_target} with path={path_value} may not capture subpaths.",
                                evidence=[Evidence(
                                    source_file=f"ingress/{namespace}/{name}",
                                    line_number=1,
                                    excerpt=f"path: {path_value}, rewrite-target: {rewrite_target}",
                                    command=f"kubectl get ingress {name} -n {namespace}",
                                )],
                                treatment="Use path: /api/(.*) with rewrite-target: /$1 for proper capture.",
                                impact=["Subpath routing may fail (e.g., /api/v1 returns 404)"],
                            ))
        
        return findings
    
    def _analyze_certificates(self) -> list[Finding]:
        """Analyze cert-manager certificates."""
        findings: list[Finding] = []
        
        certs = self._kubectl([
            "get", "certificates", "--all-namespaces",
            "-o", "json"
        ])
        
        if not certs:
            return findings
        
        for cert in certs.get("items", []):
            metadata = cert.get("metadata", {})
            status = cert.get("status", {})
            
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                          for c in status.get("conditions", []))
            
            if not ready:
                findings.append(Finding(
                    id="K8S-005",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    condition=f"Certificate {name} not ready",
                    cause="cert-manager certificate is not in Ready state.",
                    evidence=[Evidence(
                        source_file=f"certificate/{namespace}/{name}",
                        line_number=1,
                        excerpt=f"ready: {ready}, conditions: {status.get('conditions', [])}",
                        command=f"kubectl describe certificate {name} -n {namespace}",
                    )],
                    treatment="Check cert-manager logs and DNS validation for ACME challenges.",
                    impact=["TLS termination will fail for affected domains"],
                ))
        
        return findings
    
    def _analyze_ingress_controller(self) -> list[Finding]:
        """Analyze nginx-ingress controller configuration."""
        findings: list[Finding] = []
        
        # Check for ingress-nginx pods
        pods = self._kubectl([
            "get", "pods", "--all-namespaces",
            "-l", "app.kubernetes.io/name=ingress-nginx",
            "-o", "json"
        ])
        
        if not pods or not pods.get("items"):
            findings.append(Finding(
                id="K8S-006",
                severity=Severity.INFO,
                confidence=0.8,
                condition="nginx-ingress controller not detected",
                cause="No ingress-nginx pods found with standard labels.",
                evidence=[Evidence(
                    source_file="k8s-cluster",
                    line_number=1,
                    excerpt="No pods with label app.kubernetes.io/name=ingress-nginx",
                    command="kubectl get pods --all-namespaces -l app.kubernetes.io/name=ingress-nginx",
                )],
                treatment="If using nginx-ingress, ensure it's labeled correctly.",
                impact=["Ingress controller health cannot be verified"],
            ))
            return findings
        
        # Check controller configmap
        configmap = self._kubectl([
            "get", "configmap", "-n", "ingress-nginx",
            "ingress-nginx-controller",
            "-o", "json"
        ])
        
        if configmap:
            data = configmap.get("data", {})
            
            # Check for recommended settings
            if data.get("ssl-protocols") is None:
                findings.append(Finding(
                    id="K8S-007",
                    severity=Severity.WARNING,
                    confidence=0.7,
                    condition="nginx-ingress TLS protocols not restricted",
                    cause="ssl-protocols not set in ingress-nginx ConfigMap.",
                    evidence=[Evidence(
                        source_file="configmap/ingress-nginx/ingress-nginx-controller",
                        line_number=1,
                        excerpt="ssl-protocols: not set",
                        command="kubectl get configmap ingress-nginx-controller -n ingress-nginx",
                    )],
                    treatment="Set ssl-protocols: 'TLSv1.2 TLSv1.3' in ConfigMap data.",
                    impact=["Legacy TLS versions (1.0, 1.1) may be enabled"],
                ))
        
        return findings


class K8sAuditAction:
    """Action to run Kubernetes analysis."""
    
    def __init__(self, kubeconfig: str | None = None, context: str | None = None):
        self.analyzer = K8sAnalyzer(kubeconfig, context)
    
    def audit(self) -> list[Finding]:
        """Run full Kubernetes audit."""
        return self.analyzer.analyze()
