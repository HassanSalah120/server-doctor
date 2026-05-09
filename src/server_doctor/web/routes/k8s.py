"""Kubernetes analyzer routes for server-doctor web app.

Provides web API for K8s ingress, cert-manager, and nginx-ingress analysis.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from server_doctor.analyzer.k8s_analyzer import K8sAnalyzer, K8sAuditAction
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(prefix="/k8s", tags=["kubernetes"], dependencies=[Depends(require_auth)])


class K8sScanRequest(BaseModel):
    """Kubernetes scan request."""
    kubeconfig: str | None = None
    context: str | None = None
    namespace: str | None = None


class K8sScanResponse(BaseModel):
    """Kubernetes scan response."""
    findings_count: int
    ingresses: list[dict[str, Any]]
    certificates: list[dict[str, Any]]
    findings: list[dict[str, Any]]


class K8sIngressDetail(BaseModel):
    """Kubernetes ingress detail."""
    name: str
    namespace: str
    host: str
    paths: list[dict]
    tls_configured: bool
    annotations: dict[str, str]
    issues: list[str]


@router.post("/scan", dependencies=[Depends(require_csrf)])
async def scan_kubernetes(request: K8sScanRequest) -> K8sScanResponse:
    """Scan Kubernetes cluster for ingress and cert-manager issues."""
    try:
        analyzer = K8sAnalyzer(
            kubeconfig=request.kubeconfig,
            context=request.context,
        )
        
        findings = analyzer.analyze()
        
        # Get ingress details
        ingresses = await _get_ingresses(analyzer)
        certificates = await _get_certificates(analyzer)
        
        return K8sScanResponse(
            findings_count=len(findings),
            ingresses=ingresses,
            certificates=certificates,
            findings=[
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "condition": f.condition,
                    "cause": f.cause,
                    "treatment": f.treatment,
                }
                for f in findings
            ],
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"K8s scan failed: {str(e)}")


async def _get_ingresses(analyzer: K8sAnalyzer) -> list[dict]:
    """Get ingress details from K8s."""
    ingresses = analyzer._kubectl([
        "get", "ingress", "--all-namespaces",
        "-o", "json"
    ])
    
    if not ingresses:
        return []
    
    result = []
    for ing in ingresses.get("items", []):
        metadata = ing.get("metadata", {})
        spec = ing.get("spec", {})
        
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        annotations = metadata.get("annotations", {})
        
        # Check TLS
        rules = spec.get("rules", [])
        tls = spec.get("tls", [])
        hosts = [r.get("host", "") for r in rules if r.get("host")]
        tls_hosts = []
        for tls_entry in tls:
            tls_hosts.extend(tls_entry.get("hosts", []))
        
        has_tls = all(h in tls_hosts for h in hosts if h)

        issues: list[str] = []
        if hosts and not has_tls:
            issues.append("TLS is not configured for all hosts")
        if not hosts:
            issues.append("No host rules found")

        host = hosts[0] if hosts else ""
        
        result.append({
            "name": name,
            "namespace": namespace,
            "host": host,
            "tls_configured": has_tls,
            "annotations": {
                k: v for k, v in annotations.items()
                if k.startswith("nginx.ingress.kubernetes.io/")
            },
            "paths": [
                p.get("path", "/")
                for r in rules
                for p in r.get("http", {}).get("paths", [])
            ],
            "issues": issues,
        })
    
    return result


async def _get_certificates(analyzer: K8sAnalyzer) -> list[dict]:
    """Get cert-manager certificate details."""
    certs = analyzer._kubectl([
        "get", "certificates", "--all-namespaces",
        "-o", "json"
    ])
    
    if not certs:
        return []
    
    result = []
    for cert in certs.get("items", []):
        metadata = cert.get("metadata", {})
        status = cert.get("status", {})
        spec = cert.get("spec", {})
        
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in status.get("conditions", [])
        )

        expiry = status.get("notAfter") or status.get("renewalTime") or ""
        cert_status = "Ready" if ready else "NotReady"
        
        result.append({
            "name": metadata.get("name", "unknown"),
            "namespace": metadata.get("namespace", "default"),
            "domains": spec.get("dnsNames", []),
            "ready": ready,
            "issuer": spec.get("issuerRef", {}).get("name", ""),
            "renewal_time": status.get("renewalTime"),
            "status": cert_status,
            "expiry": expiry,
        })
    
    return result


@router.get("/ingresses")
async def list_ingresses(
    namespace: str | None = None,
    kubeconfig: str | None = None,
) -> list[dict[str, Any]]:
    """List all Kubernetes ingresses."""
    analyzer = K8sAnalyzer(kubeconfig=kubeconfig)
    
    args = ["get", "ingress"]
    if namespace:
        args.extend(["-n", namespace])
    else:
        args.extend(["--all-namespaces"])
    args.extend(["-o", "json"])
    
    ingresses = analyzer._kubectl(args)
    
    if not ingresses:
        return []
    
    return [
        {
            "name": ing.get("metadata", {}).get("name"),
            "namespace": ing.get("metadata", {}).get("namespace"),
            "host": ing.get("spec", {}).get("rules", [{}])[0].get("host"),
            "class": ing.get("spec", {}).get("ingressClassName"),
        }
        for ing in ingresses.get("items", [])
    ]


@router.get("/certificates")
async def list_certificates(
    namespace: str | None = None,
    kubeconfig: str | None = None,
) -> list[dict[str, Any]]:
    """List all cert-manager certificates."""
    analyzer = K8sAnalyzer(kubeconfig=kubeconfig)
    
    args = ["get", "certificates"]
    if namespace:
        args.extend(["-n", namespace])
    else:
        args.extend(["--all-namespaces"])
    args.extend(["-o", "json"])
    
    certs = analyzer._kubectl(args)
    
    if not certs:
        return []
    
    return [
        {
            "name": cert.get("metadata", {}).get("name"),
            "namespace": cert.get("metadata", {}).get("namespace"),
            "ready": any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in cert.get("status", {}).get("conditions", [])
            ),
            "domains": cert.get("spec", {}).get("dnsNames", []),
        }
        for cert in certs.get("items", [])
    ]


@router.get("/config/ingress-nginx")
async def get_ingress_nginx_config(
    kubeconfig: str | None = None,
) -> dict[str, Any]:
    """Get nginx-ingress controller configuration."""
    analyzer = K8sAnalyzer(kubeconfig=kubeconfig)
    
    configmap = analyzer._kubectl([
        "get", "configmap", "-n", "ingress-nginx",
        "ingress-nginx-controller",
        "-o", "json"
    ])
    
    if not configmap:
        return {"error": "ConfigMap not found"}
    
    return {
        "name": configmap.get("metadata", {}).get("name"),
        "namespace": "ingress-nginx",
        "data": configmap.get("data", {}),
    }


@router.post("/validate", dependencies=[Depends(require_csrf)])
async def validate_ingress(
    namespace: str,
    ingress_name: str,
    kubeconfig: str | None = None,
) -> dict[str, Any]:
    """Validate a specific ingress configuration."""
    analyzer = K8sAnalyzer(kubeconfig=kubeconfig)
    
    # Get ingress details
    ingress = analyzer._kubectl([
        "get", "ingress", "-n", namespace, ingress_name,
        "-o", "json"
    ])
    
    if not ingress:
        raise HTTPException(status_code=404, detail="Ingress not found")
    
    # Validate
    issues = []
    metadata = ingress.get("metadata", {})
    spec = ingress.get("spec", {})
    
    # Check for TLS
    rules = spec.get("rules", [])
    tls = spec.get("tls", [])
    hosts = [r.get("host", "") for r in rules if r.get("host")]
    
    if hosts and not tls:
        issues.append("No TLS configured for HTTPS hosts")
    
    # Check annotations
    annotations = metadata.get("annotations", {})
    if not annotations.get("nginx.ingress.kubernetes.io/proxy-body-size"):
        issues.append("No proxy-body-size limit set")
    
    return {
        "name": ingress_name,
        "namespace": namespace,
        "valid": len(issues) == 0,
        "issues": issues,
    }
