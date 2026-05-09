"""AI-driven infrastructure diagnosis engine.

Produces structured diagnosis reports from scan findings.

Current implementation: rule-based engine.
LLM-ready: swap RuleBasedProvider for LLMProvider without refactoring.

Public API:
    generate_diagnosis(findings, topology, score, history) -> DiagnosisReport
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from server_doctor.analyzer.finding_correlation import CorrelationEngine, SynthesizedFinding
from server_doctor.engine.remediation import RemediationGenerator
from server_doctor.engine.remediation_classifier import classify_impact
from server_doctor.engine.root_cause import correlate_root_causes as correlate_root_causes_records
from server_doctor.model.server import ServerModel


# ─── Data Models ───────────────────────────────────────────────────────────────


@dataclass
class RemediationStep:
    """A single step in the remediation plan."""

    priority: int
    title: str
    description: str
    effort: str  # "low", "medium", "high"
    category: str  # "security", "performance", "architecture", "app"
    phase: int = 1  # 1: High risk/low effort, 2: Medium risk, 3: Cleanup
    estimated_time: str = "15m"
    requires_downtime: bool = False
    is_auto_fixable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "title": self.title,
            "description": self.description,
            "effort": self.effort,
            "category": self.category,
            "phase": self.phase,
            "estimated_time": self.estimated_time,
            "requires_downtime": self.requires_downtime,
            "is_auto_fixable": self.is_auto_fixable,
        }


@dataclass
class RiskItem:
    """A prioritized risk entry."""

    severity: str
    title: str
    finding_id: str
    impact: str
    confidence: float
    fix_effort: str = "Medium"
    is_auto_fixable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "finding_id": self.finding_id,
            "impact": self.impact,
            "confidence": self.confidence,
            "fix_effort": self.fix_effort,
            "is_auto_fixable": self.is_auto_fixable,
        }


@dataclass
class DiagnosisReport:
    """Complete AI-generated diagnosis report."""

    root_cause: str
    top_risks: list[RiskItem]  # Replaced risk_prioritization, limit to top 3
    health_summary: str
    remediation_plan: list[RemediationStep]
    confidence: float
    correlations: list[SynthesizedFinding] = field(default_factory=list)
    category_breakdown: dict[str, Any] = field(default_factory=dict)
    environment_summary: dict[str, Any] = field(default_factory=dict)
    auto_fix_candidates: list[str] = field(default_factory=list)
    generated_by: str = "rule-based"

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.root_cause,
            "top_risks": [r.to_dict() for r in self.top_risks],
            "health_summary": self.health_summary,
            "remediation_plan": [s.to_dict() for s in self.remediation_plan],
            "confidence": self.confidence,
            "correlations": [c.__dict__ for c in self.correlations],
            "category_breakdown": self.category_breakdown,
            "environment_summary": self.environment_summary,
            "auto_fix_candidates": self.auto_fix_candidates,
            "generated_by": self.generated_by,
        }


# ─── Provider Protocol (LLM-ready) ────────────────────────────────────────────


@dataclass
class DiagnosisContext:
    """All context needed to generate a diagnosis."""

    findings: list[Any]
    topology: dict[str, Any]
    score: int
    history: Any = None

    def to_prompt_context(self) -> dict[str, Any]:
        """Serialize to a format suitable for LLM prompts."""
        if hasattr(self.topology, "__dict__"):
            # It's a model
            return {
                "score": self.score,
                "total_findings": len(self.findings),
                "findings_by_severity": self._group_by_severity(),
                "topology_stats": {}, # Should map from model if needed
                "domains": [s.server_names[0] for s in self.topology.nginx.servers if s.server_names] if self.topology.nginx else [],
            }
        
        return {
            "score": self.score,
            "total_findings": len(self.findings),
            "findings_by_severity": self._group_by_severity(),
            "topology_stats": self.topology.get("stats", {}),
            "domains": self.topology.get("domains", []),
        }

    def _group_by_severity(self) -> dict[str, int]:
        groups: dict[str, int] = {}
        for f in self.findings:
            sev = getattr(f, "severity", None)
            sev_str = sev.value if hasattr(sev, "value") else str(sev)
            groups[sev_str] = groups.get(sev_str, 0) + 1
        return groups


@runtime_checkable
class DiagnosisProvider(Protocol):
    """Protocol for diagnosis providers. Implement for LLM integration."""

    def generate(self, context: DiagnosisContext) -> DiagnosisReport:
        """Generate diagnosis from context."""
        ...


# ─── Rule-Based Provider ──────────────────────────────────────────────────────


class RuleBasedProvider:
    """Rule-based diagnosis engine.

    Groups findings by category, identifies dominant patterns,
    and generates structured remediation plans from finding.treatment fields.
    """

    SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
    EFFORT_MAP = {
        "security": "medium",
        "performance": "low",
        "architecture": "high",
        "app": "medium",
    }

    def generate(self, context: DiagnosisContext) -> DiagnosisReport:
        findings = context.findings
        score = context.score
        # Convert dict topology to ServerModel only when it actually looks like a ServerModel shape.
        # The web/AI layer also passes compact dict snapshots (e.g. {"stats": {...}}) which should
        # remain dicts.
        topology_model = context.topology
        if isinstance(context.topology, dict):
            looks_like_server_model = any(
                key in context.topology
                for key in ("hostname", "nginx", "os", "services", "projects", "runtime")
            )
            if looks_like_server_model:
                try:
                    topology_model = ServerModel(**context.topology)
                except TypeError:
                    topology_model = context.topology

        if not findings:
            return DiagnosisReport(
                root_cause="No issues detected. Infrastructure appears healthy.",
                top_risks=[],
                health_summary=f"Health score: {score}/100. No findings to report.",
                remediation_plan=[],
                confidence=1.0,
                category_breakdown={},
                generated_by="rule-based",
            )

        correlations: list = []
        remediation_gen = None
        if isinstance(topology_model, ServerModel):
            # 1. Run Correlation Engine (topology-aware)
            correlation_engine = CorrelationEngine(findings, topology_model)
            correlations = correlation_engine.correlate()

            # 2. Run Remediation Generator (Topology-Aware)
            remediation_gen = RemediationGenerator(topology_model)

        # 3. Run root cause correlation (works on rule_id-based findings;
        #    adapt Finding objects with duck-typed rule_id/severity fields)
        #    This runs regardless of topology type because it only needs findings.
        rc_findings = [
            _RootCauseAdapter(f) for f in findings
        ]
        root_causes = correlate_root_causes_records(rc_findings)
        for rc in root_causes:
            rc_support = set(rc.supporting_rule_ids)
            if any(set(c.supporting_rule_ids) == rc_support for c in correlations):
                continue
            correlations.append(
                SynthesizedFinding(
                    correlation_id=rc.id,
                    root_cause_hypothesis=rc.hypothesis,
                    blast_radius=rc.title,
                    severity=rc.severity,
                    supporting_rule_ids=rc.supporting_rule_ids,
                    confidence=rc.confidence,
                    fix_bundle=[
                        {"step": step, "effort": "medium"}
                        for step in rc.recommended_next_steps
                    ],
                )
            )

        # Group findings by category
        categories = self._categorize_findings(findings)
        category_breakdown = {
            cat: len(items) for cat, items in categories.items()
        }

        # Build risk prioritization (Phase 3: prefer correlations)
        risks = self._build_risk_list(findings, correlations, topology_model)

        # Generate root cause narrative (Phase 3: context-aware)
        root_cause = self._generate_root_cause(categories, score, correlations)

        # Generate health summary
        health_summary = self._generate_health_summary(
            findings, score, context.topology
        )

        # Generate remediation plan (Phase 3: topology-aware)
        remediation = self._generate_remediation_plan(findings, categories, correlations, remediation_gen)

        # Confidence based on findings consistency
        confidence = self._compute_confidence(findings, score, correlations)

        # Environment summary
        topology_dict = context.topology if isinstance(context.topology, dict) else {}
        env_summary = {
            "os": topology_dict.get("os_info", "Unknown"),
            "nginx": topology_dict.get("nginx_version", "Unknown"),
            "domains": topology_dict.get("stats", {}).get("domains", 0),
            "routes": topology_dict.get("stats", {}).get("routes", 0),
            "mode": topology_dict.get("mode", "Unknown"),
        }

        # Auto-fix candidates (heuristics based on check IDs)
        auto_fix_ids = {"SEC-HEAD-1", "NGX-SEC-2", "NGX-SEC-3", "NGX002", "NGX008"}
        auto_fix = [
            getattr(f, "condition", "Unknown issue") 
            for f in findings 
            if getattr(f, "id", "") in auto_fix_ids
        ]

        return DiagnosisReport(
            root_cause=root_cause,
            top_risks=risks[:3],  # Limit to top 3
            health_summary=health_summary,
            remediation_plan=remediation,
            confidence=confidence,
            correlations=correlations,
            category_breakdown=category_breakdown,
            environment_summary=env_summary,
            auto_fix_candidates=auto_fix,
            generated_by="rule-based",
        )

    def _categorize_findings(
        self, findings: list[Any]
    ) -> dict[str, list[Any]]:
        """Group findings into categories based on finding ID prefix."""
        cats: dict[str, list] = {
            "security": [],
            "performance": [],
            "architecture": [],
            "app": [],
            "maintenance": [],
            "reliability": [],
        }
        for f in findings:
            fid = getattr(f, "id", "").upper()
            condition = (getattr(f, "condition", "") or "").lower()

            # Security
            if any(fid.startswith(p) for p in ("SEC", "NGX-SEC", "SSH", "HTTP-PROBE-005", "HTTP-PROBE-003", "HTTP-PROBE-004")):
                cats["security"].append(f)
            elif fid.startswith("DNS-TLS") or fid.startswith("TLS"):
                cats["security"].append(f)
            elif any(kw in condition for kw in ("composer.json", ".env", "dotfile", "password", "exposed")):
                cats["security"].append(f)
            elif fid.startswith("SC-DEP-003"):
                cats["security"].append(f)

            # Maintenance (outdated deps, pending updates)
            elif fid.startswith("SC-DEP") or "UPDATE" in fid or "OUTDATED" in fid or fid.startswith("VULNERABILITY"):
                cats["maintenance"].append(f)

            # Reliability
            elif fid.startswith(("RES-", "LOG-", "LOG-NGX", "LOG-PHP", "LOG-DOCKER")):
                cats["reliability"].append(f)

            # Performance
            elif fid.startswith("NGX-PERF") or fid.startswith("PERF"):
                cats["performance"].append(f)

            # App
            elif fid.startswith(("LARAVEL", "PHPFPM", "HTTP-PROBE-006")):
                cats["app"].append(f)

            # Architecture (everything else)
            else:
                cats["architecture"].append(f)

        # Remove empty categories
        return {k: v for k, v in cats.items() if v}

    def _build_risk_list(self, findings: list[Any], correlations: list[SynthesizedFinding], topology: Any) -> list[RiskItem]:
        """Build prioritized risk list sorted by severity. Prefers correlations."""
        seen_risk_keys: set[tuple[str, str]] = set()
        risks = []
        
        def _add_risk(severity: str, title: str, finding_id: str, impact: str, confidence: float, fix_effort: str, is_auto_fixable: bool) -> None:
            key = (finding_id, title)
            if key in seen_risk_keys:
                return
            seen_risk_keys.add(key)
            risks.append(RiskItem(
                severity=severity, title=title, finding_id=finding_id,
                impact=impact, confidence=confidence, fix_effort=fix_effort,
                is_auto_fixable=is_auto_fixable,
            ))
        
        # Add correlated risks first (Phase 3)
        for c in correlations:
            _add_risk(
                severity=c.severity,
                title=c.root_cause_hypothesis,
                finding_id=c.correlation_id,
                impact=c.blast_radius,
                confidence=c.confidence,
                fix_effort=c.fix_bundle[0].get("effort", "Medium").capitalize() if c.fix_bundle else "Medium",
                is_auto_fixable=False,
            )

        # Add isolated findings
        correlated_rule_ids = set()
        for c in correlations:
            correlated_rule_ids.update(c.supporting_rule_ids)

        for f in findings:
            fid = getattr(f, "id", "")
            if fid in correlated_rule_ids:
                continue
            if (fid, getattr(f, "condition", "Unknown issue")) in seen_risk_keys:
                continue
                
            sev = getattr(f, "severity", None)
            sev_str = sev.value if hasattr(sev, "value") else str(sev)
            impacts = getattr(f, "impact", [])
            impact_str = impacts[0] if impacts else self._compute_blast_radius(f, topology)

            _add_risk(
                severity=sev_str,
                title=getattr(f, "condition", "Unknown issue"),
                finding_id=fid,
                impact=impact_str,
                confidence=getattr(f, "confidence", 0.5),
                fix_effort=self.EFFORT_MAP.get(getattr(f, "category", "app"), "Medium").capitalize(),
                is_auto_fixable=fid in {"SEC-HEAD-1", "NGX-SEC-2", "NGX-SEC-3", "NGX002", "NGX008"},
            )

        risks.sort(key=lambda r: self.SEVERITY_ORDER.get(r.severity, 99))
        return risks

    def _generate_root_cause(
        self, categories: dict[str, list], score: int, correlations: list[SynthesizedFinding]
    ) -> str:
        """Generate a root cause narrative from categorized findings and correlations."""
        parts = []

        if correlations:
            # Use correlations as primary root cause narrative
            parts.append(f"Diagnosis suggests {len(correlations)} key architectural issues.")
            for c in correlations:
                parts.append(c.root_cause_hypothesis)
        else:
            if score < 40:
                parts.append(
                    "The infrastructure has significant issues requiring immediate attention."
                )
            elif score < 70:
                parts.append(
                    "The infrastructure has moderate issues that should be addressed."
                )
            else:
                parts.append(
                    "The infrastructure is generally healthy with some items to review."
                )

            # Identify dominant problem area
            dominant = max(categories, key=lambda k: len(categories[k]))
            count = len(categories[dominant])
            if count > 0:
                parts.append(
                    f"The primary area of concern is {dominant} "
                    f"with {count} finding(s)."
                )

        # Note critical findings (limit length)
        criticals = []
        for cat_findings in categories.values():
            for f in cat_findings:
                sev = getattr(f, "severity", None)
                if hasattr(sev, "value") and sev.value == "critical":
                    criticals.append(getattr(f, "condition", ""))
        if criticals:
            parts.append(
                f"Critical flags: {'; '.join(criticals[:2])}."
            )

        return " ".join(parts)

    def _generate_health_summary(
        self,
        findings: list[Any],
        score: int,
        topology: Any,
    ) -> str:
        """Generate health summary with topology context."""
        if hasattr(topology, "__dict__"):
            # It's a model
            domains = len(topology.nginx.servers) if topology.nginx else 0
            # Rough estimate of routes
            routes = sum(len(s.locations) for s in topology.nginx.servers) if topology.nginx else 0
        else:
            stats = topology.get("stats", {})
            domains = stats.get("domains", 0)
            routes = stats.get("routes", 0)

        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = getattr(f, "severity", None)
            sev_str = sev.value if hasattr(sev, "value") else str(sev)
            sev_counts[sev_str] = sev_counts.get(sev_str, 0) + 1

        parts = [f"Health Score: {score}/100."]
        parts.append(
            f"Infrastructure: {domains} domain(s), {routes} route(s)."
        )
        sev_parts = [
            f"{count} {sev}" for sev, count in sorted(sev_counts.items())
        ]
        if sev_parts:
            parts.append(f"Findings: {', '.join(sev_parts)}.")

        return " ".join(parts)

    def _generate_remediation_plan(
        self,
        findings: list[Any],
        categories: dict[str, list],
        correlations: list[SynthesizedFinding],
        remediation_gen: RemediationGenerator | None,
    ) -> list[RemediationStep]:
        """Generate ordered remediation steps (topology-aware)."""
        steps: list[RemediationStep] = []
        seen_step_text: set[str] = set()
        priority = 1
        
        correlated_rule_ids = set()
        for c in correlations:
            correlated_rule_ids.update(c.supporting_rule_ids)
            # Add correlation fix bundle
            for i, fix in enumerate(c.fix_bundle):
                description = fix["step"]
                step_key = f"{c.correlation_id}::{description}"
                if step_key in seen_step_text:
                    continue
                seen_step_text.add(step_key)
                if remediation_gen:
                    description = remediation_gen.wrap_fix(description)
                steps.append(
                    RemediationStep(
                        priority=priority,
                        title=f"{c.correlation_id} - Step {i+1}",
                        description=description,
                        effort=fix.get("effort", "medium"),
                        category="architecture",
                        phase=1 if c.severity == "high" else 2,
                        requires_downtime=classify_impact(c.correlation_id, fix.get("step", "")) in {"restart_service", "app_deploy_required", "possible_downtime"}
                    )
                )
                priority += 1

        # Process critical findings first, then warnings, then info
        for sev_target in ["critical", "warning", "info"]:
            for cat_name, cat_findings in categories.items():
                for f in cat_findings:
                    if getattr(f, "rule_id", "") in correlated_rule_ids:
                        continue # Skip isolated findings that are part of a correlation
                        
                    sev = getattr(f, "severity", None)
                    sev_str = sev.value if hasattr(sev, "value") else str(sev)
                    if sev_str != sev_target:
                        continue

                    treatment = getattr(f, "treatment", "")
                    if not treatment:
                        continue

                    description = treatment
                    if remediation_gen:
                        description = remediation_gen.wrap_fix(description)

                    # Calculate phase
                    if sev_str == "critical":
                        phase = 1
                    elif sev_str == "warning" and cat_name == "security":
                        phase = 1
                    elif sev_str == "warning":
                        phase = 2
                    else:
                        phase = 3
                        
                    is_auto_fixable = getattr(f, "id", "") in {"SEC-HEAD-1", "NGX-SEC-2", "NGX-SEC-3", "NGX002", "NGX008"}

                    steps.append(
                        RemediationStep(
                            priority=priority,
                            title=getattr(f, "condition", "Fix issue"),
                            description=description,
                            effort=self.EFFORT_MAP.get(cat_name, "medium"),
                            category=cat_name,
                            phase=phase,
                            estimated_time="5m" if is_auto_fixable else "15m",
                            requires_downtime=classify_impact(getattr(f, "rule_id", "") or getattr(f, "id", ""), getattr(f, "condition", "")) in {"restart_service", "app_deploy_required", "possible_downtime"} and not str(getattr(f, "rule_id", "") or "").startswith("DNS"),
                            is_auto_fixable=is_auto_fixable,
                        )
                    )
                    priority += 1

        return steps

    def _compute_blast_radius(self, finding: Any, topology: Any) -> str:
        """Compute the blast radius of a single finding based on topology."""
        if not hasattr(finding, "evidence") or not finding.evidence:
            return "Entire server"

        # If any finding is critical security but not specific to nginx, it's server-wide
        fid = getattr(finding, "id", "").upper()
        if fid.startswith("SEC-AUTH") or fid.startswith("SEC-SSH") or "SSH" in getattr(finding, "cause", ""):
            return "Entire server (System-wide risk)"

        # Try to find the affected server block
        affected_domains = set()
        affected_paths = set()

        # Normalize topology for easier access
        nginx = getattr(topology, "nginx", None)
        if not nginx:
            return "Entire server"

        for ev in finding.evidence:
            if not hasattr(ev, "source_file") or not ev.source_file:
                continue

            # Match source_file of server/location blocks
            found_match = False
            for s in nginx.servers:
                if s.source_file == ev.source_file:
                    found_match = True
                    if s.server_names:
                        affected_domains.add(s.server_names[0])
                    else:
                        affected_domains.add("default_server")

                    for l in s.locations:
                        if l.source_file == ev.source_file:
                            # If finding is inside or near this location
                            if l.line_number <= ev.line_number <= l.line_number + 20:
                                affected_paths.add(l.path)
            
            if not found_match and ("/etc/nginx" in ev.source_file or "nginx" in ev.source_file.lower()):
                 return "All Nginx services"

        if affected_domains:
            domain_str = ", ".join(sorted(list(affected_domains)))
            if affected_paths:
                path_str = f" at paths: {', '.join(sorted(list(affected_paths)))}"
                return f"Affected domains: {domain_str}{path_str}"
            return f"Affected domains: {domain_str}"

        return "Potential infrastructure degradation"

    def _compute_confidence(self, findings: list[Any], score: int, correlations: list[SynthesizedFinding]) -> float:
        """Compute overall diagnosis confidence."""
        if not findings and not correlations:
            return 1.0

        weights = []
        if findings:
            weights.extend([getattr(f, "confidence", 0.5) for f in findings])
        if correlations:
            weights.extend([c.confidence for c in correlations])
            
        avg = sum(weights) / len(weights) if weights else 0.5

        # Boost confidence if score is extreme
        if score >= 90 or score <= 20:
            avg = min(1.0, avg + 0.1)

        return round(avg, 2)


# ─── Public API ────────────────────────────────────────────────────────────────

# Default provider instance
_default_provider: DiagnosisProvider = RuleBasedProvider()


def generate_diagnosis(
    findings: list[Any],
    topology: dict[str, Any],
    score: int,
    history: Any = None,
    *,
    provider: DiagnosisProvider | None = None,
) -> DiagnosisReport:
    """Generate an AI-driven diagnosis report.

    Args:
        findings: List of Finding objects from the scan.
        topology: Topology snapshot dict.
        score: Overall health score (0-100).
        history: Optional historical trend data.
        provider: Optional custom provider (defaults to RuleBasedProvider).

    Returns:
        DiagnosisReport with root cause, risks, remediation plan.
    """
    ctx = DiagnosisContext(
        findings=findings,
        topology=topology,
        score=score,
        history=history,
    )
    engine = provider or _default_provider
    return engine.generate(ctx)


class _RootCauseAdapter:
    """Adapts a Finding object to be compatible with correlate_root_causes (which expects FindingRecord-like objects)."""

    def __init__(self, finding: Any) -> None:
        self.rule_id = getattr(finding, "id", "") or getattr(finding, "rule_id", "")
        self.title = getattr(finding, "condition", "") or getattr(finding, "title", "")
        self.description = getattr(finding, "cause", "") or getattr(finding, "description", "")
        self.evidence_ref = ""
        self.evidence_json = ""
        sev = getattr(finding, "severity", None)
        self.severity = sev.value if hasattr(sev, "value") else str(sev)

    def __repr__(self) -> str:
        return f"<RootCauseAdapter rule_id={self.rule_id} severity={self.severity}>"
