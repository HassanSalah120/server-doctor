"""Deduplication and Ranking Engine for Findings."""

import re

from server_doctor.model.evidence import Severity
from server_doctor.model.finding import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Combine, deduplicate, and rank findings from multiple sources.
    
    This function:
    1. Maps missing IDs using condition patterns.
    2. Canonicalizes overlapping rule families (e.g., SSH-2 -> HOST-002).
    3. Groups findings by (rule_id, condition).
    4. Merges evidence for duplicate findings.
    5. Applies instance numbering (e.g., NGX002-1, NGX002-2).
    6. Performs cross-linking (Root Cause Analysis).
    """
    if not findings:
        return []

    # Rule ID map (Centralized)
    rule_map = {
        "Backup configuration": "NGX001",
        "Duplicate server_name": "NGX002",
        "PHP-FPM socket not found": "NGX003",
        "Laravel root misconfigured": "NGX004",
        "Missing try_files": "NGX005",
        "Nginx config variables": "NGX006",
        "sites-enabled only contains symlinks": "NGX007",
        "Default nginx site still enabled": "NGX008",
        # Modular checks (to be expanded)
        "PHP version consistency": "NGX100",
        "Multiple PHP versions": "NGX100",
        "Mixed PHP versions": "NGX101",
        ".env file may be exposed": "NGX200",
        "Sensitive path": "NGX210",
        "Port 443 without SSL directive": "NGX201",
        "SSL enabled without certificate": "NGX202",
        "Insecure security headers": "SEC001",
        "HSTS missing": "SEC002",
        "X-Frame-Options missing": "SEC003",
    }

    # Canonical ID mapping: legacy rule IDs -> canonical replacements
    CANONICAL_MAP = {
        "SSH-2": "HOST-002",       # SSH password auth -> host security
        "OPS-SSH-5": "HOST-004",   # SSH TCP forwarding -> host security
    }

    # Semantic condition normalizer: maps known semantically identical conditions
    # to a canonical form for deduplication (e.g., "is allowed" == "is enabled")
    _CONDITION_NORMALIZER: dict[str, str] = {
        "SSH TCP forwarding is enabled": "SSH TCP forwarding is allowed",
    }

    # 1. Assign Rule IDs and Deduplicate
    deduped: list[Finding] = []
    seen_keys: dict[tuple[str, str], Finding] = {} # (rule_id, condition) -> Finding
    
    for f in findings:
        # Resolve ID if it's default
        current_id = f.id
        if current_id == "NGX000":
            for pattern, rid in rule_map.items():
                if pattern.lower() in f.condition.lower():
                    current_id = rid
                    break
        
        # Canonicalize overlapping rule families
        current_id = CANONICAL_MAP.get(current_id, current_id)
        
        # Normalize semantically equivalent conditions
        norm_condition = _CONDITION_NORMALIZER.get(f.condition, f.condition)
        
        # Use (id, condition) as deduplication key
        key = (current_id, norm_condition)
        
        if key in seen_keys:
            # Merge evidence into existing finding
            base = seen_keys[key]
            for ev in f.evidence:
                # Check for exact evidence duplicate (file + line)
                is_dup = any(
                    e.source_file == ev.source_file and 
                    e.line_number == ev.line_number and
                    e.excerpt == ev.excerpt
                    for e in base.evidence
                )
                if not is_dup:
                    base.evidence.append(ev)
            
            # Keep higher severity if different
            severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
            if severity_order[f.severity] < severity_order[base.severity]:
                base.severity = f.severity
        else:
            f.id = current_id # Provisional ID
            seen_keys[key] = f
            deduped.append(f)
    
    # 2. Instance counters with deterministic/stable ordering across scans.
    # Preserve explicit IDs like CERTBOT-4 / SYSTEMD-1 and suffix only collisions.
    numbering_order = sorted(deduped, key=_finding_signature)

    explicit_id_total: dict[str, int] = {}
    for f in numbering_order:
        if _has_explicit_numeric_suffix(f.id):
            explicit_id_total[f.id] = explicit_id_total.get(f.id, 0) + 1

    explicit_id_seen: dict[str, int] = {}
    instance_counters: dict[str, int] = {}
    for f in numbering_order:
        if _has_explicit_numeric_suffix(f.id):
            # Keep first instance of explicit ID untouched, suffix subsequent ones.
            total = explicit_id_total.get(f.id, 1)
            if total > 1:
                explicit_id_seen[f.id] = explicit_id_seen.get(f.id, 0) + 1
                if explicit_id_seen[f.id] > 1:
                    f.id = f"{f.id}.{explicit_id_seen[f.id]}"
            continue
        instance_counters[f.id] = instance_counters.get(f.id, 0) + 1
        f.id = f"{f.id}-{instance_counters[f.id]}"
    
    # 3. ROOT CAUSE CHAINING: 
    # Link side-effects to primary causes (e.g., Backup files -> Duplicate server_name)
    _apply_root_cause_linking(deduped)
    
    # 4. Final Sorting (Critical -> Warning -> Info)
    return sorted(
        deduped, 
        key=lambda x: (
            0 if x.severity == Severity.CRITICAL else 
            1 if x.severity == Severity.WARNING else 2,
            x.id
        )
    )


def _apply_root_cause_linking(findings: list[Finding]) -> None:
    """Analyze findings to find parent-child relationships."""
    
    # Relationship: NGX001 (Backup Config) causes many others
    backup_findings = [f for f in findings if "NGX001" in f.id]
    if backup_findings:
        backup_files = set()
        for bf in backup_findings:
            backup_files.update({ev.source_file for ev in bf.evidence if ev.source_file != "nginx.conf"})
        
        for f in findings:
            # Duplicate server_name or PHP socket mismatch might be caused by backups
            if any(prefix in f.id for prefix in ["NGX002", "NGX003"]):
                from_backup = any(ev.source_file in backup_files for ev in f.evidence)
                
                if from_backup:
                    f.derived_from = "NGX001"
                    f.severity = Severity.INFO
                    f.cause = f"{f.cause}. This is likely a side-effect of backup files being enabled (NGX001)."
                    f.treatment = "Resolve parent finding NGX001 first."


def _has_explicit_numeric_suffix(finding_id: str) -> bool:
    """Return True when the finding id already ends with '-<number>'."""
    return bool(re.fullmatch(r".+-\d+(?:\.\d+)?", finding_id))


def _finding_signature(finding: Finding) -> tuple[str, str, str, int, str]:
    """Deterministic sort key used for stable ID suffix assignment."""
    severity_rank = {
        Severity.CRITICAL: 0,
        Severity.WARNING: 1,
        Severity.INFO: 2,
    }.get(finding.severity, 3)
    if finding.evidence:
        ev = sorted(
            finding.evidence,
            key=lambda item: (item.source_file, item.line_number, item.excerpt),
        )[0]
        source_file = ev.source_file
        line_number = ev.line_number
        excerpt = ev.excerpt
    else:
        source_file = ""
        line_number = 0
        excerpt = ""
    return (finding.id, str(severity_rank), finding.condition, source_file, line_number, excerpt)
