"""Remediation downtime impact classifier.

Maps rule IDs and finding titles to downtime impact categories so
the report can distinguish "Needs downtime" findings from those
that only require a config reload or no service interruption at all.
"""


def classify_impact(rule_id: str, finding_title: str) -> str:
    """Return a downtime-impact label for a given rule + title.

    Returns one of:
        "no_downtime"
        "reload_only"
        "restart_service"
        "app_deploy_required"
        "possible_downtime"
        "unknown"
    """
    rid = (rule_id or "").upper()
    title_lower = (finding_title or "").lower()

    # ── Nginx config changes → reload only ──────────────────────────────
    nginx_keywords = {"nginx", "dotfile", "redirect", "ssl", "protect", "block", "rootcause", "public"}
    if any(kw in rid.lower() for kw in nginx_keywords):
        return "reload_only"
    if rid.startswith(("NGX-DEEP", "HTTP-PROBE", "NGX-SEC", "ROOTCAUSE-")):
        return "reload_only"

    # ── SSH config changes → no downtime ────────────────────────────────
    if "SSH" in rid or "password" in title_lower:
        return "no_downtime"

    # ── Dependency updates → app deploy required ────────────────────────
    dependency_keywords = {"UPDATE", "OUTDATED", "VULNERABILITY"}
    if any(kw in rid for kw in dependency_keywords):
        return "app_deploy_required"
    if any(mgr in title_lower for mgr in ("npm", "composer", "pip")):
        return "app_deploy_required"

    # ── MySQL / Redis restart → possible downtime ───────────────────────
    if rid.startswith(("MYSQL", "REDIS")):
        return "possible_downtime"

    # ── System service restart → restart_service ────────────────────────
    if rid.startswith("SYSTEMD") or "service" in title_lower or "restart" in title_lower:
        return "restart_service"

    return "unknown"
