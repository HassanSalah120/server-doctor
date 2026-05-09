"""SAFE-APPLY-001: narrow Nginx sensitive-path blocking."""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from server_doctor.storage.models import FindingRecord, ScanJobRecord

SUPPORTED_RULE_IDS = {
    "HTTP-PROBE-005",
    "HTTP-PROBE-SOFT404",
    "API-001",
    "NGX-SEC-3",
}

MARKER_START = "# ServerDoctor SAFE-APPLY-001: block sensitive fake/static paths"
MARKER_END = "# /ServerDoctor SAFE-APPLY-001"


@dataclass
class SensitivePathApplyPlan:
    finding_id: int
    rule_id: str
    can_apply: bool
    reason: str | None
    nginx_file: str | None
    domain: str | None
    target_url: str | None
    target_path: str | None
    expected: str = "Target URL returns HTTP 403 or 404"


def build_sensitive_path_apply_plan(
    finding: FindingRecord,
    job: ScanJobRecord,
) -> SensitivePathApplyPlan:
    """Build the strict SAFE-APPLY-001 plan for one finding."""
    base_rule_id = _base_rule_id(finding.rule_id)
    if base_rule_id not in SUPPORTED_RULE_IDS:
        return _blocked_plan(finding, "Unsupported rule for SAFE-APPLY-001")

    target_url = _extract_url(finding)
    if not target_url:
        return _blocked_plan(finding, "A concrete target URL is required")

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _blocked_plan(finding, "Target URL must be HTTP or HTTPS")

    target_path = parsed.path or "/"
    if not _is_known_sensitive_path(target_path):
        return _blocked_plan(
            finding,
            "Target path is not in the SAFE-APPLY-001 sensitive-path allowlist",
            target_url=target_url,
            domain=parsed.hostname,
            target_path=target_path,
        )

    nginx_file = _resolve_nginx_file(finding, job, parsed.hostname or "")
    if not nginx_file:
        return _blocked_plan(
            finding,
            "Could not resolve an existing Nginx server-block file",
            target_url=target_url,
            domain=parsed.hostname,
            target_path=target_path,
        )

    return SensitivePathApplyPlan(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        can_apply=True,
        reason=None,
        nginx_file=nginx_file,
        domain=parsed.hostname,
        target_url=target_url,
        target_path=target_path,
    )


def build_sensitive_path_patch(
    content: str,
    plan: SensitivePathApplyPlan,
) -> tuple[str | None, str | None]:
    """Return modified content and unified diff, or a reason if patching is unsafe."""
    if not plan.can_apply or not plan.nginx_file or not plan.domain:
        return None, plan.reason or "Plan is not applicable"
    if MARKER_START in content:
        return None, "SAFE-APPLY-001 marker already exists in this file"

    snippet = _sensitive_path_snippet()
    modified = _insert_snippet_in_server_block(content, plan.domain, snippet)
    if modified is None:
        return None, f"Could not find Nginx server block for {plan.domain}"

    diff = "\n".join(
        difflib.unified_diff(
            content.splitlines(),
            modified.splitlines(),
            fromfile=plan.nginx_file,
            tofile=f"{plan.nginx_file} (patched)",
            lineterm="",
        )
    )
    return modified, diff


def validate_sensitive_path_status(status_text: str) -> bool:
    """Return True when curl output proves the path is blocked."""
    match = re.search(r"\b([1-5]\d\d)\b", status_text or "")
    if not match:
        return False
    return int(match.group(1)) in {403, 404}


def sensitive_path_validation_command(target_url: str) -> str:
    return f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time 8 {_quote(target_url)}"


def _blocked_plan(
    finding: FindingRecord,
    reason: str,
    *,
    target_url: str | None = None,
    domain: str | None = None,
    target_path: str | None = None,
) -> SensitivePathApplyPlan:
    return SensitivePathApplyPlan(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        can_apply=False,
        reason=reason,
        nginx_file=None,
        domain=domain,
        target_url=target_url,
        target_path=target_path,
    )


def _base_rule_id(rule_id: str) -> str:
    return re.sub(r"\.\d+$", "", rule_id or "unknown")


def _extract_url(finding: FindingRecord) -> str | None:
    for value in _all_text_values(finding):
        match = re.search(r"https?://[^\s;,)]+", value)
        if match:
            return match.group(0).rstrip(".")
    return None


def _all_text_values(finding: FindingRecord) -> list[str]:
    values = [
        finding.title or "",
        finding.description or "",
        finding.evidence_ref or "",
        finding.recommendation or "",
        *_evidence_values(finding),
    ]
    return [value for value in values if value]


def _evidence_values(finding: FindingRecord) -> list[str]:
    if not finding.evidence_json:
        return []
    try:
        parsed = json.loads(finding.evidence_json)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    values: list[str] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        for key in ("source_file", "excerpt", "command"):
            value = item.get(key)
            if isinstance(value, str):
                values.append(value)
    return values


def _is_known_sensitive_path(path: str) -> bool:
    normalized = "/" + path.lstrip("/")
    exact = {
        "/.env",
        "/.git/config",
        "/composer.json",
        "/composer.lock",
        "/package.json",
        "/package-lock.json",
        "/pnpm-lock.yaml",
        "/yarn.lock",
    }
    prefixes = ("/vendor/", "/storage/logs/", "/node_modules/")
    return normalized in exact or normalized.startswith(prefixes)


def _resolve_nginx_file(
    finding: FindingRecord,
    job: ScanJobRecord,
    domain: str,
) -> str | None:
    if finding.evidence_ref and _looks_like_nginx_file(finding.evidence_ref):
        return finding.evidence_ref

    for value in _evidence_values(finding):
        if _looks_like_nginx_file(value):
            return value.split(":", 1)[0]

    if not job.model_json:
        return None
    try:
        model = json.loads(job.model_json)
    except (json.JSONDecodeError, TypeError):
        return None
    servers = ((model.get("nginx") or {}).get("servers") or [])
    for server in servers:
        if not isinstance(server, dict):
            continue
        names = [str(name).lower() for name in server.get("server_names") or []]
        source_file = server.get("source_file")
        if domain.lower() in names and _looks_like_nginx_file(str(source_file)):
            return str(source_file)
    return None


def _looks_like_nginx_file(value: str) -> bool:
    return value.startswith("/etc/nginx/") and not value.rstrip("/").endswith("/etc/nginx")


def _sensitive_path_snippet() -> str:
    file_pattern = (
        r"(^|/)(\.env|\.git|composer\.(json|lock)|package(-lock)?\.json|"
        r"pnpm-lock\.yaml|yarn\.lock)$"
    )
    return f"""{MARKER_START}
location ~* {file_pattern} {{
    return 404;
}}

location ~* ^/(vendor|storage/logs|node_modules)/ {{
    return 404;
}}
{MARKER_END}"""


def _insert_snippet_in_server_block(content: str, domain: str, snippet: str) -> str | None:
    end_pos = _find_server_block_end(content, domain)
    if end_pos is None:
        return None
    indented = "\n    " + snippet.replace("\n", "\n    ") + "\n"
    return content[:end_pos] + indented + content[end_pos:]


def _find_server_block_end(content: str, domain: str) -> int | None:
    pattern = rf"server_name[^;]*\b{re.escape(domain)}\b[^;]*;"
    match = re.search(pattern, content)
    if not match:
        return None

    server_matches = list(re.finditer(r"\bserver\s*\{", content[: match.start()]))
    if not server_matches:
        return None

    server_start = server_matches[-1].start()
    brace_count = 0
    in_server = False
    for index, char in enumerate(content[server_start:], start=server_start):
        if char == "{":
            brace_count += 1
            in_server = True
        elif char == "}":
            brace_count -= 1
            if in_server and brace_count == 0:
                return index
    return None


def _quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
