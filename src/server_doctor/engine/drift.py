"""Scan model and finding comparison helpers."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DriftItem(BaseModel):
    kind: str
    severity: str
    title: str
    before: str | None = None
    after: str | None = None


class ReportCompareResponse(BaseModel):
    current_job_id: int
    previous_job_id: int | None
    score_delta: int | None
    new_findings: list[str]
    resolved_findings: list[str]
    drift: list[DriftItem]


def diff_sets(kind: str, before: set[str], after: set[str]) -> list[DriftItem]:
    items: list[DriftItem] = []
    for value in sorted(after - before):
        items.append(
            DriftItem(
                kind=kind,
                severity="warning",
                title=f"New {kind}: {value}",
                before=None,
                after=value,
            )
        )
    for value in sorted(before - after):
        items.append(
            DriftItem(
                kind=kind,
                severity="info",
                title=f"Removed {kind}: {value}",
                before=value,
                after=None,
            )
        )
    return items


def _has_baseline_data(before: dict[str, Any] | None) -> bool:
    if not before:
        return False
    if "network_surface" not in before:
        return False
    return True


def compare_models(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[DriftItem]:
    before = before or {}
    after = after or {}
    if not _has_baseline_data(before):
        return []
    return diff_sets("public port", _public_ports(before), _public_ports(after))


def _public_ports(model: dict[str, Any]) -> set[str]:
    network = model.get("network_surface") or {}
    endpoints = network.get("endpoints") or network.get("listeners") or []
    ports: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        port = endpoint.get("port")
        protocol = endpoint.get("protocol", "tcp")
        public = endpoint.get("is_public")
        if public is None:
            public = endpoint.get("public_exposed")
        if public and port is not None:
            ports.add(f"{protocol.lower()}/{port}")
    return ports
