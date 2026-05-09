"""Topology snapshot and diff utilities."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from server_doctor.model.server import ServerModel


def build_topology_snapshot(model: ServerModel, ws_inventory: list | None = None) -> dict[str, Any]:
    """Build a deterministic topology snapshot for export/diff."""
    ws_inventory = ws_inventory or []
    routes = _build_routes(model, ws_inventory)
    public_bindings = _build_public_bindings(model)
    ws_routes = _build_ws_routes(ws_inventory)

    os_model = getattr(model, "os", None)
    os_info_str = os_model.full_name if os_model else "unknown"
    nginx_model = getattr(model, "nginx", None)
    nginx_version = getattr(nginx_model, "version", "unknown") if nginx_model else "unknown"

    payload: dict[str, Any] = {
        "host": _as_text(getattr(model, "hostname", "")),
        "os_info": os_info_str,
        "nginx_version": nginx_version,
        "mode": _as_text(getattr(getattr(model, "nginx", None), "mode", "unknown")) or "unknown",
        "domains": sorted({r["domain"] for r in routes if r.get("domain")}),
        "routes": routes,
        "public_bindings": public_bindings,
        "ws_routes": ws_routes,
        "route_keys": [r["key"] for r in routes],
        "binding_keys": [b["key"] for b in public_bindings],
        "ws_keys": [w["key"] for w in ws_routes],
        "stats": {
            "domains": len({r["domain"] for r in routes if r.get("domain")}),
            "routes": len(routes),
            "public_bindings": len(public_bindings),
            "ws_routes": len(ws_routes),
        },
    }
    payload["signature"] = _signature(payload)
    return payload


def diff_topology(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Compare two topology snapshots and return deterministic diff."""
    if not previous:
        return {
            "has_previous": False,
            "signature_changed": False,
            "added_routes": [],
            "removed_routes": [],
            "added_bindings": [],
            "removed_bindings": [],
            "stats_delta": {},
        }

    prev_route_keys = set(previous.get("route_keys", []))
    cur_route_keys = set(current.get("route_keys", []))
    prev_binding_keys = set(previous.get("binding_keys", []))
    cur_binding_keys = set(current.get("binding_keys", []))

    prev_stats = previous.get("stats", {}) if isinstance(previous.get("stats"), dict) else {}
    cur_stats = current.get("stats", {}) if isinstance(current.get("stats"), dict) else {}
    stats_delta = {}
    for key in sorted(set(prev_stats.keys()) | set(cur_stats.keys())):
        before = int(prev_stats.get(key, 0))
        after = int(cur_stats.get(key, 0))
        stats_delta[key] = after - before

    return {
        "has_previous": True,
        "signature_changed": previous.get("signature") != current.get("signature"),
        "added_routes": sorted(cur_route_keys - prev_route_keys),
        "removed_routes": sorted(prev_route_keys - cur_route_keys),
        "added_bindings": sorted(cur_binding_keys - prev_binding_keys),
        "removed_bindings": sorted(prev_binding_keys - cur_binding_keys),
        "stats_delta": stats_delta,
    }


def _build_routes(model: ServerModel, ws_inventory: list) -> list[dict[str, Any]]:
    nginx = getattr(model, "nginx", None)
    if not nginx or not isinstance(getattr(nginx, "servers", None), list):
        return []

    upstream_map: dict[str, list[str]] = {
        upstream.name: sorted(upstream.servers)
        for upstream in (nginx.upstreams if isinstance(getattr(nginx, "upstreams", None), list) else [])
    }
    ws_keys = {
        (getattr(ws, "domain", ""), getattr(getattr(ws, "location", None), "path", ""))
        for ws in ws_inventory
    }
    out: list[dict[str, Any]] = []
    for server in nginx.servers:
        domain = _as_text(server.server_names[0]) if getattr(server, "server_names", None) else "_"
        for location in (server.locations if isinstance(getattr(server, "locations", None), list) else []):
            route_type = "proxy"
            target = (location.proxy_pass or "").strip()
            if not target:
                if location.fastcgi_pass:
                    target = location.fastcgi_pass
                    route_type = "php-fpm"
                elif location.root or server.root:
                    target = location.root or server.root or ""
                    route_type = "static"
                else:
                    continue

            resolved_targets = [target]
            if route_type == "proxy":
                upstream_name = _extract_upstream_name(target)
                if upstream_name and upstream_name in upstream_map and upstream_map[upstream_name]:
                    resolved_targets = upstream_map[upstream_name]

            for resolved in resolved_targets:
                route_type_final = "websocket" if (domain, location.path) in ws_keys else route_type
                key = f"{domain}|{location.path}|{resolved}|{route_type_final}"
                out.append(
                    {
                        "key": key,
                        "domain": domain,
                        "path": _as_text(location.path),
                        "route_type": route_type_final,
                        "target": _as_text(resolved),
                    }
                )

    out.sort(key=lambda row: row["key"])
    return out


def _build_public_bindings(model: ServerModel) -> list[dict[str, Any]]:
    services = getattr(model, "services", None)
    if not services:
        return []

    proxied_ports = _extract_nginx_backend_ports(model)
    out: list[dict[str, Any]] = []
    containers = services.docker_containers if isinstance(getattr(services, "docker_containers", None), list) else []
    for container in containers:
        for mapping in (container.ports if isinstance(getattr(container, "ports", None), list) else []):
            if mapping.host_port is None or mapping.host_ip not in {"0.0.0.0", "::"}:
                continue
            key = f"{container.name}|{mapping.host_ip}|{mapping.host_port}|{mapping.container_port}|{mapping.proto}"
            out.append(
                {
                    "key": key,
                    "container": _as_text(container.name),
                    "host_ip": _as_text(mapping.host_ip),
                    "host_port": mapping.host_port,
                    "container_port": mapping.container_port,
                    "proto": _as_text(mapping.proto),
                    "proxied": mapping.container_port in proxied_ports,
                }
            )

    out.sort(key=lambda row: row["key"])
    return out


def _build_ws_routes(ws_inventory: list) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ws in ws_inventory:
        domain = getattr(ws, "domain", "")
        path = getattr(getattr(ws, "location", None), "path", "")
        target = getattr(ws, "proxy_target", "")
        quality = getattr(ws, "handshake_quality", "UNKNOWN")
        risk = getattr(ws, "risk_level", "UNKNOWN")
        key = f"{domain}|{path}|{target}|{quality}|{risk}"
        out.append(
            {
                "key": key,
                "domain": domain,
                "path": path,
                "target": target,
                "handshake_quality": quality,
                "risk": risk,
            }
        )

    out.sort(key=lambda row: row["key"])
    return out


def _signature(payload: dict[str, Any]) -> str:
    stable = dict(payload)
    stable.pop("signature", None)
    body = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _extract_nginx_backend_ports(model: ServerModel) -> set[int]:
    ports: set[int] = set()
    nginx = getattr(model, "nginx", None)
    if not nginx or not isinstance(getattr(nginx, "servers", None), list):
        return ports

    upstream_ports: dict[str, set[int]] = {}
    for upstream in (nginx.upstreams if isinstance(getattr(nginx, "upstreams", None), list) else []):
        upstream_ports[upstream.name] = {
            p
            for p in (_extract_port_from_target(target) for target in upstream.servers)
            if p is not None
        }

    for server in nginx.servers:
        for location in (server.locations if isinstance(getattr(server, "locations", None), list) else []):
            proxy = (location.proxy_pass or "").strip()
            if not proxy:
                continue
            direct = _extract_port_from_target(proxy)
            if direct is not None:
                ports.add(direct)
                continue
            upstream_name = _extract_upstream_name(proxy)
            if upstream_name and upstream_name in upstream_ports:
                ports.update(upstream_ports[upstream_name])
    return ports


def _extract_port_from_target(target: str) -> int | None:
    cleaned = target.strip().rstrip(";")
    for prefix in ("http://", "https://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
    if cleaned.startswith("unix:"):
        return None
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if cleaned.startswith("[") and "]:" in cleaned:
        cleaned = cleaned.rsplit("]:", 1)[1]
    elif ":" in cleaned:
        cleaned = cleaned.rsplit(":", 1)[1]
    return int(cleaned) if cleaned.isdigit() else None


def _extract_upstream_name(proxy_pass: str) -> str | None:
    cleaned = proxy_pass.strip().rstrip(";")
    for prefix in ("http://", "https://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned or cleaned.startswith("["):
        return None
    return cleaned if cleaned else None


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)
