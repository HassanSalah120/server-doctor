"""Build a compact Nginx/application topology tree."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TopologyNode(BaseModel):
    id: str
    label: str
    kind: str
    status: str
    metadata: dict[str, str | int | bool | None] = Field(default_factory=dict)
    children: list[TopologyNode] = Field(default_factory=list)


def server_block_status(server: Any) -> str:
    ssl_enabled = bool(_get(server, "ssl_enabled", False) or _has_ssl_listen(server))
    ssl_certificate = _get(server, "ssl_certificate", None)
    locations = _get(server, "locations", []) or []
    has_proxy = any(_get(loc, "proxy_pass", None) for loc in locations)
    if ssl_enabled and not ssl_certificate:
        return "critical"
    if not _get(server, "root", None) and not has_proxy:
        return "warning"
    return "ok"


def build_nginx_topology(model: Any) -> list[TopologyNode]:
    nginx = _get(model, "nginx", {}) or {}
    servers = _get(nginx, "servers", []) or []
    projects = _get(model, "projects", []) or []
    roots = {
        _get(project, "path", ""): project
        for project in projects
        if _get(project, "path", "")
    }
    nodes: list[TopologyNode] = []
    seen_blocks: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    for idx, server in enumerate(servers):
        names = _get(server, "server_names", []) or ["default"]
        names_key = tuple(sorted(str(n) for n in names))
        listens = _get(server, "listens", []) or []
        listen_keys = tuple(
            sorted(
                "/".join(
                    str(v) for _, v in sorted(
                        d.items() if isinstance(d, dict) else {"raw": str(d)}.items()
                    )
                )
                for d in listens
            )
        )
        block_key = (names_key, listen_keys)
        if block_key in seen_blocks:
            continue
        seen_blocks.add(block_key)
        root = _get(server, "root", None)
        block = TopologyNode(
            id=f"server-block-{idx}",
            label=", ".join(str(name) for name in names),
            kind="server_block",
            status=server_block_status(server),
            metadata={
                "source_file": _get(server, "source_file", None),
                "root": root,
            },
        )
        for name in names:
            block.children.append(
                TopologyNode(
                    id=f"domain-{idx}-{name}",
                    label=str(name),
                    kind="domain",
                    status="ok",
                    metadata={},
                )
            )
        if root:
            block.children.append(_project_or_location_node(root, roots, idx, "root"))
        for loc_idx, loc in enumerate(_get(server, "locations", []) or []):
            proxy = _get(loc, "proxy_pass", None)
            fastcgi = _get(loc, "fastcgi_pass", None)
            loc_root = _get(loc, "root", None)
            alias = _get(loc, "alias", None)
            meta: dict[str, str | int | bool | None] = {
                "source_file": _get(loc, "source_file", None),
            }
            route_display = str(_get(loc, "path", "/"))
            if proxy:
                meta["target"] = str(proxy)
                meta["kind_detail"] = "proxy"
                route_display = f"{route_display}  →  {proxy}"
            elif fastcgi:
                meta["target"] = str(fastcgi)
                meta["kind_detail"] = "php_fpm"
                route_display = f"{route_display}  →  {fastcgi}"
            elif loc_root and not alias:
                project = roots.get(loc_root)
                if project:
                    target = str(_get(project, "name", None) or loc_root)
                    meta["target"] = target
                    meta["kind_detail"] = "project"
                    route_display = f"{route_display}  →  {target}"
                else:
                    meta["root"] = loc_root
                    meta["kind_detail"] = "root"
                    route_display = f"{route_display}  →  {loc_root}"
            loc_node = TopologyNode(
                id=f"location-{idx}-{loc_idx}",
                label=route_display,
                kind="location",
                status="ok",
                metadata=meta,
            )
            block.children.append(loc_node)
        nodes.append(block)
    return nodes


def _project_or_location_node(
    path: str,
    roots: dict[str, Any],
    server_idx: int,
    suffix: str,
) -> TopologyNode:
    project = roots.get(path)
    if project:
        return TopologyNode(
            id=f"project-{server_idx}-{suffix}",
            label=str(_get(project, "name", None) or path),
            kind="project",
            status="ok",
            metadata={"path": path, "type": str(_get(project, "type", ""))},
        )
    return TopologyNode(
        id=f"location-root-{server_idx}-{suffix}",
        label=path,
        kind="location",
        status="ok",
        metadata={"root": path},
    )


def _has_ssl_listen(server: Any) -> bool:
    return any(
        bool(_get(listen, "ssl", False))
        for listen in (_get(server, "listens", []) or [])
    )


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
