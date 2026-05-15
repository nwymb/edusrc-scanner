"""L4 主动验证 — 未授权访问检测

探测已知的后台/管理面板端点是否可无需认证直接访问。
对每个 Target 尝试访问常见管理路径，检测响应是否包含后台管理内容。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from urllib.parse import urljoin

import aiohttp

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

# 通用未授权访问探测端点
_UNAUTH_PATHS = [
    "/admin/", "/admin/index.php", "/admin/login.aspx",
    "/manager/", "/manage/", "/console/", "/dashboard/",
    "/system/", "/backend/", "/panel/",
    "/druid/index.html", "/druid/login.html",
    "/swagger-ui.html", "/swagger-ui/index.html",
    "/actuator", "/actuator/health",
    "/api-docs", "/v2/api-docs",
    "/phpinfo.php", "/info.php",
    "/.env",
    "/elfinder/", "/filemanager/",
    "/phpmyadmin/", "/phpMyAdmin/", "/adminer.php",
    "/manager/html", "/host-manager/html", "/manager/status",
]

# 后台内容特征词
_ADMIN_BODY_KEYWORDS = [
    "后台管理", "管理中心", "系统管理", "控制台",
    "dashboard", "admin panel", "control panel",
    "用户管理", "角色管理", "权限管理",
    "系统设置", "网站设置",
    "user management", "role management",
    "logout", "退出登录", "注销",
]

# 强证据关键词 (命中即 HIGH)
_STRONG_KEYWORDS = [
    "用户列表", "文章管理", "内容管理",
    "系统信息", "数据库管理", "数据备份",
    "user list", "content management",
]


def _score_admin_body(body: str) -> tuple[int, list[str]]:
    body_lower = body.lower()
    hits = [kw for kw in _ADMIN_BODY_KEYWORDS if kw.lower() in body_lower]
    return len(hits), hits


def _score_strong(body: str) -> list[str]:
    body_lower = body.lower()
    return [kw for kw in _STRONG_KEYWORDS if kw.lower() in body_lower]


async def _probe_unauth(base_url: str, path: str, session) -> Finding | None:
    target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    try:
        resp = await session.get(target_url)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("unauth_get_failed url=%s error=%s", target_url, e)
        return None

    if resp.status in {401, 403}:
        return None

    location = resp.headers.get("Location", "").lower()
    if resp.status in {301, 302, 307} and any(
        kw in location for kw in ("login", "signin", "auth")
    ):
        return None

    try:
        body = await resp.text()
        body = body[:32768]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("unauth_body_failed url=%s error=%s", target_url, e)
        return None

    kw_count, kw_hits = _score_admin_body(body)
    strong_hits = _score_strong(body)

    if kw_count < 3 and not strong_hits:
        return None

    severity = VulnSeverity.HIGH if strong_hits else VulnSeverity.MEDIUM
    confidence = 0.80 if strong_hits else 0.60

    return Finding(
        url=target_url,
        vuln_type="unauth",
        severity=severity,
        title=f"未授权访问: {path}",
        evidence=f"HTTP {resp.status} admin_keywords={kw_hits[:5]}"
                f"{' strong=' + str(strong_hits) if strong_hits else ''}",
        confidence=confidence,
        source=FindingSource.L4_ACTIVE,
        source_module="unauth_check",
        raw={
            "endpoint": path,
            "status_code": resp.status,
            "admin_keywords": kw_hits[:10],
            "strong_evidence": strong_hits,
        },
    )


@register("unauth_check")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    if not targets:
        logger.info("unauth_check_skip", reason="no_targets")
        return {"findings": []}

    logger.info("unauth_check_start", target_count=len(targets),
                path_count=len(_UNAUTH_PATHS))

    sem = asyncio.Semaphore(5)
    findings: list[Finding] = []

    async def probe_target(target: dict):
        url = target.get("url", "")
        if not url:
            return
        async with sem:
            for path in _UNAUTH_PATHS:
                finding = await _probe_unauth(url, path, session)
                if finding is not None:
                    findings.append(finding)
                await asyncio.sleep(0.2)
            await asyncio.sleep(0.3)

    task_limit = min(len(targets), 10)
    for i in range(0, len(targets), task_limit):
        batch = targets[i:i + task_limit]
        await asyncio.gather(*[probe_target(t) for t in batch])

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    logger.info("unauth_check_done", total_findings=len(findings), by_severity=by_sev)

    return {"findings": [asdict(f) for f in findings]}
