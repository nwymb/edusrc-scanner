"""L3 被动检测 — 敏感路径探测

对 L2 产出的每个存活 Target URL 拼接敏感路径字典做 HEAD/GET 探测。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urljoin

import aiohttp
import yaml

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

with open(_PROJECT_ROOT / "data" / "dicts" / "sensitive_paths.yaml", "r") as _f:
    _PATH_DICT = yaml.safe_load(_f)
    _PATHS: list[dict] = _PATH_DICT.get("paths", [])

_SEVERITY_MAP = {
    "info": VulnSeverity.INFO,
    "low": VulnSeverity.LOW,
    "medium": VulnSeverity.MEDIUM,
    "high": VulnSeverity.HIGH,
}

_HIT_STATUS = {200, 204, 301, 302, 307}  # 403=WAF拦截，不算命中


async def _probe_url(base_url: str, entry: dict, session) -> Finding | None:
    """对单个 Target 探测单条路径"""
    path = entry["path"]
    target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    try:
        resp = await session.head(target_url)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("sensitive_head_failed target=%s error=%s", target_url, e)
        return None

    status = resp.status
    if status not in _HIT_STATUS:
        return None

    body_snippet = ""
    content_length = resp.headers.get("Content-Length", "")
    try:
        cl = int(content_length) if content_length else 0
    except ValueError:
        cl = 0

    # 200 必须拿到 body 内容才能确认，防止 catch-all 路由误报
    if status == 200:
        if cl == 0:
            # Content-Length 为 0 大概率是空洞响应，补一发 GET 最终确认
            pass
        try:
            r = await session.get(target_url)
            body = await r.text()
            body_snippet = body[:512]
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("sensitive_get_failed target=%s error=%s", target_url, e)
        # GET 无 body → 跳过（catch-all 路由）
        if not body_snippet.strip():
            return None
        # body 是 HTML 页面但无敏感内容特征 → catch-all 误报
        if _is_catchall_html(body_snippet, entry):
            return None

    evidence = f"HTTP {status}"
    if body_snippet:
        evidence += f" body_preview={body_snippet[:120]}"
    if cl:
        evidence += f" size={cl}B"

    return Finding(
        url=target_url,
        vuln_type="sensitive_path",
        severity=_SEVERITY_MAP.get(entry.get("severity", "info"), VulnSeverity.INFO),
        title=entry.get("description", path),
        evidence=evidence,
        confidence=0.75 if body_snippet else 0.60,
        source=FindingSource.L3_PASSIVE,
        source_module="sensitive_path",
        raw={
            "category": entry.get("category", ""),
            "status_code": status,
            "body_preview": body_snippet[:200],
        },
    )


# HTML 白名单: 这些路径本身就应该返回 HTML 页面（但必须验证指纹）
_HTML_WHITELIST = {"/swagger-ui.html", "/swagger-resources", "/doc.html",
                   "/druid/index.html", "/api-docs", "/v2/api-docs", "/v3/api-docs"}

# 精准指纹: 白名单路径必须在 body 中包含至少一个特征关键词才算真命中
_VULN_FINGERPRINTS: dict[str, list[str]] = {
    "/swagger-ui.html":    ["swagger-ui", "swagger"],
    "/swagger-resources":  ["swagger"],
    "/doc.html":           ["knife4j", "swagger", "接口文档"],
    "/druid/index.html":   ["druid stat", "druid", "datasource", "sql stat",
                            "active thread"],
    "/api-docs":           ["openapi", "swagger", "paths", "definitions",
                            "info", "components"],
    "/v2/api-docs":        ["swagger", "paths", "definitions"],
    "/v3/api-docs":        ["openapi", "paths", "components"],
}


def _is_catchall_html(body: str, entry: dict) -> bool:
    """判断响应是否为 catch-all 路由 / SPA 幽灵 200 的 HTML 页面。

    真实敏感文件 (.env, backup.sql 等) 永远不会是完整 HTML 页面。
    白名单路径 (Swagger, Druid) 即使返回 HTML 也必须验证组件指纹。
    """
    bl = body.strip()
    bl_lower = bl[:200].lower()

    # 不是 HTML → 放行
    if not bl_lower.startswith(("<!doctype", "<html", "<head", "<body",
                                 "<meta", "<title", "<link", "<script")):
        return False

    # 极短 body 可能是真实敏感文件内容（如 ref: refs/heads/master）
    if len(bl) < 30:
        return False

    path = entry.get("path", "")
    if path in _HTML_WHITELIST:
        # 白名单路径需验证指纹: body 必须含组件特征词
        markers = _VULN_FINGERPRINTS.get(path, [])
        if markers:
            full_lower = bl.lower()
            for m in markers:
                if m.lower() in full_lower:
                    return False  # 指纹命中 → 真漏洞
            return True  # 白名单路径但无指纹 → SPA 幽灵 200

    # 非 HTML 路径返回了完整 HTML 页面 → catchall 误报
    return True


@register("sensitive_path")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    if not targets:
        logger.info("sensitive_path_skip", reason="no_targets")
        return {"findings": []}

    logger.info("sensitive_path_start", target_count=len(targets),
                path_count=len(_PATHS))

    sem = asyncio.Semaphore(5)
    findings: list[Finding] = []

    async def probe_target(target: dict):
        url = target.get("url", "")
        if not url:
            return
        async with sem:
            for entry in _PATHS:
                finding = await _probe_url(url, entry, session)
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
        sev = f.severity.value
        by_sev[sev] = by_sev.get(sev, 0) + 1

    logger.info("sensitive_path_done", total_findings=len(findings), by_severity=by_sev)

    return {"findings": [asdict(f) for f in findings]}
