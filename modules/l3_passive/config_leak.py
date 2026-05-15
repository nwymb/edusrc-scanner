"""L3 被动检测 — 框架配置缺陷检测

根据 L2 fingerprint 结果选择目标框架的端点字典，探测各端点响应是否包含
数据库连接串、密钥、debug 信息等敏感配置。
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urljoin

import aiohttp
import yaml

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

with open(_PROJECT_ROOT / "data" / "dicts" / "framework_endpoints.yaml", "r") as _f:
    _FW_DICT = yaml.safe_load(_f)
    _FRAMEWORKS: dict = _FW_DICT.get("frameworks", {})

_DEFAULT = _FRAMEWORKS.get("_default", {"paths": [], "content_markers": []})


def _picker(fp: str) -> dict:
    """根据 fingerprint 字符串选择最佳匹配的框架端点规则"""
    fp_lower = fp.lower()
    for fw_name, fw_rule in _FRAMEWORKS.items():
        if fw_name == "_default":
            continue
        if fw_name.lower() in fp_lower:
            return fw_rule
    return _DEFAULT


def _check_markers(body: str, markers: list[str]) -> list[str]:
    """返回 body 中匹配到的 content_marker 列表"""
    hits: list[str] = []
    body_lower = body.lower()
    for m in markers:
        pattern = re.escape(m.lower())
        if re.search(pattern, body_lower):
            hits.append(m)
    return hits


async def _probe_fw(url: str, path: str, markers: list[str], session) -> Finding | None:
    """探测单个框架端点"""
    target_url = urljoin(url.rstrip("/") + "/", path.lstrip("/"))

    try:
        resp = await session.get(target_url)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("config_leak_get_failed target=%s error=%s", target_url, e)
        return None

    if resp.status != 200:
        return None

    try:
        body = await resp.text()
        body = body[:65536]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("config_leak_body_failed target=%s error=%s", target_url, e)
        return None

    hits = _check_markers(body, markers)
    if not hits:
        return None

    return Finding(
        url=target_url,
        vuln_type="config_leak",
        severity=VulnSeverity.HIGH if len(hits) >= 2 else VulnSeverity.MEDIUM,
        title=f"框架配置泄露: {', '.join(hits[:3])}",
        evidence=f"matched_markers={hits} body_preview={body[:200]}",
        confidence=0.85 if len(hits) >= 2 else 0.65,
        source=FindingSource.L3_PASSIVE,
        source_module="config_leak",
        raw={
            "matched_markers": hits,
            "body_preview": body[:300],
            "endpoint": path,
        },
    )


@register("config_leak")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    if not targets:
        logger.info("config_leak_skip", reason="no_targets")
        return {"findings": []}

    logger.info("config_leak_start", target_count=len(targets))

    sem = asyncio.Semaphore(5)
    findings: list[Finding] = []

    async def probe_target(target: dict):
        url = target.get("url", "")
        fp = target.get("fingerprint", "")
        if not url:
            return

        fw_rule = _picker(fp)
        paths = fw_rule.get("paths", [])
        markers = fw_rule.get("content_markers", [])
        if not paths:
            return

        async with sem:
            for path in paths:
                finding = await _probe_fw(url, path, markers, session)
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

    logger.info("config_leak_done", total_findings=len(findings), by_severity=by_sev)

    return {"findings": [asdict(f) for f in findings]}
