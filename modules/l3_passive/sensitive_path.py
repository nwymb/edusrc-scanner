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

_HIT_STATUS = {200, 201, 202, 204, 301, 302, 307, 403}


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

    if status == 200 and cl != 0:
        try:
            r = await session.get(target_url)
            body = await r.text()
            body_snippet = body[:512]
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("sensitive_get_failed target=%s error=%s", target_url, e)

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
