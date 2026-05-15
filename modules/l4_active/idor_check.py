"""L4 主动验证 — IDOR 越权检测

模式匹配：从 Target URL 中提取数值型资源 ID，尝试访问相邻 ID，
比较响应差异判断是否存在越权访问风险。
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict

import aiohttp

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

# IDOR-prone URL patterns: path segments or query params with numeric IDs
_ID_PATTERNS = [
    r"/(\d{1,10})(?=/|\.|$)",
    r"[?&](id|uid|userId|user_id)=(\d{1,10})",
    r"/(user|users|member|order|article|post|page|file|doc|download)/(\d{1,10})",
]

# Response difference indicators (PII in body suggests different user data)
_DIFF_INDICATORS = [
    "username", "姓名", "手机号", "email", "邮箱",
    "身份证", "学号", "工号", "地址", "电话",
]


def _extract_ids(url: str) -> list[tuple[str, int]]:
    """从 URL 提取资源 ID 候选项，返回 (context, id_value)"""
    results: list[tuple[str, int]] = []
    for pattern in _ID_PATTERNS:
        for m in re.finditer(pattern, url, re.IGNORECASE):
            groups = m.groups()
            if len(groups) >= 2 and groups[-1].isdigit():
                context = groups[0] if len(groups) > 1 else "id"
                id_val = int(groups[-1])
                results.append((context, id_val))
            elif len(groups) == 1 and groups[0].isdigit():
                results.append(("id", int(groups[0])))
    return results


def _build_adjacent_url(url: str, context: str, old_id: int, new_id: int) -> str:
    """构造修改 ID 后的相邻 URL"""
    return re.sub(
        rf"({re.escape(context)}[=/]?|(?<!/))\b{old_id}\b",
        lambda m: m.group(0).replace(str(old_id), str(new_id)),
        url, count=1
    )


async def _check_idor(base_url: str, id_info: tuple[str, int], session) -> Finding | None:
    """探测单个 ID 参数是否存在越权"""
    context, id_val = id_info
    adj_id = id_val + 1

    try:
        resp_orig = await session.get(base_url)
        body_orig = await resp_orig.text()
        body_orig = body_orig[:16384]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("idor_orig_failed url=%s error=%s", base_url, e)
        return None

    adj_url = _build_adjacent_url(base_url, context, id_val, adj_id)
    if adj_url == base_url:
        return None

    try:
        resp_adj = await session.get(adj_url)
        body_adj = await resp_adj.text()
        body_adj = body_adj[:16384]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("idor_adj_failed url=%s error=%s", adj_url, e)
        return None

    if resp_adj.status != 200 or resp_orig.status != 200:
        return None

    if body_adj == body_orig:
        return None

    size_diff = abs(len(body_adj) - len(body_orig))
    if size_diff < 100:
        return None

    hits = [kw for kw in _DIFF_INDICATORS if kw.lower() in body_adj.lower()]
    confidence = 0.65 if hits else 0.40

    if confidence < 0.5 and size_diff < 500:
        return None

    return Finding(
        url=base_url,
        vuln_type="idor",
        severity=VulnSeverity.HIGH if hits else VulnSeverity.MEDIUM,
        title=f"疑似 IDOR: {context}={id_val} → {adj_id}",
        evidence=f"orig_len={len(body_orig)} adj_len={len(body_adj)}"
                f" diff={size_diff}"
                f"{' indicators=' + ','.join(hits[:3]) if hits else ''}",
        confidence=confidence,
        source=FindingSource.L4_ACTIVE,
        source_module="idor_check",
        raw={
            "param": context,
            "original_id": id_val,
            "tested_id": adj_id,
            "adjacent_url": adj_url,
            "orig_len": len(body_orig),
            "adj_len": len(body_adj),
            "indicators": hits[:5],
        },
    )


@register("idor_check")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    if not targets:
        logger.info("idor_check_skip", reason="no_targets")
        return {"findings": []}

    id_targets: list[tuple[str, list[tuple[str, int]]]] = []
    for t in targets:
        url = t.get("url", "")
        ids = _extract_ids(url)
        if ids:
            id_targets.append((url, ids))

    if not id_targets:
        logger.info("idor_check_skip", reason="no_id_urls")
        return {"findings": []}

    logger.info("idor_check_start", id_url_count=len(id_targets))

    sem = asyncio.Semaphore(3)
    findings: list[Finding] = []

    async def probe_idor(url: str, ids: list[tuple[str, int]]):
        async with sem:
            for id_info in ids[:2]:
                finding = await _check_idor(url, id_info, session)
                if finding is not None:
                    findings.append(finding)
                await asyncio.sleep(0.5)

    await asyncio.gather(*[probe_idor(url, ids) for url, ids in id_targets[:20]])

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    logger.info("idor_check_done", total_findings=len(findings), by_severity=by_sev)

    return {"findings": [asdict(f) for f in findings]}
