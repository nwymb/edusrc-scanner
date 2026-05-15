"""L4 主动验证 — Nday POC 验证

根据 L2 fingerprint 结果匹配 POC 规则库，发送无害检测请求验证已知漏洞。
同类型漏洞通杀扩散：同一 fingerprint 下所有 POC 规则全部测试。
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

with open(_PROJECT_ROOT / "data" / "pocs" / "nday_rules.yaml", "r") as _f:
    _POC_DICT = yaml.safe_load(_f)
    _POC_RULES: list[dict] = _POC_DICT.get("rules", [])

_SEVERITY_MAP = {
    "critical": VulnSeverity.CRITICAL,
    "high": VulnSeverity.HIGH,
    "medium": VulnSeverity.MEDIUM,
    "low": VulnSeverity.LOW,
    "info": VulnSeverity.INFO,
}


def _select_pocs(fp: str) -> list[dict]:
    """根据 fingerprint 选择匹配的 POC 规则 + 通用规则 (fingerprint="")"""
    selected: list[dict] = []
    fp_lower = fp.lower()
    for rule in _POC_RULES:
        rule_fp = rule.get("fingerprint", "")
        if not rule_fp:
            selected.append(rule)
        elif rule_fp.lower() in fp_lower:
            selected.append(rule)
    return selected


def _match_response(resp, body: str, rule: dict) -> bool:
    """检查响应是否满足 POC 匹配条件 (全部条件 AND)"""
    match_cfg = rule.get("match", {})

    expected_status = match_cfg.get("status", [])
    if expected_status and resp.status not in expected_status:
        return False

    expected_headers = match_cfg.get("headers", {})
    for h_name, h_val in expected_headers.items():
        actual = ""
        for k, v in resp.headers.items():
            if k.lower() == h_name.lower():
                actual = v
                break
        if h_val.lower() not in actual.lower():
            return False

    expected_body = match_cfg.get("body", [])
    if expected_body:
        body_lower = body.lower()
        for pat in expected_body:
            if pat.lower() not in body_lower:
                return False

    return True


async def _execute_poc(base_url: str, rule: dict, session) -> Finding | None:
    """执行单条 POC 检测"""
    path = rule.get("path", "/")
    method = rule.get("method", "GET").upper()
    target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    headers = rule.get("headers") or {}
    body_template = rule.get("body", "")

    try:
        if method == "POST":
            resp = await session.post(target_url, data=body_template, headers=headers)
        else:
            resp = await session.get(target_url, headers=headers)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("nday_poc_failed rule=%s url=%s error=%s", rule["id"], target_url, e)
        return None

    try:
        body = await resp.text()
        body = body[:65536]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("nday_body_failed rule=%s url=%s error=%s", rule["id"], target_url, e)
        body = ""

    if not _match_response(resp, body, rule):
        return None

    return Finding(
        url=target_url,
        vuln_type=f"nday/{rule['id']}",
        severity=_SEVERITY_MAP.get(rule.get("severity", "medium"), VulnSeverity.MEDIUM),
        title=rule.get("name", rule["id"]),
        evidence=f"HTTP {resp.status} body_preview={body[:150]}",
        confidence=0.85 if body else 0.65,
        source=FindingSource.L4_ACTIVE,
        source_module="nday_poc",
        raw={
            "poc_id": rule["id"],
            "poc_name": rule.get("name", ""),
            "status_code": resp.status,
            "body_preview": body[:300],
        },
    )


@register("nday_poc")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    if not targets:
        logger.info("nday_poc_skip", reason="no_targets")
        return {"findings": []}

    # 按 fingerprint 去重，同框架只测一次 POC 通杀
    fp_targets: dict[str, str] = {}
    for t in targets:
        fp = t.get("fingerprint", "")
        url = t.get("url", "")
        if url and fp not in fp_targets:
            fp_targets[fp] = url
        elif url and not fp and "" not in fp_targets:
            fp_targets[""] = url

    logger.info("nday_poc_start", target_count=len(targets),
                unique_fingerprints=len(fp_targets), poc_count=len(_POC_RULES))

    sem = asyncio.Semaphore(3)
    findings: list[Finding] = []

    async def probe_fp(fp: str, url: str):
        rules = _select_pocs(fp)
        if not rules:
            return
        async with sem:
            for rule in rules:
                finding = await _execute_poc(url, rule, session)
                if finding is not None:
                    findings.append(finding)
                await asyncio.sleep(0.3)
            await asyncio.sleep(0.3)

    await asyncio.gather(*[probe_fp(fp, url) for fp, url in fp_targets.items()])

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    logger.info("nday_poc_done", total_findings=len(findings), by_severity=by_sev)

    return {"findings": [asdict(f) for f in findings]}
