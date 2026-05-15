"""L5 报告输出 — 去重合并

对 L3+L4 所有 findings 按 url+vuln_type 去重，同 key 保留最高 severity。
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from modules import register
from shared.models import VulnSeverity

_log = logging.getLogger(__name__)

_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _dedup_key(f: dict) -> str:
    return f"{f.get('url', '')}|{f.get('vuln_type', '')}"


def _sev_rank(f: dict) -> int:
    sev = f.get("severity", "info")
    if hasattr(sev, "value"):
        sev = sev.value
    return _SEVERITY_ORDER.get(str(sev), 1)


@register("dedup")
async def run(context: dict) -> dict:
    findings: list[dict] = context.get("findings", [])
    logger = context["logger"]

    if not findings:
        logger.info("dedup_skip", reason="no_findings")
        return {"findings": []}

    deduped: dict[str, dict] = {}
    for f in findings:
        key = _dedup_key(f)
        if key not in deduped or _sev_rank(f) > _sev_rank(deduped[key]):
            deduped[key] = f

    result = list(deduped.values())
    dropped = len(findings) - len(result)

    logger.info("dedup_done", total=len(findings), deduped=len(result), dropped=dropped)

    return {"findings": result}
