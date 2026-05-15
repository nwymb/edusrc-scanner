"""L5 报告输出 — 报告生成

从去重后的 findings 生成 JSON 报告并按 severity 分类统计。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from modules import register

_log = logging.getLogger(__name__)


@register("report")
async def run(context: dict) -> dict:
    findings: list[dict] = context.get("findings", [])
    logger = context["logger"]
    config: dict = context.get("config", {})

    if not findings:
        logger.info("report_skip", reason="no_findings")
        return {"findings": []}

    # 按 severity 分组统计
    by_sev: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        if hasattr(sev, "value"):
            sev = sev.value
        by_sev[str(sev)] = by_sev.get(str(sev), 0) + 1
        vtype = f.get("vuln_type", "unknown")
        by_type[vtype] = by_type.get(vtype, 0) + 1

    # 写入报告
    output_dir = config.get("output_dir", "data/output")
    report_path = Path(output_dir) / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "summary": {
            "total": len(findings),
            "by_severity": by_sev,
            "by_type": by_type,
        },
        "findings": findings,
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                          encoding="utf-8")

    logger.info("report_done", path=str(report_path), total=len(findings),
                by_severity=by_sev)

    return {"findings": findings}
