"""L4 主动验证 — Nuclei 扫描引擎集成

调用系统 nuclei CLI，使用教育行业高频标签精选模板扫描，
限速 5 req/s，JSON 输出解析为 Finding 对象。
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import shutil
import tempfile
from dataclasses import asdict
from pathlib import Path

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

# 教育行业最高频 Nday 标签 (精选，不全量)
_NUCLEI_TAGS = "thinkphp,log4j,oa,spring,unauth,struts2,shiro,tomcat,laravel,django"

_BULK_SIZE = 10

_SEVERITY_MAP = {
    "critical": VulnSeverity.CRITICAL,
    "high": VulnSeverity.HIGH,
    "medium": VulnSeverity.MEDIUM,
    "low": VulnSeverity.LOW,
    "info": VulnSeverity.INFO,
}


def _find_nuclei() -> str | None:
    binary = shutil.which("nuclei")
    if binary:
        return binary
    for p in (Path.home() / "go" / "bin" / "nuclei",
              Path.home() / ".local" / "bin" / "nuclei"):
        if p.is_file():
            return str(p)
    return None


class NucleiScanner:
    """Nuclei 扫描引擎封装

    用法:
        scanner = NucleiScanner(logger, rate_limit=5)
        findings = await scanner.scan(targets)
    """

    def __init__(self, logger, rate_limit: int = 5,
                 tags: str | None = None):
        self.logger = logger
        self.rate_limit = rate_limit
        self.tags = tags or _NUCLEI_TAGS
        self._binary = _find_nuclei()

    async def scan(self, targets: list[dict]) -> list[Finding]:
        if not self._binary:
            self.logger.warning("nuclei_skip", reason="nuclei_not_found")
            return []

        urls = [t.get("url", "") for t in targets if t.get("url")]
        if not urls:
            self.logger.info("nuclei_skip", reason="no_urls")
            return []

        self.logger.info("nuclei_start", target_count=len(urls),
                         tags=self.tags, rate_limit=self.rate_limit)

        findings: list[Finding] = []
        for i in range(0, len(urls), _BULK_SIZE):
            batch = urls[i:i + _BULK_SIZE]
            findings.extend(await self._scan_batch(batch))

        self.logger.info("nuclei_done", total_findings=len(findings))
        return findings

    async def _scan_batch(self, urls: list[str]) -> list[Finding]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tf:
            tf.write("\n".join(urls))
            targets_file = tf.name

        try:
            cmd = [
                self._binary,
                "-list", targets_file,
                "-tags", self.tags,
                "-rate-limit", str(self.rate_limit),
                "-silent", "-json",
                "-no-interactsh",
                "-timeout", "10",
                "-max-host-error", "5",
                "-retries", "1",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0 and stderr:
                _log.debug("nuclei_stderr: %s",
                          stderr.decode(errors="replace")[:500])

            return self._parse_output(stdout.decode(errors="replace"))
        except (OSError, asyncio.TimeoutError) as e:
            _log.debug("nuclei_exec_failed error=%s", e)
            return []
        finally:
            Path(targets_file).unlink(missing_ok=True)

    def _parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = _json.loads(line)
            except _json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            template_id = entry.get("template-id", "unknown")
            sev_raw = info.get("severity", "info").lower()

            findings.append(Finding(
                url=entry.get("matched-at", entry.get("host", "")),
                vuln_type=f"nuclei/{template_id}",
                severity=_SEVERITY_MAP.get(sev_raw, VulnSeverity.INFO),
                title=info.get("name", template_id),
                evidence=(
                    f"template={template_id}"
                    f" matched={entry.get('matched-at', '')}"
                    f" type={entry.get('type', '')}"
                ),
                confidence=0.90,
                source=FindingSource.L4_ACTIVE,
                source_module="nuclei_scanner",
                raw={
                    "template_id": template_id,
                    "template_name": info.get("name", ""),
                    "severity": sev_raw,
                    "matched_at": entry.get("matched-at", ""),
                    "curl_command": entry.get("curl-command", ""),
                    "extracted_results": entry.get("extracted-results", []),
                    "tags": info.get("tags", []),
                },
            ))

        return findings


@register("nuclei_scanner")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    logger = context["logger"]
    config: dict = context.get("config", {})

    tags = config.get("nuclei_tags") or None
    qps = config.get("rate_limit", {}).get("default_qps", 5)
    rate_limit = int(qps) if qps else 5

    scanner = NucleiScanner(logger, rate_limit=rate_limit, tags=tags)
    findings = await scanner.scan(targets)
    return {"findings": [asdict(f) for f in findings]}
