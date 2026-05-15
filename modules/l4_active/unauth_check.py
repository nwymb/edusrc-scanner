"""L4 主动验证 — P1 级未授权访问与越权旁路检测 (UnauthScanner)

1. 筛选 API/Admin 类 URL + is_login=False 的资产
2. GET + POST(空参数) 零凭据探测
3. 遇 401/403 → 伪造 X-Forwarded-For: 127.0.0.1 重试绕过
4. 200 OK + JSON/敏感字段 → 判定为未授权漏洞
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
from dataclasses import asdict
from urllib.parse import urljoin

import aiohttp

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

# AdvancedBypass — 4 层 Header 组合，遇 403 自动轮换
_BYPASS_COMBOS: list[dict[str, str]] = [
    # Tier 1: 伪造请求路径 (绕过 URL-based ACL)
    {"X-Original-URL": "/", "X-Rewrite-URL": "/"},
    # Tier 2: 伪造网关来源 (绕过 reverse-proxy 限制)
    {"X-Forwarded-Host": "127.0.0.1",
     "Forwarded": "for=127.0.0.1;proto=https",
     "X-Forwarded-Proto": "https"},
    # Tier 3: 伪造管理权限 (绕过 RBAC)
    {"X-Admin": "true", "X-Role": "admin",
     "X-Auth-Token": "admin", "X-Auth-User": "admin"},
    # Tier 4: 复合 IP 伪造 (绕过 IP whitelist)
    {"X-Client-IP": "127.0.0.1", "X-Original-For": "127.0.0.1",
     "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
     "X-Originating-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1"},
]

# ── 敏感信息关键词 (按类别) ──
# API 结构泄露
_API_STRUCT = [
    '"code":0', '"code": 0', '"success":true', '"success": true',
    '"total":', '"data":', '"list":', '"rows":', '"records":',
    '"result":', '"items":', '"body":',
]
# 凭据/隐私数据 (出现在 JSON 字段名中)
_PII_FIELDS = [
    '"username":', '"password":', '"passwd":', '"secret":',
    '"token":', '"accessKey":', '"access_token":', '"apiKey":',
    '"email":', '"phone":', '"mobile":', '"idCard":',
    '"realName":', '"address":', '"birthday":',
]
# 数据库/基础设施泄露
_INFRA_LEAK = [
    '"jdbc:', 'jdbc:mysql', 'jdbc:oracle', 'jdbc:postgresql',
    '"datasource":', '"connectionString":',
    'spring.datasource', 'mongodb://', 'redis://',
    'DB_HOST', 'DB_PASSWORD', 'APP_KEY',
]

# 额外探测的管理端点 (追加在目标 base URL 后)
_ADMIN_PATHS = [
    "/admin/", "/api/", "/actuator/health", "/actuator/env",
    "/druid/datasource.json", "/druid/index.html",
    "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
    "/.env",
]


def _is_sensitive(body: str, content_type: str) -> tuple[bool, list[str]]:
    """检测响应是否包含未授权敏感数据"""
    hits: list[str] = []
    body_lower = body.lower()

    # JSON 内容类型加成
    is_json = "application/json" in content_type.lower()

    for kw in _API_STRUCT:
        if kw.lower() in body_lower:
            hits.append(kw)
    for kw in _PII_FIELDS:
        if kw.lower() in body_lower:
            hits.append(kw)
    for kw in _INFRA_LEAK:
        if kw.lower() in body_lower:
            hits.append(kw)

    # 判定阈值: JSON 格式 + ≥1 个命中 或 ≥3 个命中
    if is_json and len(hits) >= 1:
        return True, hits
    if len(hits) >= 3:
        return True, hits
    return False, []


class UnauthScanner:
    """未授权访问与越权旁路检测扫描器

    用法:
        scanner = UnauthScanner(session, logger)
        findings = await scanner.scan(targets)
    """

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger

    # ── public API ──

    async def scan(self, targets: list[dict]) -> list[Finding]:
        """对目标列表执行未授权访问检测"""
        candidates = self._select_targets(targets)
        if not candidates:
            self.logger.info("unauth_skip", reason="no_candidates")
            return []

        self.logger.info("unauth_start", candidate_count=len(candidates))

        sem = asyncio.Semaphore(5)
        findings: list[Finding] = []

        async def probe_one(target: dict):
            async with sem:
                results = await self._probe_target(target)
                findings.extend(results)

        await asyncio.gather(*[probe_one(t) for t in candidates])

        self.logger.info("unauth_done", total=len(findings))
        return findings

    # ── target selection ──

    @staticmethod
    def _select_targets(targets: list[dict]) -> list[dict]:
        """筛选高价值目标: /api/ /admin/ /system/ /user/ + is_login=False"""
        high_value = []
        for t in targets:
            url = t.get("url", "").lower()
            score = 0
            for frag in ("/api/", "/api/v", "/admin/", "/system/", "/user/",
                         "/manage/", "/console/", "/backend/"):
                if frag in url:
                    score += 2
            if not t.get("is_login", True):
                score += 1
            if score >= 1:
                high_value.append(t)
        return high_value

    # ── per-target probe ──

    async def _probe_target(self, target: dict) -> list[Finding]:
        """探测单个目标及其管理端点"""
        url = target.get("url", "")
        if not url:
            return []

        findings: list[Finding] = []

        # 1) 直接探测目标 URL (GET + POST)
        for method in ("GET", "POST"):
            f = await self._check_endpoint(url, method, bypass_used=False)
            if f:
                findings.append(f)

        # 2) 探测常见管理子路径 (仅 GET，限 5 条)
        for path in _ADMIN_PATHS[:5]:
            endpoint = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
            f = await self._check_endpoint(endpoint, "GET", bypass_used=False)
            if f:
                findings.append(f)
                break  # 命中一条即止

        return findings

    async def _check_endpoint(self, url: str, method: str,
                              bypass_used: bool = False) -> Finding | None:
        """探测单个端点，遇 403 自动轮换 AdvancedBypass 四层 Header 组合"""
        hit, body, content_type, status = await self._request(url, method, {})

        # AdvancedBypass: 401/403 → 依序尝试 4 层 Header 组合
        bypass_tier = 0
        if not hit and status in (401, 403):
            for tier_idx, combo in enumerate(_BYPASS_COMBOS, 1):
                hit, body, content_type, status = await self._request(
                    url, method, combo
                )
                if hit:
                    bypass_used = True
                    bypass_tier = tier_idx
                    break

        if not hit:
            return None

        hits = _is_sensitive(body, content_type)[1]

        severity = VulnSeverity.HIGH
        for kw in hits:
            if any(leak in kw.lower() for leak in ("jdbc:", "password", "token",
                                                     "secret", "accesskey")):
                severity = VulnSeverity.CRITICAL
                break

        evidence = f"HTTP {status} method={method}"
        if bypass_used:
            tier_labels = {1: "path_forgery", 2: "gateway_forgery",
                          3: "auth_forgery", 4: "composite_ip"}
            evidence += f" bypass={tier_labels.get(bypass_tier, 'tier_%d'%bypass_tier)}"
        evidence += f" content_type={content_type[:60]} hits={hits[:6]}"

        return Finding(
            url=url,
            vuln_type="unauth",
            severity=severity,
            title=f"未授权访问: {url}",
            evidence=evidence,
            confidence=0.85 if len(hits) >= 3 else 0.65,
            source=FindingSource.L4_ACTIVE,
            source_module="unauth_check",
            raw={
                "method": method,
                "status_code": status,
                "bypass_used": bypass_used,
                "bypass_tier": bypass_tier,
                "content_type": content_type,
                "sensitive_hits": hits[:10],
                "body_preview": body[:300],
            },
        )

    async def _request(self, url: str, method: str,
                       extra_headers: dict) -> tuple[bool, str, str, int]:
        """发送零凭据请求，返回 (is_hit, body, content_type, status)"""
        try:
            if method == "POST":
                resp = await self.session.post(url, data="", headers=extra_headers)
            else:
                resp = await self.session.get(url, headers=extra_headers)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("unauth_req_failed url=%s error=%s", url, e)
            return False, "", "", 0

        status = resp.status

        if status != 200:
            return False, "", "", status

        body = ""
        content_type = resp.headers.get("Content-Type", "")
        try:
            body = await resp.text()
            body = body[:65536]
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("unauth_body_failed url=%s error=%s", url, e)

        sensitive, _ = _is_sensitive(body, content_type)
        return sensitive, body, content_type, status


# ── 模块入口 ──

@register("unauth_check")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    scanner = UnauthScanner(session, logger)
    findings = await scanner.scan(targets)
    return {"findings": [asdict(f) for f in findings]}
