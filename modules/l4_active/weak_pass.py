"""L4 主动验证 — 弱口令检测

对 L2 标记为登录页的 Target 尝试少量常见弱口令组合，仅做存在性证明。
每个登录页最多 2 次尝试，避免账号锁定。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from pathlib import Path

import aiohttp

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

with open(_PROJECT_ROOT / "data" / "dicts" / "weak_passwords.txt", "r") as _f:
    _CREDENTIALS: list[tuple[str, str]] = []
    for _line in _f:
        _line = _line.strip()
        if not _line or _line.startswith("#"):
            continue
        if ":" in _line:
            _u, _p = _line.split(":", 1)
            _CREDENTIALS.append((_u.strip(), _p.strip()))

# 每目标最大尝试次数
_MAX_ATTEMPTS = 2

# 登录失败响应特征
_FAIL_INDICATORS = [
    "密码错误", "用户名或密码错误", "登录失败", "账号或密码错误",
    "密码不正确", "用户名不能为空", "用户不存在",
    "incorrect password", "invalid password", "wrong password",
    "login failed", "authentication failed",
    "用户名或密码有误", "验证码错误", "请输入验证码",
]


def _pick_cred(creds: list[tuple[str, str]], idx: int) -> tuple[str, str]:
    """循环取凭据 """
    if not creds:
        return ("admin", "123456")
    return creds[idx % len(creds)]


async def _try_login(url: str, username: str, password: str, session) -> Finding | None:
    """POST 登录尝试"""
    # 同时发送多个常见字段名，服务端解析它认识的即可
    data = {
        "username": username, "password": password,
        "user": username, "pass": password,
        "name": username, "pwd": password,
    }

    try:
        resp = await session.post(url, data=data)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("weak_pass_post_failed url=%s error=%s", url, e)
        return None

    if resp.status in {401, 403}:
        return None

    try:
        body = await resp.text()
        body_lower = body[:8192].lower()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("weak_pass_body_failed url=%s error=%s", url, e)
        return None

    # 检查失败指示器
    for fail in _FAIL_INDICATORS:
        if fail.lower() in body_lower:
            return None

    # 登录成功证据评分
    score = 0
    evidence: list[str] = []

    location = resp.headers.get("Location", "")
    if location:
        score += 1
        evidence.append(f"redirect={location}")

    set_cookies = resp.headers.getall("Set-Cookie", [])
    cookie_str = " ".join(set_cookies).lower()
    if any(kw in cookie_str for kw in ("session", "token", "jsessionid", "auth")):
        score += 1
        evidence.append("session_cookie")

    if resp.status == 302:
        score += 1

    admin_kw = ["后台", "管理", "admin", "dashboard", "control panel"]
    hits = [kw for kw in admin_kw if kw in body_lower]
    if hits:
        score += 1
        evidence.append(f"admin_body={hits}")

    if score < 2:
        return None

    return Finding(
        url=url,
        vuln_type="weak_password",
        severity=VulnSeverity.HIGH if score >= 3 else VulnSeverity.MEDIUM,
        title=f"弱口令: {username}:{password}",
        evidence="; ".join(evidence),
        confidence=0.70 if score >= 3 else 0.55,
        source=FindingSource.L4_ACTIVE,
        source_module="weak_pass",
        raw={
            "username": username,
            "password": password,
            "status_code": resp.status,
            "location": location,
        },
    )


@register("weak_pass")
async def run(context: dict) -> dict:
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    login_targets = [t for t in targets if t.get("is_login")]
    if not login_targets:
        logger.info("weak_pass_skip", reason="no_login_targets")
        return {"findings": []}

    logger.info("weak_pass_start", login_target_count=len(login_targets),
                credential_count=len(_CREDENTIALS))

    sem = asyncio.Semaphore(3)
    findings: list[Finding] = []

    async def probe_target(target: dict, cred_idx: int):
        url = target.get("url", "")
        if not url:
            return
        async with sem:
            for attempt in range(_MAX_ATTEMPTS):
                u, p = _pick_cred(_CREDENTIALS, cred_idx + attempt)
                finding = await _try_login(url, u, p, session)
                if finding is not None:
                    findings.append(finding)
                    break
                await asyncio.sleep(0.5)

    for i, t in enumerate(login_targets):
        await probe_target(t, i)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    logger.info("weak_pass_done", total_findings=len(findings), by_severity=by_sev)

    return {"findings": [asdict(f) for f in findings]}
