"""L2 资产价值评分 + 登录页/管理后台识别"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from modules import register

_log = logging.getLogger(__name__)

_LOGIN_TITLE = [
    "登录", "登陆", "sign in", "signin", "log in", "login",
    "统一认证", "单点登录", "用户登录", "身份认证",
    "sso", "cas", "oauth",
]
_LOGIN_BODY = [
    "type=\"password\"", "type='password'",
    "密码", "password", "passwd",
    "验证码", "captcha", "verification",
    "忘记密码", "forgot password",
    "rememberme",
]
_ADMIN_URL = [
    "/admin", "/manage", "/manager", "/dashboard", "/console",
    "/system", "/backend", "/control", "/panel",
]
_ADMIN_TITLE = [
    "后台", "管理", "admin", "manage", "dashboard",
    "console", "控制台", "panel", "管理中心",
]
_EDU_HIGH_VALUE = [
    "jw", "jwc", "jiaowu", "graduate", "yjs", "grs",
    "zs", "zsb", "zhaosheng", "oa", "erp", "hr", "finance",
    "cas", "sso", "auth", "pay", "payment",
    "lib", "library", "tsg", "exam", "kaoshi", "cet",
]


def _score(target: dict) -> int:
    score = 0
    url = target.get("url", "").lower()
    status = target.get("status_code", 0)
    tech = target.get("tech_stack", [])
    fp = target.get("fingerprint", "")

    if 200 <= status < 300:
        score += 10
    if url.startswith("https://"):
        score += 5
    for kw in _EDU_HIGH_VALUE:
        if kw in url:
            score += 15
            break
    score += min(len(tech) * 5, 20)
    if fp:
        score += 10
    if target.get("is_login"):
        score += 15
    if target.get("is_admin"):
        score += 15
    return min(score, 100)


def _is_login(target: dict, body: str) -> bool:
    title = target.get("title", "").lower()
    body_lower = body.lower()
    for pat in _LOGIN_TITLE:
        if pat in title:
            return True
    has_pw = "type=\"password\"" in body_lower or "type='password'" in body_lower
    has_submit = "type=\"submit\"" in body_lower or "登录" in body_lower
    if has_pw and has_submit:
        return True
    for pat in _LOGIN_BODY:
        if pat in body_lower:
            return True
    return False


def _is_admin(target: dict) -> bool:
    url = target.get("url", "").lower()
    title = target.get("title", "").lower()
    fp = target.get("fingerprint", "").lower()
    for pat in _ADMIN_URL:
        if pat in url or pat in fp:
            return True
    for pat in _ADMIN_TITLE:
        if pat in title:
            return True
    return False


async def _analyze(target: dict, session) -> dict:
    url = target.get("url", "")
    if not url:
        target["value_score"] = 0
        return target

    body = ""
    try:
        resp = await session.get(url)
        body = await resp.text()
        body = body[:131072]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("value_score_fetch_failed url=%s error=%s", url, e)

    target["is_login"] = _is_login(target, body)
    target["is_admin"] = _is_admin(target)
    target["value_score"] = _score(target)
    return target


@register("value_score")
async def run(context: dict) -> dict:
    targets = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]

    if not targets:
        logger.info("value_score_skip", reason="no_targets")
        return {"targets": []}

    logger.info("value_score_start", target_count=len(targets))
    sem = asyncio.Semaphore(5)
    result = []

    async def probe_one(t: dict):
        async with sem:
            result.append(await _analyze(t, session))

    await asyncio.gather(*[probe_one(t) for t in targets])

    high = sum(1 for t in result if t.get("value_score", 0) >= 50)
    login_n = sum(1 for t in result if t.get("is_login"))
    admin_n = sum(1 for t in result if t.get("is_admin"))
    logger.info("value_score_done", total=len(result),
                high_value=high, login_pages=login_n, admin_pages=admin_n)
    return {"targets": result}
