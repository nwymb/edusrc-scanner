"""L4 主动验证 — P0 级弱口令检测 (WeakPasswordScanner)

1. GET 登录页 → 解析 form action / 字段名 / CSRF token
2. POST 凭据 → 判定 302 跳转 / Set-Cookie / 成功关键词
3. 每目标 ≤3 次尝试，防止账号锁定
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urljoin

import aiohttp

from modules import register
from shared.models import Finding, FindingSource, VulnSeverity

_log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_DEFAULT_DICT = _PROJECT_ROOT / "data" / "dicts" / "weak_passwords_edu.txt"

# 登录成功正指示词
_SUCCESS_KEYWORDS = [
    "登录成功", "登陆成功", "欢迎光临", "欢迎回来",
    "后台管理", "管理中心", "控制台",
    "welcome", "dashboard", "admin panel",
    "注销", "退出", "logout", "sign out",
]

# 登录失败反指示词
_FAIL_KEYWORDS = [
    "密码错误", "用户名或密码错误", "账号或密码错误",
    "登录失败", "密码不正确", "验证码错误", "请输入验证码",
    "incorrect password", "invalid password", "login failed",
]

# 登录表单提取正则
_FORM_RE = re.compile(r"<form\b[^>]*\saction\s*=\s*[\"']([^\"']+)[\"']", re.I)
_INPUT_RE = re.compile(r"<input\b[^>]*\sname\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.I)
_VALUE_RE = re.compile(r"\svalue\s*=\s*[\"']([^\"']*)[\"']", re.I)


def _load_credentials(path: str | Path | None = None) -> list[tuple[str, str]]:
    path = Path(path) if path else _DEFAULT_DICT
    creds: list[tuple[str, str]] = []
    if not path.exists():
        return [("admin", "123456"), ("admin", "admin")]
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            u, p = line.split(":", 1)
            creds.append((u.strip(), p.strip()))
    return creds


class WeakPasswordScanner:
    """教育行业弱口令检测扫描器

    用法:
        scanner = WeakPasswordScanner(session, logger)
        findings = await scanner.scan(login_targets)
    """

    def __init__(self, session, logger,
                 dict_path: str | Path | None = None,
                 max_attempts: int = 3):
        self.session = session
        self.logger = logger
        self.max_attempts = max_attempts
        self.credentials = _load_credentials(dict_path)
        self._total_tried = 0
        self._total_hit = 0

    # ── public API ──

    async def scan(self, targets: list[dict]) -> list[Finding]:
        """对登录页目标列表执行弱口令检测"""
        login_targets = [t for t in targets if t.get("is_login")]
        if not login_targets:
            self.logger.info("weak_pass_skip", reason="no_login_targets")
            return []

        self.logger.info("weak_pass_start", target_count=len(login_targets),
                         cred_count=len(self.credentials),
                         max_attempts=self.max_attempts)

        sem = asyncio.Semaphore(3)
        findings: list[Finding] = []

        async def probe_one(target: dict, idx: int):
            url = target.get("url", "")
            if not url:
                return
            async with sem:
                result = await self._probe_target(url, idx)
                if result is not None:
                    findings.append(result)

        await asyncio.gather(*[probe_one(t, i) for i, t in enumerate(login_targets)])

        self.logger.info("weak_pass_done", total=len(findings),
                         tried=self._total_tried, hit=self._total_hit)
        return findings

    # ── internal ──

    async def _probe_target(self, url: str, idx: int) -> Finding | None:
        """探测单个目标"""
        form_info = await self._parse_login_form(url)
        if not form_info:
            return None

        # 从凭据列表中轮转选取，避免全字典砸同一个目标
        for attempt in range(self.max_attempts):
            cred_idx = (idx + attempt) % len(self.credentials)
            username, password = self.credentials[cred_idx]
            self._total_tried += 1

            finding = await self._try_login(url, form_info, username, password)
            if finding is not None:
                self._total_hit += 1
                return finding

            await asyncio.sleep(0.5)  # 同一目标内尝试间隔

        return None

    async def _parse_login_form(self, url: str) -> dict | None:
        """GET 登录页，提取 form action / 输入字段 / 隐藏参数"""
        try:
            resp = await self.session.get(url)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("weak_pass_get_page_failed url=%s error=%s", url, e)
            return None

        if resp.status != 200:
            return None

        try:
            html = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("weak_pass_body_failed url=%s error=%s", url, e)
            return None

        # 提取 form action
        action = None
        m = _FORM_RE.search(html)
        if m:
            action = urljoin(url, m.group(1))

        # 提取所有 input name
        input_names: list[str] = []
        for m in _INPUT_RE.finditer(html):
            name = m.group(1)
            if name and name not in input_names:
                input_names.append(name)

        # 识别用户名/密码字段名
        user_field = None
        pass_field = None
        for name in input_names:
            nl = name.lower()
            if not user_field and any(kw in nl for kw in ("user", "name", "account", "email", "login")):
                user_field = name
            if not pass_field and any(kw in nl for kw in ("pass", "pwd", "password")):
                pass_field = name

        if not user_field:
            user_field = "username"
        if not pass_field:
            pass_field = "password"

        # 提取隐藏字段 (CSRF token)
        hidden: dict[str, str] = {}
        for m in re.finditer(
            r"<input\b[^>]*\stype\s*=\s*[\"']hidden[\"'][^>]*>", html, re.I
        ):
            nm = _VALUE_RE.search(m.group(0))
            if nm:
                name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', m.group(0), re.I)
                if name_m:
                    hidden[name_m.group(1)] = nm.group(1)

        return {
            "action": action or url,
            "user_field": user_field,
            "pass_field": pass_field,
            "hidden": hidden,
        }

    async def _try_login(self, url: str, form_info: dict,
                         username: str, password: str) -> Finding | None:
        """执行一次登录尝试并判定结果"""
        data = {
            form_info["user_field"]: username,
            form_info["pass_field"]: password,
            **form_info.get("hidden", {}),
        }

        action_url = form_info["action"]

        try:
            resp = await self.session.post(action_url, data=data)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("weak_pass_post_failed url=%s error=%s", url, e)
            return None

        try:
            body = await resp.text()
            body_lower = body[:16384].lower()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            _log.debug("weak_pass_body_failed url=%s error=%s", url, e)
            return None

        # ── 判定逻辑 ──
        hit, evidence = self._judge(resp, body_lower)

        if not hit:
            return None

        return Finding(
            url=url,
            vuln_type="weak_password",
            severity=VulnSeverity.HIGH,
            title=f"弱口令: {username}:{password}",
            evidence="; ".join(evidence),
            confidence=0.85 if len(evidence) >= 2 else 0.65,
            source=FindingSource.L4_ACTIVE,
            source_module="weak_pass",
            raw={
                "username": username,
                "password": password,
                "action_url": action_url,
                "status_code": resp.status,
                "evidence": evidence,
            },
        )

    @staticmethod
    def _judge(resp, body_lower: str) -> tuple[bool, list[str]]:
        """判定登录是否成功，返回 (is_success, evidence_list)"""
        evidence: list[str] = []

        # 1. 失败关键词快速否定
        for kw in _FAIL_KEYWORDS:
            if kw.lower() in body_lower:
                return False, []

        # 2. 302 跳转到非登录页
        location = resp.headers.get("Location", "")
        if resp.status in {301, 302, 303, 307} and location:
            loc_lower = location.lower()
            if not any(kw in loc_lower for kw in ("login", "signin", "error", "fail")):
                evidence.append(f"redirect={location}")

        # 3. Set-Cookie 会话标识
        cookie_vals = resp.headers.getall("Set-Cookie")
        session_tokens = [
            c for c in cookie_vals
            if any(kw in c.lower() for kw in ("session", "token", "jsessionid",
                                                "auth", "sid", "phpssid"))
        ]
        if session_tokens:
            evidence.append(f"session_cookie={session_tokens[0][:80]}")

        # 4. 响应体成功关键词
        body_hits = [kw for kw in _SUCCESS_KEYWORDS if kw.lower() in body_lower]
        if body_hits:
            evidence.append(f"body_hits={body_hits[:4]}")

        return len(evidence) >= 1, evidence


# ── 模块入口 (与 scheduler / main.py 联动) ──

@register("weak_pass")
async def run(context: dict) -> dict:
    """scheduler 调用的模块入口"""
    targets: list[dict] = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]
    config: dict = context.get("config", {})

    dict_path = config.get("weak_pass_dict") or None
    max_attempts = int(config.get("weak_pass_max_attempts", 3))

    scanner = WeakPasswordScanner(session, logger,
                                  dict_path=dict_path,
                                  max_attempts=max_attempts)
    findings = await scanner.scan(targets)
    return {"findings": [asdict(f) for f in findings]}
