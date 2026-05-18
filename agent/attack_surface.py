"""攻击面提取器 — 从 HTML 中提取 URL 参数、表单等核心攻击面。

在 L4 主动扫描中，目标返回 200 OK 时先调用此函数，将结构化攻击面
而非原始 HTML 发给 LLM，节省 Token 并提高精确度。

v2: 集成敏感信息嗅探，提取邮箱/手机/工号 → 存入全局 Memory。
v3: JS Hunter — 下载同源 JS，扒出 Vue/React 硬编码 API 路由。
"""

from __future__ import annotations

import asyncio
import logging
import re as _re
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import yaml
from bs4 import BeautifulSoup

_log = logging.getLogger(__name__)

# ── 敏感信息正则 ──
_EMAIL_RE = _re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = _re.compile(r"(?:1[3-9]\d{9})|(?:\d{3,4}-?\d{7,8})")
_EMPLOYEE_ID_RE = _re.compile(r"(?:工号|学号|职工号|员工编号|userid|employee\s*id)[:\s]*(\w{4,20})", _re.IGNORECASE)
_INTERNAL_PATH_RE = _re.compile(r"""(?:href|src|action)=["']([^"']*(?:admin|manage|api|internal|backup|config|debug|export|log|upload|download)[^"']*)["']""", _re.IGNORECASE)

# ── JS API 路由正则 ──
# 匹配 JS 中硬编码的路径字符串: "/api/xxx"  '/admin/xxx'  `/v1/xxx`
_API_ROUTE_RE = _re.compile(
    r"""["'`](/[a-zA-Z0-9._/]*(?:api|v\d+|admin|manage|system|login|logout|auth|user|role|menu|dept|dict|notice|file|upload|download|config|backup|debug|graphql|ws|proxy)[a-zA-Z0-9._/]*)["'`]""",
    _re.IGNORECASE,
)


def _load_proxy() -> str:
    cfg_path = Path(__file__).resolve().parent.parent / "orchestrator" / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path) as f:
            return (yaml.safe_load(f) or {}).get("http", {}).get("proxy", "")
    return ""


def _is_same_origin(script_src: str, base_url: str) -> bool:
    """判断 JS 链接是否与当前页面同源。"""
    if not script_src or script_src.startswith("data:") or script_src.startswith("blob:"):
        return False
    if script_src.startswith("//") or script_src.startswith(("http://", "https://")):
        return urlparse(script_src).netloc == urlparse(base_url).netloc
    # 相对路径 → 同源
    return True


def _extract_script_srcs(html_content: str, base_url: str) -> list[str]:
    """从 HTML 中提取同源 <script src=...> 链接。"""
    soup = BeautifulSoup(html_content, "html.parser")
    srcs: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = (tag.get("src") or "").strip()
        if src and _is_same_origin(src, base_url):
            full = urljoin(base_url, src)
            if full not in srcs:
                srcs.append(full)
    return srcs[:5]  # 限 5 个，控请求量


def _extract_api_routes(js_content: str) -> list[str]:
    """从 JS 内容中提取硬编码的 API 路由。"""
    routes: list[str] = []
    seen = set()
    for m in _API_ROUTE_RE.finditer(js_content):
        raw = m.group(1)
        # 过滤 JS 关键字 / 伪路径
        if raw in ("/", "//", "/*", "/**"):
            continue
        # 去重 + 标准化
        normalized = raw.rstrip("/\\")
        if normalized not in seen:
            seen.add(normalized)
            routes.append(normalized)
    return sorted(routes, key=lambda r: len(r))


async def _download_js(url: str, proxy: str) -> str | None:
    """下载 JS 文件内容，复用代理 + 忽略 SSL。"""
    try:
        async with httpx.AsyncClient(
            proxy=proxy or None,
            verify=False,
            timeout=httpx.Timeout(10),
            follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers={"Connection": "close"})
            return resp.text[:65536]  # 取前 64K，足够扒路由
    except Exception as e:
        _log.debug("js_download_failed url=%s error=%s", url, e)
        return None


async def extract_attack_surface(html_content: str, current_url: str) -> dict:
    """从 HTML 页面提取核心攻击面 + 敏感信息 + JS 隐藏路由。

    Returns:
        {"url_params": ..., "forms": ..., "sensitive_info": {...},
         "internal_links": [...], "hidden_apis": [...]}
    """
    # 1. URL Query 参数
    url_params: dict[str, list[str]] = {}
    parsed = urlparse(current_url)
    if parsed.query:
        url_params = parse_qs(parsed.query, keep_blank_values=True)

    # 2. Form 表单提取
    soup = BeautifulSoup(html_content, "html.parser")
    forms: list[dict] = []

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").strip().upper()

        inputs: list[dict] = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = (tag.get("name") or "").strip()
            if not name:
                continue

            raw_type = (tag.get("type") or "text").strip().lower()
            if raw_type in ("submit", "button", "reset", "image"):
                continue

            if tag.name == "select":
                field_type = "select"
            elif tag.name == "textarea":
                field_type = "textarea"
            else:
                field_type = raw_type

            inputs.append({"name": name, "type": field_type})

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    # 3. 敏感信息嗅探 (存入全局 Memory)
    sensitive: dict[str, list[str]] = {}
    plain_text = soup.get_text()

    emails = list(set(_EMAIL_RE.findall(plain_text)))
    if emails:
        sensitive["emails"] = emails

    phones = list(set(_PHONE_RE.findall(plain_text)))
    if phones:
        sensitive["phones"] = phones

    eids = list(set(g for g in _EMPLOYEE_ID_RE.findall(plain_text) if len(g) >= 4))
    if eids:
        sensitive["employee_ids"] = eids

    internal_links = list(set(_INTERNAL_PATH_RE.findall(html_content)))

    # 写入全局记忆
    try:
        from agent.memory import AgentMemory
        mem = AgentMemory.get()
        for k, v in sensitive.items():
            mem.set(k, v)
        if internal_links:
            mem.set("internal_links", internal_links)
        mem.save()
    except ImportError:
        pass

    # 4. JS Hunter: 下载同源 JS → 扒隐藏路由
    hidden_apis: list[str] = []
    script_links = _extract_script_srcs(html_content, current_url)
    if script_links:
        proxy = _load_proxy()
        tasks = [_download_js(url, proxy) for url in script_links]
        js_results = await asyncio.gather(*tasks, return_exceptions=True)
        for url, js in zip(script_links, js_results):
            if isinstance(js, str) and js:
                routes = _extract_api_routes(js)
                if routes:
                    hidden_apis.extend(routes)
                    _log.info("js_hunter url=%s routes=%d", url, len(routes))

    # 去重排序
    hidden_apis = sorted(set(hidden_apis), key=lambda r: len(r))

    # 存入记忆
    if hidden_apis:
        try:
            from agent.memory import AgentMemory
            AgentMemory.get().set("hidden_apis", hidden_apis)
            AgentMemory.get().save()
        except ImportError:
            pass

    return {
        "url_params": url_params,
        "forms": forms,
        "sensitive_info": sensitive,
        "internal_links": internal_links,
        "hidden_apis": hidden_apis,
    }
