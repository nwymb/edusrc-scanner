"""Agent Tool Registry — 统一工具注册 + 第一批 3 把武器

send_http_request:  万能发包器 (compressor 内置)
web_fingerprint:    技术栈指纹识别
dir_scanner:        敏感路径爆破
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import urllib.parse
from urllib.parse import urljoin

import aiohttp

from agent.observation_compressor import compress_http_response

_log = logging.getLogger(__name__)

_BINARY_CT = {"image", "video", "audio", "application/pdf",
              "application/zip", "application/octet-stream",
              "application/gzip", "application/x-tar"}

# ── 小型精准字典 ──
_WORDLISTS = {
    "admin": ["/admin", "/admin/login", "/manage", "/manager", "/console",
              "/system", "/backend", "/panel", "/admin/login.php", "/admin/login.aspx"],
    "api": ["/api", "/api/v1", "/api/v2", "/swagger-ui.html", "/api-docs",
            "/v2/api-docs", "/v3/api-docs", "/graphql", "/actuator", "/api/users"],
    "backup": ["/backup.zip", "/www.zip", "/backup.sql", "/.env",
               "/config.php.bak", "/web.config", "/.git/HEAD", "/backup.rar"],
    "config": ["/.env", "/config.php.bak", "/web.config", "/application.properties",
               "/settings.py", "/wp-config.php.bak", "/config/database.yml"],
    "mail": ["/webmail", "/coremail", "/session/login", "/api/manager",
             "/sys/admin/login", "/interface"],
}


# ═══════════════════════════════════════════════
# Tool 1: send_http_request (万能发包 + 视觉清洗)
# ═══════════════════════════════════════════════

async def send_http_request(
    url: str, method: str = "GET", headers: dict | None = None,
    body: str | None = None, session: RateLimitedSession | None = None,
) -> str:
    _close_after = False
    if session is None:
        jar = aiohttp.CookieJar(unsafe=True)  # 允许接收 IP 地址的 Cookie
        session = aiohttp.ClientSession(cookie_jar=jar)
        _close_after = True
    method_upper = method.upper()
    headers = {k.lower(): v for k, v in (headers or {}).items()}

    # POST/PUT + 字符串 body → 转为 dict (aiohttp 才会正确发 form 数据)
    if method_upper in ("POST", "PUT") and isinstance(body, str) and body:
        if not body.strip().startswith("{") and "=" in body:
            try:
                body = dict(urllib.parse.parse_qsl(body))
            except Exception:
                pass

    # POST/PUT + 无 Content-Type → 自动补
    if method_upper in ("POST", "PUT") and body and "content-type" not in headers:
        headers["content-type"] = "application/x-www-form-urlencoded"

    try:
        if method_upper == "POST":
            resp = await session.post(url, data=body or "", headers=headers)
        elif method_upper == "HEAD":
            resp = await session.head(url, headers=headers)
        else:
            resp = await session.get(url, headers=headers)

        status = resp.status
        content_type = resp.headers.get("Content-Type", "unknown").lower()
        resp_headers = dict(resp.headers.items())

        if any(ct in content_type for ct in _BINARY_CT):
            return (f"[Binary Data] HTTP {status} {method_upper} {url}\n"
                    f"Content-Type: {content_type}")
        try:
            raw_body = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
            return f"[Undecodable Body] HTTP {status} {method_upper} {url}"

        summary = compress_http_response(status, resp_headers, raw_body)
        return f"## Request: {method_upper} {url}\n\n{summary}"
    except (ssl.SSLError, aiohttp.ClientConnectorError) as e:
        return f"[NETWORK_BLOCKED] {url}: {e}"
    except asyncio.TimeoutError:
        return f"[TIMEOUT] {url}"
    except aiohttp.ClientError as e:
        return f"[HTTP_ERROR] {url}: {e}"
    except Exception as e:
        return f"[UNEXPECTED] {url}: {type(e).__name__}: {e}"
    finally:
        if _close_after:
            await session.close()


# ═══════════════════════════════════════════════
# Tool 2: web_fingerprint (技术栈指纹)
# ═══════════════════════════════════════════════

async def web_fingerprint(
    url: str,
    session: RateLimitedSession | None = None,
) -> str:
    """GET 目标 URL，从 Header 和 Body 提取技术栈指纹。"""
    resp_text = await send_http_request(url, "GET", session=session)
    if resp_text.startswith("[") and not resp_text.startswith("##"):
        return f"Fingerprint failed: {resp_text}"

    # 从已清洗的响应中提取指纹线索
    fingerprint_parts: list[str] = []
    resp_lower = resp_text.lower()

    # Server / X-Powered-By
    if "apache" in resp_lower:
        fingerprint_parts.append("Apache")
    if "nginx" in resp_lower:
        fingerprint_parts.append("Nginx")
    if "iis" in resp_lower or "microsoft-iis" in resp_lower:
        fingerprint_parts.append("IIS")
    if "openresty" in resp_lower:
        fingerprint_parts.append("OpenResty")
    if "tomcat" in resp_lower or "apache-coyote" in resp_lower:
        fingerprint_parts.append("Tomcat")
    if "php" in resp_lower and "x-powered-by" in resp_lower:
        ver = ""
        for line in resp_text.splitlines():
            if "x-powered-by" in line.lower() and "php" in line.lower():
                ver = line.strip()
                break
        fingerprint_parts.append(ver or "PHP")
    if "asp.net" in resp_lower or "x-aspnet" in resp_lower:
        fingerprint_parts.append("ASP.NET")
    if "django" in resp_lower or "csrftoken" in resp_lower:
        fingerprint_parts.append("Django")
    if "laravel" in resp_lower or "laravel_session" in resp_lower:
        fingerprint_parts.append("Laravel")
    if "thinkphp" in resp_lower or "think_" in resp_lower:
        fingerprint_parts.append("ThinkPHP")
    if "spring" in resp_lower or "x-application-context" in resp_lower:
        fingerprint_parts.append("Spring Boot")
    if "struts" in resp_lower:
        fingerprint_parts.append("Apache Struts")
    if "shiro" in resp_lower or "rememberme" in resp_lower:
        fingerprint_parts.append("Apache Shiro")
    if "wordpress" in resp_lower or "wp-content" in resp_lower:
        fingerprint_parts.append("WordPress")
    if "jquery" in resp_lower:
        fingerprint_parts.append("jQuery")
    if "vue" in resp_lower:
        fingerprint_parts.append("Vue.js")
    if "react" in resp_lower:
        fingerprint_parts.append("React")
    if "dedecms" in resp_lower:
        fingerprint_parts.append("DedeCMS")
    if "coremail" in resp_lower:
        fingerprint_parts.append("Coremail")
    if "set-cookie" in resp_lower:
        for line in resp_text.splitlines():
            if "set-cookie" in line.lower():
                fingerprint_parts.append(f"Cookie: {line.split(':',1)[-1].strip()[:80]}")
                break

    if not fingerprint_parts:
        return f"Fingerprint: 未识别到已知技术栈 (URL: {url})"
    return f"Fingerprint: {', '.join(fingerprint_parts)}"


# ═══════════════════════════════════════════════
# Tool 3: dir_scanner (敏感路径爆破)
# ═══════════════════════════════════════════════

async def dir_scanner(
    base_url: str,
    wordlist_type: str = "admin",
    session: RateLimitedSession | None = None,
) -> str:
    """对 base_url 拼接小型精准字典并发探测，返回存活的敏感路径。"""
    paths = _WORDLISTS.get(wordlist_type, _WORDLISTS["admin"])

    _close_after = False
    if session is None:
        session = RateLimitedSession(qps=5.0, timeout=8.0)
        _close_after = True

    results: list[str] = []
    sem = asyncio.Semaphore(5)

    async def probe(p: str):
        full_url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
        try:
            async with sem:
                resp = await session.get(full_url)
                if resp.status in (200, 403, 500, 302, 301):
                    results.append(f"[{resp.status}] {p}")
        except Exception:
            pass

    await asyncio.gather(*[probe(p) for p in paths])

    if _close_after:
        await session.close()

    if not results:
        return f"No sensitive paths found for '{wordlist_type}'."
    return f"Found alive paths ({wordlist_type}): " + ", ".join(sorted(results))


# ═══════════════════════════════════════════════
# Tool Registry — 统一 Schema + 函数映射
# ═══════════════════════════════════════════════

TOOL_MAP: dict = {
    "send_http_request": send_http_request,
    "web_fingerprint": web_fingerprint,
    "dir_scanner": dir_scanner,
}

ALL_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "send_http_request",
            "description": (
                "向目标 URL 发送 HTTP 请求，返回清洗压缩后的页面精华"
                "(表单/链接/注释/Header/文本)。这是你的主要发包武器。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "完整目标 URL"},
                    "method": {"type": "string", "enum": ["GET", "POST", "HEAD"],
                              "description": "HTTP 方法"},
                    "headers": {"type": "object", "description": "自定义请求头",
                               "additionalProperties": {"type": "string"}},
                    "body": {"type": "string", "description": "POST 请求体"},
                },
                "required": ["url", "method"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_fingerprint",
            "description": (
                "对目标 URL 进行技术栈指纹识别。在正面硬刚登录框或 403 之前，"
                "先调用此工具识别 CMS/语言/中间件，以获取特定框架的已知漏洞线索。"
                "返回如 'Fingerprint: ThinkPHP, PHP, Nginx'"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dir_scanner",
            "description": (
                "对 base_url 进行敏感路径爆破。当发现 /api/ 或 /admin/ 类残缺路径时，"
                "使用此工具快速探测管理后台、API 端点、备份文件。"
                "wordlist_type 可选: admin, api, backup, config, mail"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "基础 URL"},
                    "wordlist_type": {"type": "string",
                                      "enum": ["admin", "api", "backup", "config", "mail"],
                                      "description": "字典类型"},
                },
                "required": ["base_url", "wordlist_type"],
            },
        },
    },
]
