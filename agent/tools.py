"""Agent Tool — send_http_request

LLM 唯一可调用的"扳机"。内部走 RateLimitedSession（令牌桶限速 + SSL 容错），
严格截断返回体，所有异常转为字符串绝不 raise。
"""

from __future__ import annotations

import asyncio
import logging
import ssl

import aiohttp

from shared.http_client import RateLimitedSession

_log = logging.getLogger(__name__)

# 响应体最大长度 (防撑爆 LLM Context)
_MAX_BODY_CHARS = 10240


# ── Tool 实现 ──

async def send_http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    session: RateLimitedSession | None = None,
) -> str:
    """向目标 URL 发送 HTTP 请求，返回截断后的响应摘要。

    Args:
        url: 完整目标 URL
        method: HTTP 方法 (GET/POST/HEAD)
        headers: 自定义请求头字典
        body: 请求体字符串 (POST 使用)
        session: 可选，外部注入的 RateLimitedSession。若为 None 则内部创建临时会话。

    Returns:
        字符串化的响应摘要。所有异常均被捕获，绝不上抛。
    """
    _close_after = False
    if session is None:
        session = RateLimitedSession(qps=5.0, timeout=10.0)
        _close_after = True

    method_upper = method.upper()
    headers = headers or {}

    try:
        if method_upper == "POST":
            resp = await session.post(url, data=body or "", headers=headers)
        elif method_upper == "HEAD":
            resp = await session.head(url, headers=headers)
        else:
            resp = await session.get(url, headers=headers)

        status = resp.status
        content_type = resp.headers.get("Content-Type", "unknown")
        resp_headers = dict(resp.headers.items())

        try:
            raw_body = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
            raw_body = "(binary or undecodable body)"

        # 截断
        truncated = False
        if len(raw_body) > _MAX_BODY_CHARS:
            raw_body = raw_body[:_MAX_BODY_CHARS] + "\n...<Truncated>"
            truncated = True

        summary = (
            f"HTTP {status} {method_upper} {url}\n"
            f"Content-Type: {content_type}\n"
            f"Headers: {resp_headers}\n"
            f"Body ({'truncated' if truncated else len(raw_body)} chars):\n{raw_body}"
        )
        return summary

    except (ssl.SSLError, aiohttp.ClientConnectorError) as e:
        msg = (f"[NETWORK_BLOCKED] SSL/TCP 握手失败: {e}. "
               f"IP 可能已被 WAF 封禁，建议切换代理或开启 spoof_local_ip 后重试。")
        _log.warning(msg)
        return msg
    except asyncio.TimeoutError as e:
        msg = f"[TIMEOUT] 请求超时: {url} — {e}"
        _log.debug(msg)
        return msg
    except aiohttp.ClientError as e:
        msg = f"[HTTP_ERROR] 请求失败: {url} — {e}"
        _log.debug(msg)
        return msg
    except Exception as e:
        msg = f"[UNEXPECTED] 未知错误: {url} — {type(e).__name__}: {e}"
        _log.warning(msg)
        return msg
    finally:
        if _close_after:
            await session.close()


# ── JSON Schema (喂给 DeepSeek 的 tools 参数) ──

SEND_HTTP_REQUEST_SCHEMA: dict = {
    "type": "function",
    "function": {
        "name": "send_http_request",
        "description": (
            "向目标 URL 发送 HTTP 请求，用于探测未授权访问或漏洞验证。"
            "返回状态码、响应头和截断后的响应体。这是你唯一能触达外部网络的操作。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "完整目标 URL，如 https://example.edu.cn/admin/api",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "HEAD"],
                    "description": "HTTP 方法。GET 获取资源，POST 提交数据，HEAD 仅获取响应头",
                },
                "headers": {
                    "type": "object",
                    "description": "自定义请求头，如 {'X-Forwarded-For':'127.0.0.1'}",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "POST 请求体，如 username=admin&password=123456 或 JSON",
                },
            },
            "required": ["url", "method"],
        },
    },
}

ALL_TOOLS: list[dict] = [SEND_HTTP_REQUEST_SCHEMA]
