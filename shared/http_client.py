from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Optional

import aiohttp

from orchestrator.rate_limiter import get_limiter

_log = logging.getLogger(__name__)


class Response:
    """与 aiohttp.ClientResponse 兼容的轻量 wrapper，预读取 body 释放连接"""

    __slots__ = ('status', 'headers', '_body')

    def __init__(self, status: int, headers: _Headers, body: str):
        self.status = status
        self.headers = _Headers(headers)
        self._body = body

    async def text(self) -> str:
        return self._body


class _Headers:
    """兼容 aiohttp CIMultiDict 接口的 header wrapper"""

    __slots__ = ('_pairs', '_lower')

    def __init__(self, raw_headers: _Headers | dict):
        if isinstance(raw_headers, _Headers):
            self._pairs = raw_headers._pairs
            self._lower = raw_headers._lower
            return
        self._pairs: list[tuple[str, str]] = list(raw_headers.items())
        self._lower: dict[str, str] = {}
        for k, v in self._pairs:
            kl = k.lower()
            if kl not in self._lower:
                self._lower[kl] = v

    def get(self, key: str, default: str = "") -> str:
        return self._lower.get(key.lower(), default)

    def getall(self, key: str, default: list[str] | None = None) -> list[str]:
        kl = key.lower()
        vals = [v for k, v in self._pairs if k.lower() == kl]
        return vals if vals else (default if default is not None else [])

    def items(self):
        return iter(self._pairs)


class RateLimitedSession:
    """带令牌桶限速的 aiohttp 会话封装"""

    def __init__(self, qps: float = 5.0, timeout: float = 15.0,
                 user_agent: str = "eduSRC-Scanner/0.1",
                 max_redirects: int = 3, retry: int = 2,
                 verify_ssl: bool = True,
                 spoof_local_ip: bool = False):
        self.qps = qps
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        self.retry = retry
        self.limiter = get_limiter(default_qps=qps)
        self.spoof_local_ip = spoof_local_ip
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_context, limit=20)
            headers: dict[str, str] = {"User-Agent": self.user_agent}
            if self.spoof_local_ip:
                headers.update({
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Client-IP": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Remote-Addr": "127.0.0.1",
                })
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers=headers,
            )
        return self._session

    @staticmethod
    def _domain_from_url(url: str) -> str:
        from urllib.parse import urlparse
        return urlparse(url).hostname or url

    async def get(self, url: str, **kwargs) -> Response:
        """带限速的 GET 请求，预读 body 释放连接"""
        bucket = self.limiter.get_bucket(self._domain_from_url(url))
        for attempt in range(self.retry + 1):
            await bucket.acquire()
            session = await self._get_session()
            try:
                async with session.get(url, allow_redirects=True,
                                       max_redirects=self.max_redirects, **kwargs) as resp:
                    text = await resp.text()
                    return Response(resp.status, resp.headers, text)
            except (ssl.SSLError, aiohttp.ClientConnectorError) as e:
                _log.warning("NETWORK_BLOCKED ssl_error=%s url=%s "
                            "(IP may be WAF-banned, try spoof_local_ip or wait)",
                            e, url)
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt == self.retry:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def post(self, url: str, **kwargs) -> Response:
        """带限速的 POST 请求，预读 body 释放连接"""
        bucket = self.limiter.get_bucket(self._domain_from_url(url))
        for attempt in range(self.retry + 1):
            await bucket.acquire()
            session = await self._get_session()
            try:
                async with session.post(url, allow_redirects=True,
                                        max_redirects=self.max_redirects, **kwargs) as resp:
                    text = await resp.text()
                    return Response(resp.status, resp.headers, text)
            except (ssl.SSLError, aiohttp.ClientConnectorError) as e:
                _log.warning("NETWORK_BLOCKED ssl_error=%s url=%s "
                            "(IP may be WAF-banned, try spoof_local_ip or wait)",
                            e, url)
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt == self.retry:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def head(self, url: str, **kwargs) -> Response:
        """带限速的 HEAD 请求，预读 body 释放连接"""
        bucket = self.limiter.get_bucket(self._domain_from_url(url))
        await bucket.acquire()
        session = await self._get_session()
        try:
            async with session.head(url, allow_redirects=True,
                                    max_redirects=self.max_redirects, **kwargs) as resp:
                text = await resp.text()
                return Response(resp.status, resp.headers, text)
        except (ssl.SSLError, aiohttp.ClientConnectorError) as e:
            _log.warning("NETWORK_BLOCKED ssl_error=%s url=%s "
                        "(IP may be WAF-banned, try spoof_local_ip or wait)",
                        e, url)
            raise

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
