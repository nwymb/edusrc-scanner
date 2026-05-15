from __future__ import annotations

import asyncio
import ssl
from typing import Optional

import aiohttp

from orchestrator.rate_limiter import get_limiter


class RateLimitedSession:
    """带令牌桶限速的 aiohttp 会话封装"""

    def __init__(self, qps: float = 5.0, timeout: float = 15.0,
                 user_agent: str = "eduSRC-Scanner/0.1",
                 max_redirects: int = 3, retry: int = 2):
        self.qps = qps
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        self.retry = retry
        self.limiter = get_limiter(default_qps=qps)
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_context, limit=20)
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers={"User-Agent": self.user_agent},
            )
        return self._session

    @staticmethod
    def _domain_from_url(url: str) -> str:
        from urllib.parse import urlparse
        return urlparse(url).hostname or url

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """带限速的 GET 请求"""
        bucket = self.limiter.get_bucket(self._domain_from_url(url))
        for attempt in range(self.retry + 1):
            await bucket.acquire()
            session = await self._get_session()
            try:
                resp = await session.get(url, allow_redirects=True,
                                         max_redirects=self.max_redirects, **kwargs)
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt == self.retry:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def head(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """带限速的 HEAD 请求"""
        bucket = self.limiter.get_bucket(self._domain_from_url(url))
        await bucket.acquire()
        session = await self._get_session()
        return await session.head(url, allow_redirects=True,
                                  max_redirects=self.max_redirects, **kwargs)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
