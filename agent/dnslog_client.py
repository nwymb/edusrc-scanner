"""DNSLog 盲打雷达 — 无回显漏洞 OOB 带外感知客户端。

支持 Interactsh 协议（默认，与 Nuclei/Burp 兼容），亦可切换 ceye.io 等后端。

管线接入:
    payload_generator (占位 {dnslog_domain}) → executor (替换 + 发探针 + 轮询)
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time as _time
from urllib.parse import urlparse

import httpx

_log = logging.getLogger(__name__)

_INTERACTSH_SERVER = "oast.pro"
_POLL_INTERVAL = 2       # 秒
_MAX_POLL_WAIT = 6        # 最大等待秒数


class DNSLogClient:
    """异步 OOB 客户端。

    用法:
        client = DNSLogClient()
        await client.register()
        domain = client.generate_domain("sqli-task1")
        # ... 发送 payload ...
        records = await client.poll_logs(domain)
    """

    def __init__(self, server: str = _INTERACTSH_SERVER):
        self._server = server
        self._base_url = f"https://{server}"
        self._correlation_id: str = secrets.token_hex(16)
        self._secret: str = secrets.token_hex(10)
        self._domain: str = ""
        self._registered = False

    async def register(self) -> bool:
        """向 Interactsh 服务器注册，获取唯一子域名。"""
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10), verify=False) as c:
                resp = await c.post(
                    f"{self._base_url}/register",
                    json={
                        "public-key": self._correlation_id,
                        "secret-key": self._secret,
                        "correlation-id": self._correlation_id,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._domain = data.get("interactsh_domain", "")
                    self._registered = True
                    _log.info("dnslog_registered domain=%s", self._domain)
                    return True
                _log.warning("dnslog_register_server_error status=%d", resp.status_code)
        except Exception as e:
            _log.warning("dnslog_register_failed server=%s error=%s", self._server, e)
        return False

    def generate_domain(self, task_id: str) -> str:
        """生成带追踪前缀的子域名。

        Args:
            task_id: 任务标识（如 'sqli-id-1'），用于追踪攻击向量

        Returns:
            f"{task_id}.{correlation_id}.{interactsh_domain}"
        """
        safe = task_id.replace("_", "-").replace(" ", "")[:50]
        return f"{safe}.{self._correlation_id}.{self._domain}"

    async def poll_logs(self, domain: str) -> list[dict]:
        """轮询 DNS/HTTP 交互记录，等待最多 MAX_POLL_WAIT 秒。

        Returns:
            [{"type": "dns|http", "ip": str, "full_id": str, "timestamp": str}, ...]
        """
        if not self._registered:
            return []

        target = domain.rstrip(".").lower()
        deadline = _time.monotonic() + _MAX_POLL_WAIT

        while _time.monotonic() < deadline:
            records = await self._fetch_logs()
            hit = [r for r in records if target in (r.get("full_id", "") or "").lower()]
            if hit:
                _log.info("dnslog_hit domain=%s records=%d", domain, len(hit))
                return hit
            await asyncio.sleep(_POLL_INTERVAL)

        # 最后一次 fetch
        records = await self._fetch_logs()
        return [r for r in records if target in (r.get("full_id", "") or "").lower()]

    async def _fetch_logs(self) -> list[dict]:
        """从 Interactsh 服务器拉取交互日志。"""
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10), verify=False) as c:
                resp = await c.get(
                    f"{self._base_url}/poll",
                    params={"id": self._correlation_id, "secret": self._secret},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("data", []) if isinstance(data, dict) else []
                    return [
                        {
                            "type": r.get("protocol", "dns"),
                            "full_id": r.get("full-id", ""),
                            "ip": r.get("remote-address", ""),
                            "timestamp": r.get("timestamp", ""),
                        }
                        for r in items
                    ]
        except Exception as e:
            _log.debug("dnslog_poll_error error=%s", e)
        return []
