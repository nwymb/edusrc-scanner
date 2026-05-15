"""L1 FOFA/鹰图 API — 网络空间搜索引擎资产发现"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from dataclasses import asdict

import aiohttp

from modules import register
from shared.models import Asset

_log = logging.getLogger(__name__)


def _get_fofa_creds(config: dict) -> tuple[str, str] | None:
    apis = config.get("apis", {})
    fofa = apis.get("fofa", {})
    email = fofa.get("email") or os.environ.get("FOFA_EMAIL", "")
    key = fofa.get("key") or os.environ.get("FOFA_KEY", "")
    enabled = fofa.get("enabled", False)
    if email and key and enabled:
        return email, key
    return None


def _get_hunter_creds(config: dict) -> str | None:
    apis = config.get("apis", {})
    hunter = apis.get("hunter", {})
    key = hunter.get("key") or os.environ.get("HUNTER_KEY", "")
    enabled = hunter.get("enabled", False)
    if key and enabled:
        return key
    return None


async def _fofa_search(domain: str, email: str, key: str, session) -> list[dict]:
    """FOFA API — 密钥位于 query string（该 API 不支持 header auth）"""
    q = f'domain="{domain}"'
    q_b64 = base64.b64encode(q.encode()).decode()
    url = (
        f"https://fofa.info/api/v1/search/all"
        f"?email={email}&key={key}&qbase64={q_b64}&size=200&fields=host,ip,port"
    )
    try:
        resp = await session.get(url, allow_redirects=False)
        data = json.loads(await resp.text())
        if data.get("error"):
            _log.warning("fofa_api_error error=%s", data.get("error"))
            return []
        results = []
        for host in data.get("results", []):
            if isinstance(host, list) and len(host) >= 2:
                results.append({
                    "domain": host[0], "ip": host[1],
                    "port": host[2] if len(host) > 2 else None,
                })
        return results
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError,
            ValueError) as e:
        _log.warning("fofa_request_failed error=%s", e)
        return []


async def _hunter_search(domain: str, key: str, session) -> list[dict]:
    """鹰图 API — 密钥位于 query string（该 API 不支持 header auth）"""
    q = f'domain.suffix="edu.cn"&&domain="{domain}"'
    q_b64 = base64.urlsafe_b64encode(q.encode()).decode()
    url = (
        f"https://hunter.qianxin.com/openApi/search"
        f"?api-key={key}&search={q_b64}&page=1&page_size=200"
    )
    try:
        resp = await session.get(url, allow_redirects=False)
        data = json.loads(await resp.text())
        if data.get("code") != 200:
            _log.warning("hunter_api_error code=%s msg=%s",
                         data.get("code"), data.get("message", ""))
            return []
        results = []
        for item in data.get("data", {}).get("arr", []):
            results.append({
                "domain": item.get("domain", ""),
                "ip": item.get("ip", ""),
                "port": item.get("port"),
            })
        return results
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError,
            ValueError) as e:
        _log.warning("hunter_request_failed error=%s", e)
        return []


@register("fofa_search")
async def run(context: dict) -> dict:
    domain = context["target"]
    session = context["session"]
    logger = context["logger"]
    config = context.get("config", {})

    logger.info("fofa_search_start", domain=domain)
    assets = []
    seen = set()

    fofa_creds = _get_fofa_creds(config)
    if fofa_creds:
        email, key = fofa_creds
        results = await _fofa_search(domain, email, key, session)
        logger.info("fofa_done", domain=domain, count=len(results))
        for r in results:
            if r["domain"] and r["domain"] not in seen:
                seen.add(r["domain"])
                assets.append(asdict(Asset(
                    domain=r["domain"], ip=r.get("ip"),
                    port=r.get("port"), source="fofa",
                )))
    else:
        logger.info("fofa_skipped", domain=domain, reason="no_credentials")

    hunter_key = _get_hunter_creds(config)
    if hunter_key:
        results = await _hunter_search(domain, hunter_key, session)
        logger.info("hunter_done", domain=domain, count=len(results))
        for r in results:
            if r["domain"] and r["domain"] not in seen:
                seen.add(r["domain"])
                assets.append(asdict(Asset(
                    domain=r["domain"], ip=r.get("ip"),
                    port=r.get("port"), source="hunter",
                )))
    else:
        logger.info("hunter_skipped", domain=domain, reason="no_credentials")

    logger.info("fofa_search_done", domain=domain, total=len(assets))
    return {"assets": assets}
