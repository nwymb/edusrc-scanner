"""L2 存活检测 — HTTP/HTTPS 探活 + 标题提取"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict

import aiohttp

from modules import register
from shared.models import Target

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_log = logging.getLogger(__name__)


def _extract_title(html: str) -> str:
    m = _TITLE_RE.search(html)
    if m:
        return m.group(1).strip()[:200]
    return ""


async def _probe(url: str, session) -> Target | None:
    try:
        resp = await session.head(url)
        status = resp.status
        title = ""
        if 200 <= status < 500:
            try:
                resp2 = await session.get(url)
                if resp2.status < 500:
                    text = await resp2.text()
                    title = _extract_title(text[:65536])
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        return Target(url=url, status_code=status, title=title)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("probe_failed url=%s error=%s", url, e)
        return None


@register("alive_check")
async def run(context: dict) -> dict:
    assets = context.get("assets", [])
    session = context["session"]
    logger = context["logger"]

    if not assets:
        logger.info("alive_check_skip", reason="no_assets")
        return {"targets": []}

    logger.info("alive_check_start", asset_count=len(assets))
    targets = []
    sem = asyncio.Semaphore(10)

    async def probe_one(asset: dict):
        domain = asset.get("domain", "")
        port = asset.get("port")
        if not domain:
            return
        urls = []
        if port:
            urls.append(f"https://{domain}:{port}")
            urls.append(f"http://{domain}:{port}")
        else:
            urls.append(f"https://{domain}")
            urls.append(f"http://{domain}")
        for url in urls:
            async with sem:
                target = await _probe(url, session)
            if target:
                targets.append(asdict(target))
                return

    await asyncio.gather(*[probe_one(a) for a in assets])

    logger.info("alive_check_done", probe_count=len(assets), alive=len(targets))
    return {"targets": targets}
