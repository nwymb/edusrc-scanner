"""L1 证书搜索 — crt.sh 深度证书查询 + 组织关联"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict

import aiohttp

from modules import register
from shared.models import Asset
from shared.utils import JSON_CLEAN_RE

_log = logging.getLogger(__name__)


@register("cert_search")
async def run(context: dict) -> dict:
    domain = context["target"]
    session = context["session"]
    logger = context["logger"]

    logger.info("cert_search_start", domain=domain)
    seen = set()
    assets = []

    async def query_crt(q: str, source_label: str):
        url = f"https://crt.sh/?q={q}&output=json"
        try:
            resp = await session.get(url)
            text = await resp.text()
            data = json.loads(JSON_CLEAN_RE.sub("", text))
            for entry in data:
                names = entry.get("name_value", "")
                org = entry.get("issuer_organization", entry.get("issuer_name", ""))
                for n in names.split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if not n or n in seen:
                        continue
                    seen.add(n)
                    asset_dict = asdict(Asset(domain=n, source=source_label))
                    if org:
                        asset_dict["org"] = org
                    assets.append(asset_dict)
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError,
                UnicodeDecodeError, ValueError) as e:
            _log.warning("crtsh_query_failed source=%s error=%s", source_label, e)

    await query_crt(f"%25.{domain}", "crtsh_wildcard")
    logger.info("cert_wildcard_done", domain=domain, so_far=len(assets))

    await query_crt(domain, "crtsh_exact")
    logger.info("cert_search_done", domain=domain, total=len(assets))

    return {"assets": assets}
