"""L2 技术栈指纹 — 基于响应头 + HTML 内容的 CMS/框架识别"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import aiohttp
import yaml

from modules import register

_log = logging.getLogger(__name__)

# 项目根（用于解析相对路径）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_rules(config: dict) -> list[dict]:
    default_path = _PROJECT_ROOT / "data" / "fingerprints" / "cms_patterns.yaml"
    path = config.get("fingerprint", {}).get("rules_file", str(default_path))
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])
    except (FileNotFoundError, yaml.YAMLError) as e:
        _log.warning("fingerprint_rules_load_failed path=%s error=%s", path, e)
        return []


async def _fingerprint_one(target: dict, rules: list[dict], session) -> dict:
    url = target.get("url", "")
    if not url:
        return target

    tech_stack = list(target.get("tech_stack", []))
    fingerprint = target.get("fingerprint", "")

    try:
        resp = await session.get(url)
        headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = await resp.text()
        body_sample = body[:131072]
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("fingerprint_fetch_failed url=%s error=%s", url, e)
        return target

    matched = set()
    for rule in rules:
        name = rule.get("name", "")
        if name in matched:
            continue
        for pat in rule.get("patterns", []):
            if pat.lower() in headers_text.lower():
                matched.add(name)
                break
        if name not in matched:
            for pat in rule.get("body_patterns", []):
                if pat.lower() in body_sample.lower():
                    matched.add(name)
                    break
        if name not in matched:
            for pat in rule.get("path_patterns", []):
                if pat.lower() in url.lower():
                    matched.add(name)
                    break

    if matched:
        tech_stack = sorted(set(tech_stack) | matched)
        for m in matched:
            for rule in rules:
                if rule.get("name") == m and rule.get("category") == "CMS":
                    fingerprint = m
                    break
        if not fingerprint:
            fingerprint = next(iter(matched))

    target["tech_stack"] = tech_stack
    target["fingerprint"] = fingerprint
    return target


@register("fingerprint")
async def run(context: dict) -> dict:
    targets = context.get("targets", [])
    session = context["session"]
    logger = context["logger"]
    config = context.get("config", {})

    if not targets:
        logger.info("fingerprint_skip", reason="no_targets")
        return {"targets": []}

    logger.info("fingerprint_start", target_count=len(targets))
    rules = _load_rules(config)

    sem = asyncio.Semaphore(5)
    result = []

    async def probe_one(t: dict):
        async with sem:
            result.append(await _fingerprint_one(t, rules, session))

    await asyncio.gather(*[probe_one(t) for t in targets])

    identified = sum(1 for t in result if t.get("fingerprint"))
    logger.info("fingerprint_done", total=len(result), identified=identified)
    return {"targets": result}
