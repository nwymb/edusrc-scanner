"""L1 子域名发现 — crt.sh 证书透明 + DNS 字典爆破"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import asdict
from pathlib import Path

import aiohttp

from modules import register
from shared.models import Asset
from shared.utils import JSON_CLEAN_RE

BUILTIN_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "pop3", "imap",
    "ftp", "sftp", "ssh", "vpn", "svn", "git", "gitlab",
    "api", "open", "dev", "test", "demo", "stage", "staging",
    "admin", "manage", "manager", "portal", "dashboard", "console",
    "login", "sso", "auth", "oauth", "idp", "cas", "passport",
    "news", "blog", "wiki", "docs", "doc", "help", "support",
    "app", "m", "mobile", "wap", "wechat", "wx",
    "static", "static1", "static2", "cdn", "cdn1", "cdn2",
    "img", "images", "img1", "img2", "upload", "download", "file", "files",
    "video", "vod", "live", "media", "tv",
    "oa", "erp", "crm", "srm", "hr", "finance", "pay",
    "job", "zhaopin", "career", "recruit",
    "lib", "library", "book", "ebook", "tsg",
    "jw", "jwc", "jiaowu", "jwgl", "graduate", "yjs", "gs", "grs",
    "zs", "zsb", "zhaosheng", "xsc", "xg", "xgc",
    "ky", "kyc", "keyan", "kj", "kjc", "science",
    "net", "network", "nic", "dns", "ns", "ns1", "ns2",
    "v6", "ipv6", "v4", "ipv4",
    "cms", "web", "old", "new", "www2", "wwww",
    "bbs", "forum", "tieba",
    "union", "card", "ecard", "ykt", "ec",
    "meeting", "zoom", "jitsi", "room",
    "data", "db", "mysql", "redis",
    "monitor", "nagios", "zabbix", "grafana",
    "jenkins", "ci", "cd", "devops",
    "k8s", "kibana", "es", "elastic", "docker", "swarm",
    "ldap", "ad", "dc",
    "en", "jp", "global", "intl",
    "cet", "score", "exam", "kaoshi", "ks",
    "alumni", "xiaoyou",
    "pay", "payment", "alipay", "wxpay",
    "sms", "shortmessage",
    "backup", "bak", "temp", "tmp",
    "tools", "tool", "util",
    "proxy", "gateway", "gw", "relay",
]

_log = logging.getLogger(__name__)


def _load_wordlist(config: dict) -> list[str]:
    custom_path = config.get("discovery", {}).get("wordlist", "")
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return [line.strip() for line in p.read_text().splitlines() if line.strip()]
    return BUILTIN_WORDLIST


async def _crt_fetch(domain: str, session) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subs = set()
    try:
        resp = await session.get(url)
        text = await resp.text()
        cleaned = JSON_CLEAN_RE.sub("", text)
        data = json.loads(cleaned)
        for entry in data:
            name = entry.get("name_value", entry.get("common_name", ""))
            for n in name.split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n and n.endswith(domain) and n != domain:
                    subs.add(n)
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError,
            UnicodeDecodeError, ValueError) as e:
        _log.warning("crtsh_fetch_failed domain=%s error=%s", domain, e)
    return list(subs)


async def _dns_resolve(hostname: str) -> str | None:
    try:
        loop = asyncio.get_running_loop()
        info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        if info:
            return info[0][4][0]
    except (OSError, asyncio.TimeoutError) as e:
        _log.debug("dns_resolve_failed host=%s error=%s", hostname, e)
    return None


@register("subdomain")
async def run(context: dict) -> dict:
    domain = context["target"]
    session = context["session"]
    logger = context["logger"]
    config = context.get("config", {})

    logger.info("subdomain_start", domain=domain)

    crt_subs = await _crt_fetch(domain, session)
    logger.info("crtsh_done", domain=domain, count=len(crt_subs))

    wordlist = _load_wordlist(config)
    results = []
    sem = asyncio.Semaphore(50)

    async def probe(sub: str):
        host = f"{sub}.{domain}"
        ip = await _dns_resolve(host)
        if ip:
            results.append((host, ip))

    async def bounded(sub: str):
        async with sem:
            await probe(sub)

    await asyncio.gather(*[bounded(w) for w in wordlist])
    logger.info("dns_brute_done", domain=domain, count=len(results))

    seen = set()
    assets = []
    for sub in crt_subs:
        if sub not in seen:
            seen.add(sub)
            assets.append(asdict(Asset(domain=sub, source="crtsh")))
    for host, ip in results:
        if host not in seen:
            seen.add(host)
            assets.append(asdict(Asset(domain=host, ip=ip, source="dns_brute")))

    logger.info("subdomain_done", domain=domain, total=len(assets))
    return {"assets": assets}
