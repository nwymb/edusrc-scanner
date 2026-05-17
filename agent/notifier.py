"""自动化告警通知 — 飞书/钉钉 Webhook

从 config.yaml 读取 webhook 配置，异步发送告警消息。
发送失败绝不阻塞主程序。
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path

import aiohttp
import yaml

_log = logging.getLogger(__name__)

_LEVEL_EMOJI = {
    "INFO":  "\U0001f7e2",
    "VULN":  "\U0001f6a8",
    "ERROR": "\U0001f534",
    "STOP":  "\U0001f6d1",
    "DONE":  "✅",
}

_PLATFORM_PAYLOAD = {
    "dingtalk": lambda m: {"msgtype": "text", "text": {"content": m}},
    "feishu":   lambda m: {"msgtype": "text", "text": {"content": m}},
}


def _load_webhook_config() -> dict:
    cfg_path = Path(__file__).resolve().parent.parent / "orchestrator" / "config.yaml"
    if not cfg_path.exists():
        return {}
    with open(cfg_path) as f:
        return yaml.safe_load(f).get("webhook", {})


async def send_alert(message: str, level: str = "INFO") -> None:
    """发送告警到配置的 Webhook。

    若未配置或 enabled=false，静默跳过。发送失败只记 debug，绝不 raise。
    """
    cfg = _load_webhook_config()
    if not cfg.get("enabled") or not cfg.get("url"):
        return

    emoji = _LEVEL_EMOJI.get(level, "")
    ts = datetime.now().strftime("%H:%M:%S")
    msg = f"AegisAgent {emoji} [{level}] {ts} — {message}"

    platform = cfg.get("platform", "dingtalk")
    build = _PLATFORM_PAYLOAD.get(platform, _PLATFORM_PAYLOAD["dingtalk"])
    payload = build(msg)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                cfg["url"], json=payload, timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    _log.debug("webhook_failed status=%s", resp.status)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _log.debug("webhook_error error=%s", e)
