"""LLM 客户端 — DeepSeek-V3 (OpenAI SDK 兼容)

配置读取优先级: 参数 > 环境变量 > orchestrator/config.yaml
- DEEPSEEK_API_KEY: API 密钥
- DEEPSEEK_BASE_URL: 默认 https://api.deepseek.com/v1
- DEEPSEEK_MODEL: 默认 deepseek-chat
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
import httpx
from openai import AsyncOpenAI

_log = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
_DEFAULT_MODEL = "deepseek-chat"


def _load_config() -> dict:
    cfg_path = Path(__file__).resolve().parent.parent / "orchestrator" / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def get_llm_client(
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> tuple[AsyncOpenAI, str]:
    """工厂函数：创建 AsyncOpenAI 客户端实例。

    每次调用返回新实例，避免 Agent 循环中单例状态污染。

    Returns:
        (AsyncOpenAI, model_name)
    """
    cfg = _load_config()
    llm_cfg = cfg.get("llm", {})

    resolved_key = (
        api_key
        or os.getenv("DEEPSEEK_API_KEY")
        or llm_cfg.get("api_key", "")
    )
    resolved_base = (
        base_url
        or os.getenv("DEEPSEEK_BASE_URL")
        or llm_cfg.get("base_url", _DEFAULT_BASE_URL)
    )
    resolved_model = (
        model
        or os.getenv("DEEPSEEK_MODEL")
        or llm_cfg.get("model", _DEFAULT_MODEL)
    )

    if not resolved_key:
        _log.warning("DEEPSEEK_API_KEY not set — LLM calls will fail")

    http_client = httpx.AsyncClient(proxy=None, timeout=httpx.Timeout(120.0))
    client = AsyncOpenAI(api_key=resolved_key, base_url=resolved_base,
                         http_client=http_client)
    return client, resolved_model
