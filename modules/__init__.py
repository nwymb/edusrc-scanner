"""eduSRC Scanner — 模块注册表

每个模块暴露一个 async def run(context: dict) -> dict 函数。
context 包含: target, session, logger, config, assets(L1→L2), targets(L2→L3)
"""

from __future__ import annotations

from typing import Any, Callable, Awaitable

MODULE_REGISTRY: dict[str, Callable[[dict], Awaitable[dict]]] = {}


def register(name: str):
    """装饰器: 注册模块 handler"""
    def decorator(fn):
        MODULE_REGISTRY[name] = fn
        return fn
    return decorator


# 触发所有模块的 import-time 注册
from modules.l1_discovery import subdomain      # noqa: F401
from modules.l1_discovery import cert_search     # noqa: F401
from modules.l1_discovery import fofa_client     # noqa: F401
from modules.l2_analysis import alive_check      # noqa: F401
from modules.l2_analysis import fingerprint      # noqa: F401
from modules.l2_analysis import value_scorer     # noqa: F401
from modules.l3_passive import sensitive_path    # noqa: F401
from modules.l3_passive import config_leak       # noqa: F401
from modules.l4_active import weak_pass          # noqa: F401
from modules.l4_active import unauth_check       # noqa: F401
from modules.l4_active import nuclei_scanner      # noqa: F401
from modules.l4_active import nday_poc           # noqa: F401
from modules.l4_active import idor_check          # noqa: F401
from modules.l5_output import dedup               # noqa: F401
from modules.l5_output import report              # noqa: F401
