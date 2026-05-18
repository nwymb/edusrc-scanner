"""全局记忆中枢 — 跨请求、跨页面的信息记忆，支撑 Exploit Chaining。

单例模式，所有模块共享同一份记忆。支持 JSON 持久化，扫描结束后不清空。
"""

from __future__ import annotations

import json as _json
import logging
import threading
from pathlib import Path

_log = logging.getLogger(__name__)

_MEMORY_FILE = Path(__file__).resolve().parent.parent / "data" / "output" / "agent_memory.json"


class AgentMemory:
    """跨请求记忆管理器（单实例）。

    用法:
        mem = AgentMemory.get()
        mem.set("emails", ["admin@test.edu.cn"])
        mem.save()           # 持久化到磁盘
        mem.load()           # 从磁盘恢复
    """

    _instance: AgentMemory | None = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._store: dict[str, list] = {}

    @classmethod
    def get(cls) -> AgentMemory:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
                    cls._instance.load()
        return cls._instance

    def set(self, key: str, value: object) -> None:
        """追加式写入，同名 key 自动去重。"""
        existing = self._store.get(key, [])
        if isinstance(value, list):
            for v in value:
                if v not in existing:
                    existing.append(v)
        elif value not in existing:
            existing.append(value)
        self._store[key] = existing

    def fetch(self, key: str) -> list:
        """读取记忆。"""
        return self._store.get(key, [])

    def all(self) -> dict:
        return dict(self._store)

    def save(self) -> None:
        try:
            _MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(_MEMORY_FILE, "w", encoding="utf-8") as f:
                _json.dump(self._store, f, ensure_ascii=False, indent=2)
        except OSError as e:
            _log.warning("memory_save_failed error=%s", e)

    def load(self) -> None:
        try:
            if _MEMORY_FILE.exists():
                with open(_MEMORY_FILE, "r", encoding="utf-8") as f:
                    self._store = _json.load(f)
        except (OSError, _json.JSONDecodeError) as e:
            _log.warning("memory_load_failed error=%s", e)
            self._store = {}

    def reset(self) -> None:
        self._store.clear()
