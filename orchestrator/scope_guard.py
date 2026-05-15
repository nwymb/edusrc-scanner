from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeGuard:
    """资产范围校验：只允许授权后缀和机构关键字的域名"""

    def __init__(self, config_path: str | Path = "orchestrator/config.yaml"):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        scope = cfg.get("scope", {})
        self.allowed_suffixes: list[str] = scope.get("allowed_suffixes", [".edu.cn"])
        self.allowed_keywords: list[str] = scope.get("allowed_keywords", [])

    def is_in_scope(self, domain_or_url: str) -> bool:
        """检查域名是否在允许范围内"""
        domain = self._extract_domain(domain_or_url)
        if not domain:
            return False
        domain = domain.lower()
        if any(domain.endswith(suffix) for suffix in self.allowed_suffixes):
            return True
        if any(kw in domain for kw in self.allowed_keywords):
            return True
        return False

    def filter_assets(self, assets: list[str]) -> list[str]:
        """过滤列表，返回范围内的资产"""
        return [a for a in assets if self.is_in_scope(a)]

    @staticmethod
    def _extract_domain(raw: str) -> str:
        """从 url 或裸域名中提取纯域名"""
        if "://" not in raw:
            raw = "http://" + raw
        try:
            return urlparse(raw).hostname or ""
        except Exception:
            return ""
