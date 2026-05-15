from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(str, Enum):
    L3_PASSIVE = "l3_passive"
    L4_ACTIVE = "l4_active"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── L1 产出 ──

@dataclass
class Asset:
    domain: str
    ip: Optional[str] = None
    port: Optional[int] = None
    source: str = ""  # subfinder / crtsh / fofa
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def key(self) -> str:
        return f"{self.domain}:{self.ip}:{self.port}"


# ── L2 产出 ──

@dataclass
class Target:
    url: str
    title: str = ""
    status_code: int = 0
    tech_stack: list[str] = field(default_factory=list)
    fingerprint: str = ""  # cms 名称 or 空
    value_score: int = 0
    is_login: bool = False
    is_admin: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def key(self) -> str:
        return self.url


# ── L3 / L4 产出 ──

@dataclass
class Finding:
    url: str
    vuln_type: str  # weak_password / unauth / sensitive_path / nday / idor / ...
    severity: VulnSeverity = VulnSeverity.INFO
    title: str = ""
    evidence: str = ""  # 证明漏洞存在的一段简述
    confidence: float = 0.0  # 0.0 ~ 1.0
    rank_estimate: float = 0.0  # 预估 edusrc Rank 分
    source: FindingSource = FindingSource.L3_PASSIVE
    source_module: str = ""  # sensitive_path / weak_pass / ...
    raw: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def key(self) -> str:
        """用于去重: 同 url + 同漏洞类型只保留一条"""
        return f"{self.url}|{self.vuln_type}"


# ── 调度任务 ──

@dataclass
class ScanTask:
    id: str
    module: str  # subdomain / alive_check / sensitive_path / weak_pass / ...
    target: str  # domain or url
    priority: int = 0  # 越小越优先
    depends_on: list[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[dict] = None
