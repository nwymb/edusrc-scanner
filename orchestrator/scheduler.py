from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum

from modules import MODULE_REGISTRY
from shared.http_client import RateLimitedSession
from shared.logger import AuditLogger
from shared.models import ScanTask, TaskStatus


class ScanPhase(str, Enum):
    DISCOVERY   = "l1_discovery"
    ANALYSIS    = "l2_analysis"
    PASSIVE     = "l3_passive"
    ACTIVE      = "l4_active"
    REPORT      = "l5_output"


# 模块 → 所属阶段映射
MODULE_PHASE: dict[str, ScanPhase] = {
    # L1
    "subdomain":     ScanPhase.DISCOVERY,
    "cert_search":   ScanPhase.DISCOVERY,
    "fofa_search":   ScanPhase.DISCOVERY,
    # L2
    "alive_check":   ScanPhase.ANALYSIS,
    "fingerprint":   ScanPhase.ANALYSIS,
    "value_score":   ScanPhase.ANALYSIS,
    # L3
    "sensitive_path": ScanPhase.PASSIVE,
    "config_leak":    ScanPhase.PASSIVE,
    # L4
    "weak_pass":     ScanPhase.ACTIVE,
    "unauth_check":  ScanPhase.ACTIVE,
    "idor_check":    ScanPhase.ACTIVE,
    "nuclei_scanner": ScanPhase.ACTIVE,
    "nday_poc":      ScanPhase.ACTIVE,
    # L5
    "dedup":         ScanPhase.REPORT,
    "report":        ScanPhase.REPORT,
}

PHASE_ORDER = [ScanPhase.DISCOVERY, ScanPhase.ANALYSIS, ScanPhase.PASSIVE,
               ScanPhase.ACTIVE, ScanPhase.REPORT]


@dataclass
class ScanPlan:
    tasks: list[ScanTask] = field(default_factory=list)

    def add(self, task: ScanTask):
        self.tasks.append(task)

    def pending(self) -> list[ScanTask]:
        return [t for t in self.tasks if t.status == TaskStatus.PENDING]

    def by_phase(self, phase: ScanPhase) -> list[ScanTask]:
        return [t for t in self.tasks if MODULE_PHASE.get(t.module) == phase]


class Scheduler:
    """编排引擎：生成 ScanPlan → 按阶段+优先级执行"""

    def __init__(self, logger: AuditLogger | None = None, config: dict | None = None):
        self.logger = logger or AuditLogger()
        self._config = config or {}

    def build_plan(self, seeds: list[str], modules: list[str] | None = None,
                   dry_run: bool = False) -> ScanPlan:
        """
        seeds: 域名列表
        modules: 要启用的模块列表，None = 全部
        """
        if modules is None:
            modules = list(MODULE_PHASE.keys())

        plan = ScanPlan()
        task_id = 0

        for seed in seeds:
            # L1
            if "subdomain" in modules:
                task_id += 1
                plan.add(ScanTask(id=str(task_id), module="subdomain", target=seed, priority=1))
            if "cert_search" in modules:
                task_id += 1
                plan.add(ScanTask(id=str(task_id), module="cert_search", target=seed, priority=1))
            if "fofa_search" in modules:
                task_id += 1
                plan.add(ScanTask(id=str(task_id), module="fofa_search", target=seed, priority=1))

            # L2 (依赖 L1 产出的 assets)
            for m in ["alive_check", "fingerprint", "value_score"]:
                if m in modules:
                    task_id += 1
                    plan.add(ScanTask(id=str(task_id), module=m, target=seed,
                                      priority=2, depends_on=["subdomain"]))

            # L3 (依赖 L2 产出的 targets)
            for m in ["sensitive_path", "config_leak"]:
                if m in modules:
                    task_id += 1
                    plan.add(ScanTask(id=str(task_id), module=m, target=seed,
                                      priority=3, depends_on=["alive_check"]))

            # L4 (依赖 L3 的执行结果)
            for m in ["nuclei_scanner", "weak_pass", "unauth_check", "idor_check", "nday_poc"]:
                if m in modules:
                    task_id += 1
                    plan.add(ScanTask(id=str(task_id), module=m, target=seed,
                                      priority=4, depends_on=["sensitive_path"]))

            # L5 (依赖 L4 的 findings)
            for m in ["dedup", "report"]:
                if m in modules:
                    task_id += 1
                    plan.add(ScanTask(id=str(task_id), module=m, target=seed, priority=5))

        if dry_run:
            self.logger.info("dry_run plan generated", task_count=len(plan.tasks))

        return plan

    async def execute(self, plan: ScanPlan, max_concurrency: int = 10):
        """按阶段顺序执行计划，阶段间传递资产数据"""
        cfg = getattr(self, "_config", {})
        cfg_http = cfg.get("http", {})
        cfg_rate = cfg.get("rate_limit", {})

        session = RateLimitedSession(
            qps=cfg_rate.get("default_qps", 5.0),
            timeout=cfg_http.get("timeout", 15.0),
            user_agent=cfg_http.get("user_agent", "eduSRC-Scanner/0.1"),
            max_redirects=cfg_http.get("max_redirects", 3),
            retry=cfg_http.get("retry", 2),
            verify_ssl=cfg_http.get("verify_ssl", True),
            spoof_local_ip=cfg_http.get("spoof_local_ip", False),
            proxy=cfg_http.get("proxy", ""),
        )

        sem = asyncio.Semaphore(max_concurrency)
        # 阶段间数据累积
        phase_assets: dict[str, list[dict]] = {}  # seed → assets
        phase_targets: dict[str, list[dict]] = {}  # seed → targets
        phase_findings: list[dict] = []             # all findings (L3+L4)

        try:
            for phase in PHASE_ORDER:
                phase_tasks = plan.by_phase(phase)
                if not phase_tasks:
                    continue
                self.logger.info(f"starting phase {phase.value}", task_count=len(phase_tasks))
                phase_tasks.sort(key=lambda t: t.priority)

                pending = [t for t in phase_tasks if t.status == TaskStatus.PENDING]

                async def run(t: ScanTask) -> dict | None:
                    async with sem:
                        t.status = TaskStatus.RUNNING
                        self.logger.info("running task", task_id=t.id, module=t.module, target=t.target)
                        handler = MODULE_REGISTRY.get(t.module)
                        if handler is None:
                            t.status = TaskStatus.SKIPPED
                            self.logger.warning("no handler for module", module=t.module)
                            return None

                        ctx = {
                            "target": t.target,
                            "session": session,
                            "logger": self.logger,
                            "config": cfg,
                            "assets": phase_assets.get(t.target, []),
                            "targets": phase_targets.get(t.target, []),
                            "findings": phase_findings,
                        }
                        try:
                            result = await handler(ctx)
                            t.status = TaskStatus.DONE
                            t.result = result
                            return result
                        except Exception:
                            t.status = TaskStatus.FAILED
                            self.logger.error("task failed", task_id=t.id, module=t.module, target=t.target)
                            return None

                results = await asyncio.gather(*[run(t) for t in pending])

                # 收集阶段产出
                for t, r in zip(pending, results):
                    if r is None:
                        continue
                    if phase == ScanPhase.DISCOVERY:
                        phase_assets.setdefault(t.target, []).extend(r.get("assets", []))
                    elif phase == ScanPhase.ANALYSIS:
                        phase_targets.setdefault(t.target, []).extend(r.get("targets", []))
                    elif phase in (ScanPhase.PASSIVE, ScanPhase.ACTIVE):
                        phase_findings.extend(r.get("findings", []))

                # 兜底: L1 无产出时注入 seed domain 作为保底资产
                if phase == ScanPhase.DISCOVERY:
                    all_seeds = {t.target for t in plan.tasks}
                    for seed in all_seeds:
                        if not phase_assets.get(seed):
                            fallback = {
                                "domain": seed,
                                "ip": None,
                                "port": None,
                                "source": "fallback",
                            }
                            phase_assets[seed] = [fallback]
                            self.logger.info("fallback_asset", seed=seed,
                                             reason="L1_no_discovery")

        finally:
            await session.close()

        self.logger.info("scan plan complete",
                         assets=sum(len(v) for v in phase_assets.values()),
                         targets=sum(len(v) for v in phase_targets.values()),
                         findings=len(phase_findings))
        return phase_assets, phase_targets, phase_findings
