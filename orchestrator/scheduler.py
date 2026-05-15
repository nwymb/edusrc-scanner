from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum

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

    def __init__(self, logger: AuditLogger | None = None):
        self.logger = logger or AuditLogger()

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
            for m in ["weak_pass", "unauth_check", "idor_check", "nday_poc"]:
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
        """按阶段顺序执行计划"""
        sem = asyncio.Semaphore(max_concurrency)

        for phase in PHASE_ORDER:
            phase_tasks = plan.by_phase(phase)
            if not phase_tasks:
                continue
            self.logger.info(f"starting phase {phase.value}", task_count=len(phase_tasks))
            phase_tasks.sort(key=lambda t: t.priority)

            async def run(t: ScanTask):
                async with sem:
                    t.status = TaskStatus.RUNNING
                    self.logger.info("running task", task_id=t.id, module=t.module, target=t.target)
                    await asyncio.sleep(0.01)  # placeholder: 实际执行由各模块 handler 完成
                    t.status = TaskStatus.DONE

            await asyncio.gather(*[run(t) for t in phase_tasks if t.status == TaskStatus.PENDING])

        self.logger.info("scan plan complete")
