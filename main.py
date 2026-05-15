#!/usr/bin/env python3
"""eduSRC Scanner — 教育行业漏洞自动化扫描 Agent

Usage:
    python main.py --domain xxx.edu.cn
    python main.py --file targets.txt
    python main.py --domain xxx.edu.cn --dry-run
    python main.py --domain xxx.edu.cn --l3-only
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import yaml

sys.path.insert(0, str(Path(__file__).parent))

from orchestrator.scheduler import Scheduler, ScanPhase, MODULE_PHASE
from orchestrator.scope_guard import ScopeGuard
from shared.logger import AuditLogger, setup_std_logging


def load_config() -> dict:
    cfg_path = Path(__file__).parent / "orchestrator" / "config.yaml"
    with open(cfg_path) as f:
        return yaml.safe_load(f)


@click.command()
@click.option("--domain", "-d", default=None, help="单个目标域名")
@click.option("--file", "-f", default=None, help="目标域名列表文件，一行一个")
@click.option("--dry-run", is_flag=True, help="仅生成执行计划，不实际扫描")
@click.option("--l3-only", is_flag=True, help="仅执行 L3 被动检测")
@click.option("--out", "-o", default="data/output", help="输出目录")
def main(domain: str | None, file: str | None, dry_run: bool,
         l3_only: bool, out: str):
    cfg = load_config()
    setup_std_logging()

    log = AuditLogger(Path(out) / "audit.log")
    guard = ScopeGuard()

    seeds: list[str] = []
    if domain:
        seeds.append(domain)
    if file:
        seeds.extend(line.strip() for line in open(file) if line.strip())

    if not seeds:
        click.echo("请指定 --domain 或 --file 提供目标")
        sys.exit(1)

    in_scope = guard.filter_assets(seeds)
    out_of_scope = set(seeds) - set(in_scope)
    if out_of_scope:
        click.echo(f"[!] {len(out_of_scope)} 个目标不在允许范围内，已过滤: {out_of_scope}")
        log.warning("out_of_scope_filtered", filtered=list(out_of_scope))
    if not in_scope:
        click.echo("[!] 没有范围内的目标，退出")
        sys.exit(1)

    click.echo(f"[*] 范围内目标: {len(in_scope)} 个")

    modules: list[str] | None = None
    if l3_only:
        modules = [m for m, p in MODULE_PHASE.items()
                   if p in (ScanPhase.DISCOVERY, ScanPhase.ANALYSIS, ScanPhase.PASSIVE)]

    scheduler = Scheduler(logger=log)
    plan = scheduler.build_plan(in_scope, modules=modules, dry_run=dry_run)

    click.echo(f"[*] 执行计划: {len(plan.tasks)} 个任务")
    for phase in [ScanPhase.DISCOVERY, ScanPhase.ANALYSIS, ScanPhase.PASSIVE,
                  ScanPhase.ACTIVE, ScanPhase.REPORT]:
        pts = plan.by_phase(phase)
        if pts:
            click.echo(f"    {phase.value}: {len(pts)} tasks")

    if dry_run:
        click.echo("[*] dry-run 模式，不执行实际扫描")

    max_con = cfg["scheduler"]["max_concurrency"]
    asyncio.run(scheduler.execute(plan, max_concurrency=max_con))

    click.echo(f"[*] 完成，输出目录: {out}")
    log.info("scan_session_done", seeds=in_scope, task_count=len(plan.tasks))


if __name__ == "__main__":
    main()
