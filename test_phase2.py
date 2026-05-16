#!/usr/bin/env python3
"""Phase 2 验证: ReAct 自愈攻击循环 + EduSRC 战报生成"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from agent.react_core import run_exploit_loop
from agent.report_generator import compile_src_report


async def main():
    print("=" * 60)
    print("AegisAgent Phase 2 — ReAct 自愈攻击循环")
    print("=" * 60)

    target = "http://127.0.0.1:8080/login.php"

    print(f"\n[*] 目标: {target}")
    print(f"[*] 攻击类型: unauth_bypass")
    print(f"[*] 最大步数: 4\n")

    result = await run_exploit_loop(
        target_url=target,
        attack_type="unauth_bypass",
        max_steps=4,
    )

    print("=" * 60)
    print("循环结果")
    print("=" * 60)
    print(f"成功: {result['success']}")
    print(f"步数: {result['steps']}")
    print(f"总结: {result['summary']}")

    print(f"\n{'=' * 60}")
    print("详细交互历史")
    print("=" * 60)

    for entry in result["history"]:
        print(f"\n--- Step {entry['step']} ---")
        if entry["thought"]:
            print(f"[Thought] {entry['thought'][:300]}")
        for act in entry["actions"]:
            print(f"[Action] {act['tool']}({json.dumps(act['args'], ensure_ascii=False)})")
        if entry["observation"]:
            print(f"[Observation] {entry['observation'][:400]}")

    # ── L5 战报生成 ──
    if result["success"] and result["history"]:
        print(f"\n{'=' * 60}")
        print("生成 EduSRC 战报...")
        print("=" * 60)

        report = await compile_src_report(
            history=result["history"],
            target_url=target,
        )

        print(f"\n{'=' * 60}")
        print("EduSRC 漏洞报告 (data/reports/edusrc_finding.md)")
        print("=" * 60)
        print(report)
    else:
        print(f"\n[!] 未成功利用，跳过战报生成。")


if __name__ == "__main__":
    asyncio.run(main())

