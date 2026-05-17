#!/usr/bin/env python3
"""Phase 2 验证: Autonomous Pentest Agent — LLM 主驾驶"""

import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from agent.pentest_agent import autonomous_pentest
from agent.report_generator import compile_src_report

async def main():
    print("=" * 60)
    print("AegisAgent — Autonomous Pentest (LLM 主驾驶)")
    print("=" * 60)
    target = "http://127.0.0.1:8080/login.php"
    print(f"\n[*] 目标: {target}")
    print(f"[*] 最大步数: 20\n")

    result = await autonomous_pentest(target_url=target, max_steps=20)

    print("=" * 60)
    print("结果")
    print("=" * 60)
    print(f"成功: {result['success']}")
    print(f"状态: {result['status']}")
    print(f"步数: {result['steps']}")
    print(f"总结: {result['summary'][:500]}")

    print(f"\n{'=' * 60}")
    print("详细交互历史")
    print("=" * 60)
    for entry in result["history"]:
        print(f"\n--- Step {entry['step']} ---")
        if entry.get("thought"):
            print(f"[Thought] {entry['thought']}")
        if entry.get("action"):
            print(f"[Action] {entry['action']}")
        if entry.get("observation"):
            print(f"[Observation] {entry['observation']}")

    if result["success"] and result["history"]:
        print(f"\n{'=' * 60}")
        print("生成 EduSRC 战报...")
        print("=" * 60)
        report = await compile_src_report(history=result["history"], target_url=target)
        print(f"\n{'=' * 60}")
        print("EduSRC 漏洞报告")
        print("=" * 60)
        print(report)
    else:
        print(f"\n[!] 未成功利用，跳过战报生成。")

if __name__ == "__main__":
    asyncio.run(main())
