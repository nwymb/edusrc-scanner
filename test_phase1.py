#!/usr/bin/env python3
"""Phase 3-L1 验证: DeepSeek 智能子域名字典生成"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from agent.asset_brain import generate_smart_dict


async def main():
    print("=" * 60)
    print("AegisAgent Phase 3-L1 — 智能资产字典生成")
    print("=" * 60)

    org = "中国科学技术大学"
    domain = "ustc.edu.cn"

    print(f"\n[*] 目标: {org} ({domain})")
    print("[*] 正在请求 DeepSeek 生成字典...")

    prefixes = await generate_smart_dict(org_name=org, base_domain=domain)

    print(f"\n{'=' * 60}")
    print(f"生成前缀数量: {len(prefixes)}")
    print(f"{'=' * 60}")
    print(", ".join(prefixes))
    print(f"\n[*] 完成。")


if __name__ == "__main__":
    asyncio.run(main())
