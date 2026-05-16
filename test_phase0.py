#!/usr/bin/env python3
"""Phase 0 验证: DeepSeek-V3 调用 send_http_request → httpbin.org"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from agent.llm_client import get_llm_client
from agent.tools import send_http_request, ALL_TOOLS
from shared.http_client import RateLimitedSession

TOOL_MAP = {"send_http_request": send_http_request}

SYSTEM_PROMPT = (
    "你是 AegisAgent，一个教育行业安全扫描 Agent。"
    "你可以调用 send_http_request 工具向目标发送 HTTP 请求。"
    "收到工具返回的结果后，请用中文简短总结服务器的回显内容。"
)

USER_PROMPT = (
    '请向 https://httpbin.org/post 发送一个 POST 请求。\n'
    '要求：\n'
    '- Headers 中必须包含 "X-Aegis-Agent": "Phase0-Test"\n'
    '- Body 为 JSON 格式：{"status": "agent_ready", "core": "deepseek-v3"}\n'
    '发送完毕后，请告诉我服务器的回显内容中，你的 Header 和 Body 是否被正确解析。'
)


async def main():
    print("=" * 60)
    print("AegisAgent Phase 0 — Tool Calling 验证")
    print("=" * 60)

    client, model = get_llm_client()
    print(f"[*] Model: {model}")

    session = RateLimitedSession(qps=5.0, timeout=15.0)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT},
    ]

    print("\n" + "-" * 40)
    print("[→] 发送 Prompt 给 DeepSeek...")
    print("-" * 40)

    resp = await client.chat.completions.create(
        model=model,
        messages=messages,
        tools=ALL_TOOLS,
        temperature=0.1,
    )

    msg = resp.choices[0].message
    round_num = 0

    while msg.tool_calls and round_num < 5:
        round_num += 1

        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ],
        })

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            tool_args = json.loads(tc.function.arguments)

            print(f"\n[Tool Call #{round_num}] {tool_name}")
            print(f"  Arguments: {json.dumps(tool_args, ensure_ascii=False)}")

            if tool_name in TOOL_MAP:
                result = await TOOL_MAP[tool_name](
                    url=tool_args.get("url", ""),
                    method=tool_args.get("method", "GET"),
                    headers=tool_args.get("headers"),
                    body=tool_args.get("body"),
                    session=session,
                )
            else:
                result = f"[ERROR] Unknown tool: {tool_name}"

            print(f"  Result ({len(result)} chars):")
            print(f"  {result[:500]}")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

        print(f"\n[→] 第 {round_num} 轮 LLM 请求...")

        resp = await client.chat.completions.create(
            model=model,
            messages=messages,
            tools=ALL_TOOLS,
            temperature=0.1,
        )
        msg = resp.choices[0].message

    print("\n" + "=" * 60)
    print("DeepSeek 最终回答:")
    print("=" * 60)
    print(msg.content or "(empty)")

    if msg.tool_calls:
        print(f"\n[!] 仍有未处理的 tool_calls: {len(msg.tool_calls)} 个")

    await session.close()
    print("\n[*] 测试完成。")


if __name__ == "__main__":
    asyncio.run(main())
