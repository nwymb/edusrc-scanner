"""ReAct 核心引擎 — Thought → Action → Observation 自愈攻击循环

针对 unauth_bypass 场景，DeepSeek 分析 HTTP 响应 → 决策变异策略 → 调用
send_http_request 重试 → 直到成功或耗尽步数。
"""

from __future__ import annotations

import json as _json
import logging

from agent.llm_client import get_llm_client
from agent.tools import send_http_request, ALL_TOOLS
from shared.http_client import RateLimitedSession

_log = logging.getLogger(__name__)

TOOL_MAP = {"send_http_request": send_http_request}

_SYSTEM_PROMPT = """你是高级红队自动化 Agent。目标 URL 是 {target_url}。

任务：尝试寻找未授权访问漏洞或绕过 403 限制。
你必须调用 send_http_request 工具发包。

规则：
1. 首次请求用 GET 探测目标
2. 若收到 403/401，分析响应特征，变异策略：路径绕过/IP伪造/网关伪造/权限伪造
3. 仅仅 HTTP 200 不算成功！必须拿到以下具体证据才算真正 Bypass：
   - 响应头出现新的 Set-Cookie（获取了 Session 凭据）
   - 响应 Body 含受保护页面特征：如 "Welcome to"、phpinfo()、数据库报错、
     "Dashboard"、"后台管理"、用户列表、JSON 数据接口
4. 若连续 2 次收到相同错误且绕过无效，停止并报告失败
5. 当你确定攻击成功时，必须在总结的第一行写下：__EXPLOR_SUCCESS__
   例如: "__EXPLOR_SUCCESS__: 使用默认凭据 admin/password 成功登录"

每次必须调用工具后才能说话。停止条件：拿到具体证据 或 步数耗尽。"""


async def run_exploit_loop(
    target_url: str,
    attack_type: str = "unauth_bypass",
    max_steps: int = 3,
    api_key: str | None = None,
) -> dict:
    """ReAct 自愈攻击循环。

    Args:
        target_url: 目标 URL
        attack_type: 攻击类型，当前仅支持 "unauth_bypass"
        max_steps: 最大循环步数 (硬性安全帽, 绝对上限 5)
        api_key: DeepSeek API Key

    Returns:
        {"success": bool, "summary": str, "steps": int, "history": list[dict]}
    """
    max_steps = min(max_steps, 5)

    client, model = get_llm_client(api_key=api_key)
    session = RateLimitedSession(qps=5.0, timeout=15.0)

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT.format(target_url=target_url)},
        {"role": "user", "content": f"开始对 {target_url} 进行 {attack_type}。请发送第一个探测请求。"},
    ]

    history: list[dict] = []
    step = 0
    success = False
    summary = ""

    try:
        while step < max_steps:
            step += 1
            entry: dict = {"step": step, "thought": "", "actions": [], "observation": ""}

            resp = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=ALL_TOOLS,
                temperature=0.0,
                max_tokens=2048,
                extra_body={"thinking": {"type": "enabled"}},
            )
            msg = resp.choices[0].message
            reasoning = getattr(msg, "reasoning_content", "") or ""

            # 打印思考链到 stdout → 流入扫描日志
            if reasoning:
                print(f"\n[DS-Think step={step}]\n{reasoning}\n[/DS-Think]")

            # LLM 未调用工具 → 主动结束，检查 __EXPLOR_SUCCESS__ 标记
            if not msg.tool_calls:
                summary = msg.content or "(LLM 未返回内容)"
                entry["thought"] = summary
                entry["reasoning"] = reasoning
                history.append(entry)
                messages.append({"role": "assistant", "content": summary})
                if "__EXPLOR_SUCCESS__" in summary:
                    success = True
                break

            entry["thought"] = msg.content or ""
            entry["reasoning"] = reasoning

            # 追加 assistant 消息 (含 tool_calls)
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

            # 执行所有 Tool Call
            for tc in msg.tool_calls:
                tool_name = tc.function.name
                tool_args = _json.loads(tc.function.arguments)

                entry["actions"].append({"tool": tool_name, "args": tool_args})

                if tool_name in TOOL_MAP:
                    result = await TOOL_MAP[tool_name](
                        url=tool_args.get("url", target_url),
                        method=tool_args.get("method", "GET"),
                        headers=tool_args.get("headers"),
                        body=tool_args.get("body"),
                        session=session,
                    )
                else:
                    result = f"[ERROR] Unknown tool: {tool_name}"

                entry["observation"] = result[:2000]

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

            history.append(entry)

    except Exception as e:
        _log.error("exploit_loop_crashed url=%s error=%s", target_url, e)
        summary = f"Loop crashed: {e}"

    finally:
        await session.close()

    # 终局判定: 循环结束后给 LLM 一次不调工具的分析机会
    if not success and history:
        try:
            messages.append({
                "role": "user",
                "content": "步数已用完。请根据以上所有交互历史做最终判定。"
                           "如果你已成功获取 Session/敏感数据，第一行写 __EXPLOR_SUCCESS__。",
            })
            resp = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=[],  # 不给工具，强制纯文本输出
                temperature=0.0,
                max_tokens=1024,
                extra_body={"thinking": {"type": "enabled"}},
            )
            final_msg = resp.choices[0].message.content or ""
            final_reasoning = getattr(resp.choices[0].message, "reasoning_content", "") or ""
            if final_reasoning:
                print(f"\n[DS-Think final]\n{final_reasoning}\n[/DS-Think]")
            summary = final_msg
            if "__EXPLOR_SUCCESS__" in final_msg:
                success = True
        except Exception as e:
            _log.debug("final_judge_failed error=%s", e)

    if not summary:
        summary = f"已执行 {step} 步，未获取到敏感数据，循环终止。"

    return {
        "success": success,
        "summary": summary,
        "steps": step,
        "history": history,
    }
