"""L5 自动化 EduSRC 战报生成器

将 ReAct 交互历史喂给 DeepSeek，生成符合 EduSRC 提交规范的 Markdown 漏洞报告。
"""

from __future__ import annotations

import json as _json
import logging
from pathlib import Path

from agent.llm_client import get_llm_client

_log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """你是国企和高校 SRC（安全响应中心）报告编写专家。
请根据以下自动化漏洞渗透交互历史，生成一份符合 EduSRC 提交规范的 Markdown 漏洞报告。

报告必须包含以下章节：
1. **漏洞名称**: 凝练准确
2. **漏洞评级**: 高危/严重，说明理由
3. **影响资产**: 列出受影响的 URL
4. **漏洞描述**: 说明漏洞原理和危害
5. **完整的漏洞复现步骤**: 根据交互历史，详细列出每一步操作，
   附带关键 Payload（URL、请求方法、参数）
6. **修复建议**: 具体可操作的修复措施

输出纯 Markdown，不要用代码块包裹。"""


async def compile_src_report(
    history: list[dict],
    target_url: str = "",
    api_key: str | None = None,
) -> str:
    """将 ReAct 交互历史编译为 EduSRC 漏洞报告。

    Args:
        history: run_exploit_loop 返回的 history 列表
        target_url: 目标 URL
        api_key: DeepSeek API Key

    Returns:
        Markdown 格式的漏洞报告
    """
    client, model = get_llm_client(api_key=api_key)

    history_text = _json.dumps(history, ensure_ascii=False, indent=2)

    user_prompt = (
        f"目标资产: {target_url}\n\n"
        f"自动化渗透交互历史 (JSON):\n{history_text}\n\n"
        f"请根据以上交互历史生成 EduSRC 漏洞报告。"
    )

    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
            max_tokens=4096,
        )

        report = resp.choices[0].message.content or ""

        out_dir = Path(__file__).resolve().parent.parent / "data" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "edusrc_finding.md").write_text(report, encoding="utf-8")

        _log.info("report_saved path=%s", out_dir / "edusrc_finding.md")
        return report

    except Exception as e:
        _log.error("report_generation_failed error=%s", e)
        return f"# 报告生成失败\n\n错误: {e}"
