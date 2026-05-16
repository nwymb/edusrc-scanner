"""Agent 资产情报分析 — 智能子域名字典生成

调用 DeepSeek-V3 根据机构全称和主域名，推测拼音缩写/英文变体/业务前缀。
"""

from __future__ import annotations

import json as _json
import logging

from agent.llm_client import get_llm_client

_log = logging.getLogger(__name__)

_FALLBACK_PREFIXES = [
    "www", "mail", "vpn", "oa", "test", "dev",
    "api", "admin", "portal", "sso", "cas", "lib",
]

_SYSTEM_PROMPT = """你是资深红队情报分析专家。根据目标机构名称和主域名，推测 40-60 个真实可能存在的子域名前缀。

规则（必须严格遵守）：
1. 每个前缀必须是 2-8 个字符的小写字母或数字，如 "sdjtu"、"jwc"、"mail1"
2. 仅产出以下类型的真实子域名前缀：
   - 机构名称的拼音首字母缩写（如 山东交通学院 → sdjtu, sdjtxy）
   - 高校核心业务系统缩写（jwc, yjs, zs, xsc, bgs, rsc, kyc, cwc, wlw, xcb）
   - 通用 IT 基础设施（www, mail, vpn, oa, cas, sso, portal, lib, ftp, dns, ns1, cdn, static）
   - 教学相关（mooc, elearning, exam, cet, lab, course, graduate, job）
   - 常见子系统（news, bbs, video, wiki, blog, forum, download, upload）
3. 严禁输出纯英文词典单词（如 "sleeping"、"stuff"、"thingamajig"）或任何与教育机构无关的词汇
4. 每个前缀必须是真实可能被用作域名前缀的字符串

严格只返回 JSON: {"prefixes": ["sdjtu", "jwc", "lib", ...]}"""


async def generate_smart_dict(
    org_name: str,
    base_domain: str,
    api_key: str | None = None,
) -> list[str]:
    """根据机构名称和主域名，用 DeepSeek 生成智能爆破字典。

    Args:
        org_name: 机构全称，如 "山东交通学院"
        base_domain: 主域名，如 "sdjtu.edu.cn"

    Returns:
        子域名前缀列表 (50-80 个)。异常时返回兜底列表。
    """
    client, model = get_llm_client(api_key=api_key)

    user_prompt = (
        f"目标机构全称: {org_name}\n"
        f"主域名: {base_domain}\n\n"
        f"请根据该机构的名称特征，生成推测的子域名前缀列表。"
        f"主域名中的核心词（如 sdjtu）务必包含在内。"
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
            response_format={"type": "json_object"},
        )

        raw = resp.choices[0].message.content or ""
        data = _json.loads(raw)
        prefixes: list[str] = data.get("prefixes", [])

        if not prefixes or not isinstance(prefixes, list):
            raise ValueError("LLM returned empty or invalid prefixes")

        # 过滤: 只保留 2-12 字符、纯小写字母数字、不含空格的短前缀
        cleaned = list({
            p.strip().lower() for p in prefixes
            if p and p.strip() and 2 <= len(p.strip()) <= 12
            and not any(c in p for c in (" ", "\n", "\t"))
        })
        _log.info("smart_dict_generated org=%s count=%d", org_name, len(cleaned))
        return cleaned

    except Exception as e:
        _log.warning("smart_dict_failed org=%s error=%s, using fallback", org_name, e)
        return list(_FALLBACK_PREFIXES)
