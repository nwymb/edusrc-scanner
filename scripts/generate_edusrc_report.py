#!/usr/bin/env python3
"""EduSRC 漏洞报告生成器 — 读取 findings.json，输出可直接粘贴到 EduSRC 平台的 Markdown。

用法:
    python3 scripts/generate_edusrc_report.py [findings.json路径]
"""

from __future__ import annotations

import json as _json
import sys
from pathlib import Path
from urllib.parse import urlparse

_TYPE_CATEGORY_MAP = {
    "sqli":          "Web漏洞 -> SQL注入",
    "xss":           "Web漏洞 -> XSS跨站脚本",
    "unauth":        "Web漏洞 -> 未授权访问",
    "sensitive_path": "Web漏洞 -> 信息泄露",
    "config_leak":   "Web漏洞 -> 信息泄露",
    "rce":           "Web漏洞 -> 命令执行",
    "ssrf":          "Web漏洞 -> SSRF服务端请求伪造",
    "idor":          "逻辑缺陷 -> 越权访问",
    "weak_pass":     "Web漏洞 -> 弱口令",
}

_CRITICAL_TYPES = {"sqli", "rce", "ssrf", "idor", "weak_pass"}


def _severity_label(entry: dict) -> str:
    vt = (entry.get("vulnerability_type") or entry.get("vuln_type", "")).lower()
    conf = entry.get("confidence", 0)
    if entry.get("oob_confirmed") or conf >= 95:
        return "严重"
    if vt in _CRITICAL_TYPES or conf >= 80:
        return "高危"
    sev = entry.get("severity", "")
    sev_str = sev.value if hasattr(sev, "value") else str(sev).lower()
    if sev_str in ("critical", "high"):
        return "高危"
    if sev_str == "medium":
        return "中危"
    return "低危"


def _fix_suggestion(vuln_type: str) -> str:
    t = vuln_type.lower()
    if "sqli" in t:
        return ("1. 使用参数化查询 (PreparedStatement)，禁止拼接 SQL\n"
                "2. 对所有用户输入做严格白名单校验\n"
                "3. 数据库账号遵循最小权限原则，禁用高危存储过程")
    if "xss" in t:
        return ("1. 对输出到页面的用户数据做 HTML 实体编码\n"
                "2. 设置 Content-Security-Policy 响应头\n"
                "3. Cookie 设置 HttpOnly 标志防会话劫持")
    if "unauth" in t or "sensitive_path" in t or "config_leak" in t:
        return ("1. 对敏感路径添加认证/授权拦截\n"
                "2. 生产环境禁用 Swagger/Druid/Actuator 等调试组件\n"
                "3. 网关层统一收敛 /admin /api /druid /swagger 等路径访问")
    if "rce" in t:
        return ("1. 禁止执行外部输入的命令或代码\n"
                "2. 使用沙箱/容器隔离不可信代码\n"
                "3. 严格过滤 eval/system/exec 等危险函数参数")
    if "ssrf" in t:
        return ("1. 对用户提交的 URL 做白名单限制\n"
                "2. 禁止访问内网地址段 (10/8, 172.16/12, 192.168/16)\n"
                "3. 使用独立代理隔离外网请求")
    return "1. 建议根据漏洞类型针对性修复"


def _extract_org(url: str) -> str:
    host = urlparse(url).hostname or "unknown"
    return host


def generate_report(findings: list[dict]) -> str:
    lines: list[str] = []
    lines.append("# EduSRC 漏洞提交报告\n")
    lines.append(f"> 自动生成 | 总计 {len(findings)} 个漏洞 | AegisAgent Scanner\n")
    lines.append("---\n")

    for i, entry in enumerate(findings, 1):
        url = entry.get("target_url") or entry.get("url", "")
        vt = entry.get("vulnerability_type") or entry.get("vuln_type", "unknown")
        title = entry.get("title", "")
        evidence = entry.get("evidence", "")
        payload_str = entry.get("payload", "")
        param = entry.get("target_parameter", "")
        oob = entry.get("oob_confirmed", False)
        confidence = entry.get("confidence", 0)
        host = _extract_org(url)
        sev = _severity_label(entry)
        cat = _TYPE_CATEGORY_MAP.get(vt.lower(), f"Web漏洞 -> {vt}")

        lines.append(f"## 漏洞 #{i}\n")
        lines.append("| 字段 | 内容 |")
        lines.append("|------|------|")
        lines.append(f"| **标题** | [{host}] {title} |")
        lines.append(f"| **分类** | {cat} |")
        lines.append(f"| **等级** | {sev} |")
        lines.append(f"| **是否需要账号认证** | 否 |")
        lines.append(f"| **漏洞 URL** | {url} |")
        lines.append("")

        # 一、漏洞描述
        desc = f"在 `{url}` 页面"
        if param:
            desc += f"的 `{param}` 参数处"
        desc += f"发现 {vt.upper()} 漏洞。"
        if confidence:
            desc += f" 检测置信度 {confidence}/100。"
        if oob:
            desc += " 该漏洞通过 DNSLog 带外交互确认，确凿存在。"

        lines.append("### 一、漏洞描述\n")
        lines.append(desc)
        lines.append("")

        # 二、复现证明
        lines.append("### 二、漏洞复现证明\n")
        lines.append(f"**步骤 1**：访问目标 URL：`{url}`\n")

        if payload_str:
            lines.append(f"**步骤 2**：构造并发送以下 Payload：\n")
            lines.append("```text")
            lines.append(payload_str)
            lines.append("```\n")

        lines.append("**步骤 3**：观察响应：\n")
        if oob:
            lines.append("> ⚡ **DNSLog 带外交互确认**：系统收到 OOB 回连请求。\n")
        if evidence:
            lines.append(f"> {evidence}\n")

        lines.append("*📸 [此处请手动补充 BurpSuite 发包截图 或 DNSLog 回显截图]*\n")

        # 三、修复建议
        lines.append("### 三、修复建议\n")
        lines.append(_fix_suggestion(vt))
        lines.append("")
        lines.append("---\n")

    return "\n".join(lines)


def main():
    cfg = Path(__file__).resolve().parent.parent
    default_path = cfg / "data" / "output" / "findings.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_path

    # 回退到 server findings
    if not path.exists():
        alt = Path("/tmp/server_findings.json")
        if alt.exists():
            path = alt

    if not path.exists():
        print(f"[!] 找不到 findings.json: {path}")
        sys.exit(1)

    raw = _json.loads(path.read_text(encoding="utf-8"))
    findings = raw.get("findings", []) if isinstance(raw, dict) else raw

    from collections import defaultdict
    by_domain = defaultdict(list)
    for f in findings:
        d = urlparse(f.get("url") or f.get("target_url", "")).hostname or "?"
        by_domain[d].append(f)

    print(f"[*] 加载 {len(findings)} 个 Findings，覆盖 {len(by_domain)} 个域名")

    # 过滤 catchall
    filtered = []
    for f in findings:
        raw_data = f.get("raw", {})
        bp = raw_data.get("body_preview", "")
        status = raw_data.get("status_code", 0)
        if status == 200 and (not bp or len(bp.strip()) < 10):
            continue
        if "<!DOCTYPE HTML PUBLIC" in bp[:200]:
            continue
        filtered.append(f)

    if len(filtered) < len(findings):
        print(f"[*] 已过滤 {len(findings) - len(filtered)} 个疑似 catchall 误报")

    print()
    report = generate_report(filtered)
    print(report)

    out = cfg / "data" / "reports" / "edusrc_submission.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"\n[*] 报告已保存至: {out}")


if __name__ == "__main__":
    main()
