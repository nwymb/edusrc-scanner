"""上下文清洗器 — 将原始 HTTP 响应压成 ≤10KB 黑客可读摘要

提取: 表单/链接/注释/文本 + 安全 Header，丢弃 CSS/SVG/Base64/大段 JS。
"""

from __future__ import annotations

import re
from bs4 import BeautifulSoup, Comment

# 保留的安全相关 Header
_SECURITY_HEADERS = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "set-cookie", "www-authenticate", "location",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "x-frame-options",
    "content-security-policy", "x-content-type-options",
    "strict-transport-security", "x-xss-protection",
    "content-type", "x-application-context",
}

_MAX_OUTPUT = 10240
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_WS_RE = re.compile(r"\s{2,}")


def compress_http_response(status_code: int, headers: dict, raw_body: str) -> str:
    """将 HTTP 响应压缩为黑客友好的 Markdown 摘要。

    Returns: ≤10KB Markdown
    """
    parts: list[str] = []

    parts.append(f"## HTTP {status_code}\n")

    # ── 关键 Header ──
    sec_headers = {k: v for k, v in headers.items() if k.lower() in _SECURITY_HEADERS}
    if sec_headers:
        parts.append("### 关键响应头\n")
        for k, v in sec_headers.items():
            parts.append(f"- `{k}`: {v}")
        parts.append("")

    # ── Body ──
    content_type = str(headers.get("Content-Type", headers.get("content-type", "")))
    if "json" in content_type.lower():
        parts.append("### 响应体 (JSON)\n")
        parts.append(raw_body[:5000])
        return _truncate("\n".join(parts))

    if "html" in content_type.lower() or raw_body.strip().startswith("<"):
        body_text = _compress_html(raw_body)
    else:
        body_text = raw_body[:5000]

    parts.append("### 响应体\n")
    parts.append(body_text)
    return _truncate("\n".join(parts))


def _compress_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    output: list[str] = []

    # 删除垃圾节点
    for tag_name in ("style", "svg", "img", "video", "audio", "iframe",
                     "canvas", "picture", "source", "noscript", "object", "embed"):
        for tag in soup.find_all(tag_name):
            tag.decompose()

    # 大 script (>500 字符) → 删除；短 script → 保留为线索
    for script in soup.find_all("script"):
        text = script.get_text(strip=True)
        if len(text) > 500:
            script.decompose()
        else:
            new_tag = soup.new_tag("pre")
            new_tag.string = f"// inline-script: {text[:300]}"
            script.replace_with(new_tag)

    # Base64 长串
    for tag in soup.find_all(string=True):
        s = str(tag).strip()
        if _BASE64_RE.search(s):
            tag.replace_with("[base64-data-removed]")

    # ── 表单 ──
    forms = soup.find_all("form")
    if forms:
        output.append("#### 表单\n")
        for i, form in enumerate(forms):
            action = form.get("action", "(无)")
            method = form.get("method", "GET").upper()
            output.append(f"**[Form {i+1}]** `{method} {action}`")
            for inp in form.find_all("input"):
                name = inp.get("name", "")
                itype = inp.get("type", "text")
                value = inp.get("value", "")
                if itype == "hidden":
                    output.append(f"  - `{name}` = `{value}` (hidden)")
                elif itype == "submit":
                    output.append(f"  - `{name}` = `{value}` (submit)")
                elif name:
                    output.append(f"  - `{name}` (type={itype})")
            for sel in form.find_all("select"):
                sname = sel.get("name", "")
                if sname:
                    output.append(f"  - `{sname}` (select)")
            for ta in form.find_all("textarea"):
                tname = ta.get("name", "")
                if tname:
                    output.append(f"  - `{tname}` (textarea)")
            output.append("")

    # ── 链接 ──
    links = soup.find_all("a", href=True)
    hrefs = set()
    for a in links:
        h = a["href"].strip()
        if h and not h.startswith("#") and not h.startswith("javascript:"):
            hrefs.add(h)
    if hrefs:
        output.append("#### 链接\n")
        for h in sorted(hrefs)[:50]:
            text = ""
            for a in links:
                if a.get("href") == h:
                    text = a.get_text(strip=True)[:60]
                    break
            output.append(f"- [{text or h[:50]}]({h})")
        if len(hrefs) > 50:
            output.append(f"- ... (+{len(hrefs)-50} more)")
        output.append("")

    # ── HTML 注释 ──
    comments = soup.find_all(string=lambda t: isinstance(t, Comment))
    if comments:
        output.append("#### HTML 注释 (可能泄露路径)\n")
        seen = set()
        for c in comments:
            ct = str(c).strip()
            if len(ct) > 15 and ct not in seen:
                seen.add(ct)
                output.append(f"- {ct[:200]}")
        output.append("")

    # ── 页面纯文本 ──
    body = soup.find("body")
    if body:
        raw_text = body.get_text(separator="\n", strip=True)
        lines = [_WS_RE.sub(" ", l.strip()) for l in raw_text.splitlines() if l.strip()]
        if len(lines) > 60:
            lines = lines[:60] + [f"... (+{len(lines)-60} more lines)"]
        output.append("#### 页面文本\n")
        output.append("\n".join(lines))

    return "\n".join(output) if output else "(页面无有效可提取内容)"


def _truncate(text: str) -> str:
    if len(text) > _MAX_OUTPUT:
        text = text[:_MAX_OUTPUT] + "\n\n...<COMPRESSOR_CAP>"
    return text
