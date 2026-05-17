#!/usr/bin/env python3
"""测试 Observation Compressor — HTML 清洗瘦身"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from agent.observation_compressor import compress_http_response

FAKE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>某大学后台管理系统</title>
<style>/* 5000行垃圾CSS ... */ body{margin:0}.header{background:#333;height:60px}
.container{display:flex}.row{display:flex;flex-wrap:wrap}.col{flex:1;padding:15px}
.card{border:1px solid #ddd;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.btn{display:inline-block;padding:6px 12px;font-size:14px;cursor:pointer}
.btn-primary{color:#fff;background-color:#337ab7;border-color:#2e6da4}
.table{width:100%;max-width:100%;margin-bottom:20px}
.modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5)}
</style>
<script>/* 混淆jQuery ~200KB 远超500字符应被删除 */
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a document");return t(e)}:t(e)}("undefined"!=typeof window?window:this,function(e,t){var r=[],i=Object.getPrototypeOf,o=r.slice,a=r.flat?function(e){return r.flat.call(e)}:function(e){return r.concat.apply([],e)};var s=r.push,u=r.indexOf,n={},l=n.toString,c=n.hasOwnProperty,f=c.toString,p=f.call(Object),d={},g=function(e){return"function"==typeof e&&"number"!=typeof e.nodeType&&"function"!=typeof e.item},h=function(e){return null!=e&&e===e.window},m=e.document;var v=function(e,t){return new v.fn.init(e,t)};</script>
<script>var API_BASE="/api/v2/admin";function loadUsers(){$.get(API_BASE+"/users",function(d){render(d)})}</script>
</head>
<body>
<div class="header"><span style="color:white;padding:15px;font-size:18px;">某大学综合管理平台</span></div>
<div class="sidebar"><ul>
<li><a href="/admin/dashboard">控制台</a></li>
<li><a href="/admin/users">用户管理</a></li>
<li><a href="/admin/courses">课程管理</a></li>
<li><a href="/admin/grades">成绩管理</a></li>
<li><a href="/admin/settings">系统设置</a></li>
<li><a href="/backup/download?path=/var/www/backup.sql">备份下载</a></li>
</ul></div>
<div class="content">
<h2>管理员登录</h2>
<!-- TODO: 开发环境管理员密码 admin123456，上线前改掉 -->
<!-- 后台路径: /admin/debug/sysinfo -->
<form action="/api/v2/auth/login" method="POST">
<input type="hidden" name="csrf_token" value="8a3f2e1d9b4c7a6f5e0d3c2b1a4f7e9d">
<input type="hidden" name="redirect" value="/admin/dashboard">
<input type="text" name="username" placeholder="管理员账号">
<input type="password" name="password" placeholder="密码">
<select name="role"><option value="admin">系统管理员</option><option value="teacher">教师</option></select>
<textarea name="remark" placeholder="备注"></textarea>
<input type="submit" name="submit" value="登录">
</form>
<div class="info">
<p>欢迎使用综合管理平台。本系统采用SSO统一认证。</p>
<p>技术支持: <a href="mailto:admin@university.edu.cn">admin@university.edu.cn</a></p>
</div></div>
<div class="footer">2024 某大学 - 网络信息中心</div>
<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" alt="装饰图">
</body></html>"""

HEADERS = {
    "Date": "Sat, 17 May 2026 03:15:42 GMT",
    "Server": "Apache/2.4.41 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.33",
    "Set-Cookie": "PHPSESSID=abc123def456; path=/; HttpOnly",
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": "250000",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "X-Application-Context": "admin-backend:prod",
    "Access-Control-Allow-Origin": "*",
    "X-Frame-Options": "DENY",
}

if __name__ == "__main__":
    print("=" * 60)
    print("Observation Compressor 测试")
    print("=" * 60)
    print(f"\n原始大小: {len(FAKE_HTML):,} 字符 | Headers: {len(HEADERS)}")

    result = compress_http_response(200, HEADERS, FAKE_HTML)

    print(f"压缩后:   {len(result):,} 字符")
    print(f"压缩比:   {len(result)/len(FAKE_HTML)*100:.1f}%")
    print(f"\n{'=' * 60}")
    print("压缩结果:")
    print("=" * 60)
    print(result)
