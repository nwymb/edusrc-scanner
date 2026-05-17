# 漏洞报告

## 漏洞名称

DVWA 后台默认弱口令登录漏洞

## 漏洞评级

**高危**

**评级理由：** 攻击者利用默认弱口令 `admin/password` 成功登录 DVWA 后台，获取管理员权限。该漏洞允许攻击者访问所有漏洞模块（包括 SQL 注入、文件上传、命令执行等），进而可能导致服务器被完全控制、数据泄露或进一步渗透内网。由于 DVWA 常被用于教学和测试环境，若部署在公网或内网可访问位置，风险极高。

## 影响资产

- `http://127.0.0.1:8080/login.php`
- `http://127.0.0.1:8080/`（后台首页及所有功能模块）

## 漏洞描述

目标系统为 **Damn Vulnerable Web Application (DVWA)**，运行在 Apache/2.4.25 (Debian) 上，安全级别设置为 `low`。DVWA 默认的管理员凭据为 `admin/password`，且未强制要求修改初始密码。攻击者通过获取登录页面的 CSRF token 后，使用默认凭据即可成功登录后台，获得管理员权限。

登录后，攻击者可访问所有漏洞模块，包括但不限于：
- SQL 注入（SQL Injection）
- 命令注入（Command Injection）
- 文件上传（File Upload）
- 文件包含（File Inclusion）
- 跨站脚本（XSS）
- CSRF
- 暴力破解（Brute Force）

这些模块均可被利用来执行任意 SQL 查询、执行系统命令、上传恶意文件、窃取会话等，最终可能导致服务器完全沦陷。

## 完整的漏洞复现步骤

### 步骤 1：访问登录页面

发送 GET 请求获取登录页面，收集 CSRF token 和页面信息。

**请求：**
```
GET http://127.0.0.1:8080/login.php
```

**响应关键信息：**
- 服务器：Apache/2.4.25 (Debian)
- Set-Cookie：`security=low`
- 表单中存在隐藏字段 `user_token`，值为 `b8376f56bf0decc0796060112df220ab`

### 步骤 2：获取新的 CSRF token

由于 CSRF token 为一次性使用，需重新 GET 获取新 token。

**请求：**
```
GET http://127.0.0.1:8080/login.php
```

**响应中获取到的 token：**
```
user_token = 5e5346c11c6a864d3bf71a0b75915900
```

### 步骤 3：使用默认凭据登录

使用默认管理员凭据 `admin/password` 和上一步获取的 token 发送 POST 请求。

**请求：**
```
POST http://127.0.0.1:8080/login.php
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&Login=Login&user_token=5e5346c11c6a864d3bf71a0b75915900
```

**响应结果：**
- HTTP 200
- 页面显示后台导航菜单，包含所有漏洞模块链接
- 登录成功，获得管理员权限

### 步骤 4：验证登录成功

登录成功后，可访问后台任意页面，例如：
```
GET http://127.0.0.1:8080/index.php
```

页面显示：
- Home
- Instructions
- Setup / Reset DB
- Brute Force
- Command Injection
- SQL Injection
- File Upload
- 等所有漏洞模块

## 修复建议

1. **修改默认凭据**：部署后立即修改默认管理员用户名和密码，避免使用 `admin/password` 等弱口令。

2. **强制密码策略**：实施密码复杂度要求（至少 8 位，包含大小写字母、数字和特殊字符），并强制用户在首次登录时修改初始密码。

3. **限制登录尝试**：实现登录失败锁定机制，例如连续 5 次失败后锁定账户 15 分钟，防止暴力破解。

4. **提升安全级别**：将 DVWA 的安全级别设置为 `high` 或 `impossible`，以启用更严格的输入验证和 CSRF 保护。

5. **网络隔离**：避免将 DVWA 等测试环境暴露在公网或非信任网络中，应仅限内网或本地访问。

6. **定期审计**：定期检查系统账户和密码强度，及时发现并修复弱口令问题。