# eduSRC Scanner — 架构状态快照 (2026-05-15)

## 全局架构红线（所有模块必须遵守）

| 红线 | 实现位置 |
|------|---------|
| QPS 限流 5 req/s（凌晨放宽至 10） | `orchestrator/rate_limiter.py` → `TokenBucket` + `RateLimiter` |
| 仅允许 .edu.cn / .gov.cn / .ac.cn 域名 | `orchestrator/scope_guard.py` → `ScopeGuard.is_in_scope()` |
| 禁止拖库/篡改数据 — 仅"存在性证明" | 各检测模块的验证程度约束 |
| 禁止内网渗透/横向移动 | 项目中不包含任何代理转发/隧道/C段扫描模块 |
| 禁止上传 Webshell — 仅无害探针 | L4 文件上传 POC 模块约束 |
| **SSL 证书验证默认开启** | `shared/http_client.py:verify_ssl` 默认 True |
| **异常不可沉默** | 全网调用必须使用特定异常类型 + log warning/debug |

---

## 已完成：Sprint 1（项目骨架）

```
main.py                                    # CLI 入口 (click)
shared/models.py                           # Asset, Target, Finding, ScanTask, 枚举类
shared/http_client.py                      # RateLimitedSession (令牌桶限速 async HTTP)
shared/logger.py                           # AuditLogger (JSON 行审计日志, 句柄常开)
shared/utils.py                            # JSON_CLEAN_RE (crt.sh 控制字符清理)
orchestrator/config.yaml                   # 全局 YAML 配置
orchestrator/rate_limiter.py               # TokenBucket + RateLimiter (按域名分桶)
orchestrator/scope_guard.py                # ScopeGuard (域名范围校验)
orchestrator/scheduler.py                  # ScanPlan + Scheduler (5 阶段编排引擎)
context_bar.py                             # 独立工具: 终端底部上下文进度条
```

## 已完成：Sprint 2 — L1 资产发现 + L2 资产分析

### 模块注册机制

```
modules/__init__.py
  ├─ MODULE_REGISTRY: dict[name, async_handler]   # 全局模块注册表
  ├─ @register("name")                             # 装饰器自动注册
  └─ 底部 import 触发所有子模块注册               # 6 个模块自动加载
```

### L1 资产发现模块 (3 个)

| 模块 | 文件 | 数据源 | 输入 → 输出 |
|------|------|--------|------------|
| subdomain | `modules/l1_discovery/subdomain.py` | crt.sh + DNS 字典爆破 (130+ 词) | domain → `asdict(Asset[])` |
| cert_search | `modules/l1_discovery/cert_search.py` | crt.sh 泛域名+精确搜索 | domain → `asdict(Asset[])` |
| fofa_search | `modules/l1_discovery/fofa_client.py` | FOFA / 鹰图 API (可选) | domain → `asdict(Asset[])` |

### L2 资产分析模块 (3 个)

| 模块 | 文件 | 功能 | 输入 → 输出 |
|------|------|------|------------|
| alive_check | `modules/l2_analysis/alive_check.py` | HTTP HEAD+GET 探活, 提取标题 | context["assets"] → `asdict(Target[])` |
| fingerprint | `modules/l2_analysis/fingerprint.py` | 18 条指纹规则 (Java/PHP/Python/前端/CMS/SSO) | context["targets"] → 更新 tech_stack, fingerprint |
| value_score | `modules/l2_analysis/value_scorer.py` | 价值评分 (0-100) + 登录页/管理后台检测 | context["targets"] → 更新 value_score, is_login, is_admin |

### 数据文件

```
data/dicts/subdomain.txt                     # 130+ 子域名字典
data/fingerprints/cms_patterns.yaml          # 18 条 CMS/框架/服务器指纹规则
```

### Sprint 2 模块编写规范（Review 后确立）

1. **异常处理**: 禁止 `except Exception: pass` — 必须捕获具体类型 `(aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError)` 并用 `logging.getLogger(__name__)` 输出 warning/debug
2. **dataclass 转 dict**: 统一使用 `dataclasses.asdict(obj)`，不用 `.__dict__`
3. **helper 函数**: 使用标准库 `logging` 模块（`setup_std_logging()` 已在 main.py 初始化），不用 `print`
4. **模块路径**: 用 `_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent` 代替多层 `.parent`
5. **API 调用**: 带密钥的 URL 添加注释说明限制，设置 `allow_redirects=False`

---

## 当前项目目录

```
edusrc自动扫描/
├── main.py                          # CLI 入口
├── requirements.txt                 # aiohttp, click, pyyaml
├── context_bar.py                   # 独立工具: 终端上下文进度条
├── .gitignore
├── architecture_status.md           # 本文件
│
├── shared/
│   ├── __init__.py
│   ├── models.py                    # Asset, Target, Finding, ScanTask + 枚举
│   ├── http_client.py               # RateLimitedSession (令牌桶限速, SSL 默认校验)
│   ├── logger.py                    # AuditLogger (句柄常开, JSON 行输出)
│   └── utils.py                     # JSON_CLEAN_RE
│
├── orchestrator/
│   ├── config.yaml                  # 全局配置 (含 verify_ssl, api keys 占位)
│   ├── rate_limiter.py              # TokenBucket + RateLimiter
│   ├── scope_guard.py               # ScopeGuard (域名白名单)
│   └── scheduler.py                 # ScanPlan + Scheduler (5 阶段编排 + 模块 dispatch)
│
├── modules/
│   ├── __init__.py                  # MODULE_REGISTRY + @register + 模块导入
│   ├── l1_discovery/
│   │   ├── __init__.py
│   │   ├── subdomain.py             # ✅ crt.sh + DNS 爆破
│   │   ├── cert_search.py           # ✅ crt.sh 证书搜索
│   │   └── fofa_client.py           # ✅ FOFA/鹰图
│   ├── l2_analysis/
│   │   ├── __init__.py
│   │   ├── alive_check.py           # ✅ HTTP 探活
│   │   ├── fingerprint.py           # ✅ 技术栈指纹
│   │   └── value_scorer.py          # ✅ 价值评分
│   ├── l3_passive/
│   │   ├── __init__.py
│   │   ├── sensitive_path.py          # ✅ GET 敏感路径探测 (43 条)
│   │   └── config_leak.py             # ✅ 框架配置泄露检测 (11 框架)
│   ├── l4_active/
│   │   ├── __init__.py
│   │   ├── weak_pass.py               # ✅ POST 弱口令检测 (30 组凭据)
│   │   ├── unauth_check.py            # ✅ 未授权访问检测 (30 端点)
│   │   ├── nday_poc.py                # ✅ Nday POC 验证 (18 条规则)
│   │   └── idor_check.py              # ✅ IDOR 越权检测 (pattern match)
│   └── l5_output/
│       ├── __init__.py
│       ├── dedup.py                   # ✅ url+vuln_type 去重
│       └── report.py                  # ✅ JSON 报告 + severity 统计
│
└── data/
    ├── dicts/
    │   ├── subdomain.txt               # 130+ 子域名字典
    │   ├── sensitive_paths.yaml        # 43 条敏感路径 (8 类别)
    │   ├── framework_endpoints.yaml    # 11 框架端点规则
    │   └── weak_passwords.txt          # 30 组常见弱口令
    ├── fingerprints/
    │   └── cms_patterns.yaml           # 18 条指纹规则
    ├── pocs/
    │   └── nday_rules.yaml             # 18 条 Nday POC 规则
    └── output/                         # 扫描产出目录
        ├── audit.log
        ├── assets.json
        ├── targets.json
        ├── findings.json               # Sprint 6 新增
        └── report.json                 # Sprint 6 新增
```

---

## 关键设计模式

### 数据流 (完整)

```
seeds (domains)
    │
    ├─→ L1: subdomain / cert_search / fofa_search
    │       └─→ asdict(Asset[])  ─→  assets.json
    │
    ├─→ L2: alive_check / fingerprint / value_scorer
    │       └─→ asdict(Target[])  ─→  targets.json
    │
    ├─→ L3: sensitive_path / config_leak       (被动, 只读 GET/HEAD)
    │       └─→ asdict(Finding[])  ─→
    │
    ├─→ L4: weak_pass / unauth_check / nday_poc / idor_check  (主动, POST/POC)
    │       └─→ asdict(Finding[])  ─→
    │
    └─→ L5: dedup / report
            └─→ findings.json + report.json
```

### 模块上下文 (context dict)

每个模块的 `run(context: dict) -> dict` 接收:
```python
ctx = {
    "target": str,           # 当前种子域名/URL
    "session": RateLimitedSession,  # 共享 HTTP 会话 (带限速)
    "logger": AuditLogger,   # JSON 审计日志
    "config": dict,          # 全局 YAML 配置
    "assets": list[dict],    # L1 产出 (L2+ 可用)
    "targets": list[dict],   # L2 产出 (L3+ 可用)
    "findings": list[dict],  # L3+L4 产出 (L5 可用, Sprint 6 新增)
}
```

### 新模块 checklist

1. 创建 `modules/lX_*/new_module.py`
2. 用 `@register("module_name")` 装饰 `async def run(context: dict) -> dict`
3. helper 函数用 `logging.getLogger(__name__)` 记录异常
4. 网调用 `RateLimitedSession`，捕获具体异常类型
5. 在 `modules/__init__.py` 底部添加 `from modules.lX_* import new_module`
6. 在 `orchestrator/scheduler.py:MODULE_PHASE` 添加模块→阶段映射
7. 在 `orchestrator/scheduler.py:build_plan()` 添加任务生成逻辑

---

## CLI 用法

```bash
python main.py --domain xxx.edu.cn              # 全流程扫描 (L1→L5)
python main.py --file targets.txt               # 批量扫描
python main.py --domain xxx.edu.cn --dry-run     # 仅打印执行计划，不执行
python main.py --domain xxx.edu.cn --l3-only     # L1+L2+L3 (被动检测)
python main.py --out data/custom_output          # 自定义输出目录
```

产出文件:
```
data/output/
├── assets.json       # L1 资产
├── targets.json      # L2 存活目标
├── findings.json     # L3+L4 漏洞发现  (Sprint 6 新增)
├── report.json       # 去重+统计报告   (Sprint 6 新增)
└── audit.log         # 审计日志
```

## 配置要点 (`orchestrator/config.yaml`)

- `rate_limit.default_qps: 5` — 正常限流
- `rate_limit.night_qps: 10` — 凌晨 2-6 点放宽
- `http.verify_ssl: true` — SSL 证书验证 (默认开启, 仅内网环境改 false)
- `apis.fofa.enabled: false` — FOFA 需 email+key 并设为 true 才启用
- `apis.hunter.enabled: false` — 鹰图需 key 并设为 true 才启用
- **密钥建议用环境变量**: `FOFA_EMAIL`, `FOFA_KEY`, `HUNTER_KEY`

---

## 待实施：Sprint 3 — L3 被动检测 (ROI 最高)

### 目标
对 L2 产出的存活 Target 做只读的被动漏洞检测，不发送任何 payload。

### 任务清单
1. **`data/dicts/sensitive_paths.yaml`** — 敏感路径字典
   - 备份文件: `.git/HEAD`, `.svn/entries`, `.DS_Store`, `backup.zip`, `www.zip`
   - 配置文件: `.env`, `config.php.bak`, `web.config`, `application.properties`
   - 调试信息: `phpinfo.php`, `info.php`, `test.php`, `debug/`
   - 管理入口: `admin/login.aspx`, `manager/login`, `console/`
   - API 泄露: `swagger-ui.html`, `api-docs`, `graphql`, `actuator/health`

2. **`data/dicts/framework_endpoints.yaml`** — 框架端点字典
   - Spring Boot: `/actuator/env`, `/actuator/mappings`, `/actuator/heapdump`
   - Laravel: `/.env`, `/storage/logs/laravel.log`, `/_debugbar/`
   - Django: `/admin/`, `/api/v1/`, `/graphql`
   - ThinkPHP: `/index.php?s=`, `/public/index.php`
   - Struts: `/struts/`, `.action`, `.do`
   - Tomcat: `/manager/html`, `/host-manager/html`

3. **`modules/l3_passive/sensitive_path.py`** — GET 探测敏感路径
   - 输入: targets (from L2)
   - 对每个 Target URL 拼接字典路径做 HEAD/GET 探测
   - 输出: `Finding[]` (vuln_type="sensitive_path", severity=INFO~MEDIUM)
   - 注意: 遵守限流，每个 target 的探测间隔 >= 200ms

4. **`modules/l3_passive/config_leak.py`** — 框架配置缺陷检测
   - 输入: targets (from L2, 含 fingerprint 信息)
   - 根据已知 fingerprint 选择对应的框架端点字典
   - 检测响应中是否包含敏感配置 (数据库连接串、密钥、debug 信息)
   - 输出: `Finding[]` (vuln_type="config_leak", severity=MEDIUM~HIGH)

### 预期产出
- L3 探测 coverage: 每个 Target 探测 20-50 条路径
- 发现率预估: 5-15% 的 Target 至少暴露 1 个敏感路径
- findings.json (初版)

---

## 已完成：Sprint 4 — L4 P0+P1 主动验证

| 模块 | 文件 | 功能 | 输入 → 输出 |
|------|------|------|------------|
| weak_pass | `modules/l4_active/weak_pass.py` | POST 弱口令检测，每目标 ≤2 次尝试 | L2 targets (is_login=True) → `Finding[]` vuln_type="weak_password" |
| unauth_check | `modules/l4_active/unauth_check.py` | 探测 30 个管理端点，响应含后台内容 → 未授权 | L2 targets → `Finding[]` vuln_type="unauth" |

## 已完成：Sprint 5 — L4 P3 Nday POC

| 模块 | 文件 | 功能 | 输入 → 输出 |
|------|------|------|------------|
| nday_poc | `modules/l4_active/nday_poc.py` | 18 条 POC 规则，fingerprint 匹配 + 通杀扩散 | L2 targets → `Finding[]` vuln_type="nday/{id}" |

## 已完成：Sprint 6 — L5 报告输出

| 模块 | 文件 | 功能 | 输入 → 输出 |
|------|------|------|------------|
| idor_check | `modules/l4_active/idor_check.py` | 数值 ID 提取 → 相邻 ID 探测 → 响应对比 | L2 targets → `Finding[]` vuln_type="idor" |
| dedup | `modules/l5_output/dedup.py` | url+vuln_type 去重，保留最高 severity | findings → 去重 findings |
| report | `modules/l5_output/report.py` | JSON 报告 + severity/type 统计 | findings → `report.json` |

---

## 仓库

- GitHub: `nwymb/edusrc-scanner` (private)
- 分支: `main`
- 最新 commit: Sprint 6 — L3被动检测 + L4主动验证 + L5报告输出 (14 模块全流程)
- 模块总数: 14 (MODULE_REGISTRY)
