# eduSRC Scanner — 架构状态快照

## 全局架构红线（所有模块必须遵守）

| 红线 | 实现位置 |
|------|---------|
| QPS 限流 5 req/s（凌晨放宽至 10） | `orchestrator/rate_limiter.py` → `TokenBucket` + `RateLimiter` |
| 仅允许 .edu.cn / .gov.cn / .ac.cn 域名 | `orchestrator/scope_guard.py` → `ScopeGuard.is_in_scope()` |
| 禁止拖库/篡改数据 — 仅"存在性证明" | 各检测模块的验证程度约束 |
| 禁止内网渗透/横向移动 | 项目中不包含任何代理转发/隧道/C段扫描模块 |
| 禁止上传 Webshell — 仅无害探针 | L4 文件上传 POC 模块约束 |

## 已完成：Sprint 1（项目骨架）

### 文件清单 & 对外接口

```
main.py
  └─ main()                         # CLI 入口，click 命令

shared/models.py
  ├─ Asset(domain, ip, port, source, timestamp)   # L1 产出
  ├─ Target(url, title, status_code, tech_stack, fingerprint, value_score, ...)  # L2 产出
  ├─ Finding(url, vuln_type, severity, confidence, rank_estimate, ...)  # L3/L4 产出
  ├─ ScanTask(id, module, target, priority, depends_on, status)  # 调度任务
  ├─ VulnSeverity(Enum): CRITICAL / HIGH / MEDIUM / LOW / INFO
  ├─ FindingSource(Enum): L3_PASSIVE / L4_ACTIVE
  └─ TaskStatus(Enum): PENDING / RUNNING / DONE / FAILED / SKIPPED

shared/http_client.py
  └─ RateLimitedSession            # async context manager, .get() .head() 带令牌桶限速

shared/logger.py
  ├─ AuditLogger(log_file)         # .info() .warning() .error() .finding() 输出 JSON 行
  └─ setup_std_logging()           # 标准库 logging → stdout

orchestrator/config.yaml           # YAML: scheduler / rate_limit / http / scope / logging
orchestrator/rate_limiter.py
  ├─ TokenBucket(rate, burst)      # 异步令牌桶, .acquire()
  ├─ RateLimiter(default_qps, night_qps, night_window)  # 按域名分桶, .get_bucket(domain)
  └─ get_limiter()                 # 全局单例

orchestrator/scope_guard.py
  └─ ScopeGuard(config_path)       # .is_in_scope(domain) .filter_assets(list) -> list

orchestrator/scheduler.py
  ├─ ScanPhase(Enum)               # DISCOVERY / ANALYSIS / PASSIVE / ACTIVE / REPORT
  ├─ MODULE_PHASE: dict            # 模块名 → 阶段映射
  ├─ ScanPlan                      # .add(task) .pending() .by_phase(phase)
  └─ Scheduler(logger)             # .build_plan(seeds, modules, dry_run) .execute(plan, max_con)
```

### CLI 用法

```bash
python main.py --domain xxx.edu.cn              # 全流程扫描
python main.py --file targets.txt               # 批量扫描
python main.py --domain xxx.edu.cn --dry-run     # 仅打印执行计划
python main.py --domain xxx.edu.cn --l3-only     # 仅 L1+L2+L3
```

## 待实施：Sprint 2-6

### Sprint 2 — L1 资产发现 + L2 资产分析
- `modules/l1_discovery/subdomain.py` — 封装 OneForAll / Subfinder
- `modules/l1_discovery/cert_search.py` — crt.sh API 证书查询
- `modules/l1_discovery/fofa_client.py` — FOFA/鹰图 API 封装
- `modules/l2_analysis/alive_check.py` — httpx 存活检测
- `modules/l2_analysis/fingerprint.py` — Wappalyzer 技术栈指纹
- `modules/l2_analysis/value_scorer.py` — 资产价值评分
- 产出: `targets.json`

### Sprint 3 — L3 被动检测（ROI 最高）
- `data/dicts/sensitive_paths.yaml` — 敏感路径字典
- `data/dicts/framework_endpoints.yaml` — 框架端点字典
- `modules/l3_passive/sensitive_path.py` — GET 探测敏感路径
- `modules/l3_passive/config_leak.py` — 框架配置缺陷检测

### Sprint 4 — L4 P0+P1（弱口令 + 未授权）
### Sprint 5 — L4 P3 Nday POC + 通杀扩散
### Sprint 6 — L5 报告输出 + AI 越权检测

## 当前项目目录

```
edusrc自动扫描/
├── main.py
├── requirements.txt              # aiohttp, click, pyyaml
├── shared/
│   ├── models.py
│   ├── http_client.py
│   └── logger.py
├── orchestrator/
│   ├── config.yaml
│   ├── rate_limiter.py
│   ├── scope_guard.py
│   └── scheduler.py
├── modules/                      # l1~l5 子目录已建，待填代码
├── data/                         # dicts/ fingerprints/ 待建
└── architecture_status.md        # 本文件
```

## 仓库

- GitHub: `nwymb/edusrc-scanner` (private)
- 分支: `main`
- 最新 commit: Sprint 1 基础设施
