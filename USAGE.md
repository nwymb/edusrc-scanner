# AegisAgent 使用说明

## 环境准备

```bash
pip install aiohttp click pyyaml openai
export DEEPSEEK_API_KEY="sk-你的key"
```

Nuclei（可选，L4 扫描引擎）：
```bash
brew install nuclei && nuclei -update-templates
```

---

## 六种用法

### 1. 全流程扫描（Rule + LLM 混合）

```bash
python main.py --domain xxx.edu.cn
```

L1→L5 全部模块执行。L4 unauth_check 自动走三阶段：
- 常规 AdvancedBypass 快速扫
- 遇到 403/500/登录表单 → 激活 DeepSeek ReAct 自愈
- 攻击成功 → 自动生成 EduSRC 战报 `data/reports/`

### 2. 仅看执行计划（不发包）

```bash
python main.py --domain xxx.edu.cn --dry-run
```

打印完整任务清单，不发一个包。

### 3. 仅被动检测

```bash
python main.py --domain xxx.edu.cn --l3-only
```

仅 L1+L2+L3，不做 L4 主动验证，不调 LLM。

### 4. 关闭 LLM（纯规则模式）

```yaml
# orchestrator/config.yaml
llm:
  enabled: false
```

然后正常跑 `python main.py --domain xxx.edu.cn`。

### 5. 批量扫描

```bash
python main.py --file targets.txt
```

### 6. 自定义输出目录

```bash
python main.py --domain xxx.edu.cn --out results/2026-05-16
```

---

## 关键配置

```yaml
# orchestrator/config.yaml
http:
  spoof_local_ip: true      # IP 伪造头全局开关

llm:
  enabled: true             # LLM 自愈总开关
  max_react_steps: 4        # 单目标最多 4 轮 ReAct
  total_token_budget: 500000  # Token 熔断线

rate_limit:
  default_qps: 5            # 全局 QPS
```

---

## 产出文件

```
data/output/
├── assets.json       # L1 子域名
├── targets.json      # L2 存活目标
├── findings.json     # L3+L4 漏洞发现
├── report.json       # 去重 + 严重度统计
└── audit.log         # 审计日志

data/reports/
└── unauth_*.md       # LLM 生成的 EduSRC 漏洞报告
```

---

## 独立测试

```bash
python test_phase0.py   # Tool Calling 验证
python test_phase1.py   # 智能字典生成
python test_phase2.py   # ReAct 自愈循环 (需本地 DVWA)
```
