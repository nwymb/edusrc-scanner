# AegisAgent Phase 4 — LLM 集成方案评估报告

> 评估日期: 2026-05-16
> 评估对象: 用户提出的 4 阶段 LLM 改造规划
> 评估人: 项目协作 Agent

---

## 一、总体评价

方向正确。LLM 接入是项目从"规则扫描器"跃迁到"智能 Agent"的必经之路。但**原计划的阶段顺序、模型选型、部分模块的 LLM 化边界需要调整**。

---

## 二、逐阶段分析

### 阶段 0: LLM 基建 + Tool 注册 — ✅ 无条件同意

**优先级**: P0

**认可点**:
- DeepSeek 完美兼容 OpenAI SDK
- 仅暴露 `send_http_request` 一个 Tool，最小权限设计
- JSON Schema 严格限定参数（url, method, headers, body），防越界

**补充建议**:
- 不用全局单例 → 工厂函数，底层共用 httpx 连接池
- Tool 内部走 `RateLimitedSession`，继承 5 QPS 限速和 SSL 容错

```json
{
  "name": "send_http_request",
  "description": "向目标 URL 发送 HTTP 请求",
  "parameters": {
    "type": "object",
    "properties": {
      "url":    {"type": "string"},
      "method": {"type": "string", "enum": ["GET", "POST", "HEAD"]},
      "headers": {"type": "object"},
      "body":    {"type": "string"}
    },
    "required": ["url", "method"]
  }
}
```

---

### 阶段 1: Gemini JS 逆向 → api_map.json — ⚠️ 方向对，时机错

**风险**: 中

| # | 风险 | 说明 |
|---|------|------|
| 1 | 命中率存疑 | 教育站点以 jQuery + SSR 为主，JS SPA 极少。清洗后送 LLM，多数返回空集 |
| 2 | 双模型维护税 | 加 Gemini = 两套 SDK / 认证 / 错误处理 / 限流。1 人项目不划算 |
| 3 | 可替代性 | DeepSeek-V3 支持长文本，JS 分析可合并到阶段 2 作为可选输入 |

**建议**: 降为阶段 2 可选子模块。先用 3-5 个真实 .edu.cn 站点验证命中率（>=50% 做，<30% 弃）。

---

### 阶段 2: DeepSeek ReAct 自愈攻击循环 — 🔥 核心价值最大，也最烧钱

**风险**: 高

| # | 风险 | 量化 |
|---|------|------|
| 1 | Token 爆炸 | 5 轮循环 × 10K tokens per round = 100K+ tokens，单目标 ¥5-10。100 域名 = ¥500-1000 |
| 2 | 幻觉攻击 | LLM 可能幻想 `/api/delete_all_users` 等不存在端点反复尝试 |
| 3 | 停止条件模糊 | "拿到敏感数据" 谁判定？硬编码 → 回到规则驱动；LLM 判定 → 误判风险 |
| 4 | 弱口令不应 LLM 化 | 表单解析+CSRF+indicators 判定是确定性任务，LLM 随机性是反作用。≤3 次安全红线在 ReAct 中无法保证 |

**建议调整**:

1. **弱口令保留不动** — 不接入 LLM
2. **ReAct 限定范围** — 仅 unauth bypass + nday_poc 失败重试:
   ```
   403/500 → LLM 分析响应 → 选 bypass / 改参数 → send_http_request → 评估 → 继续/停止
   ```
3. **硬性安全帽**:
   - 单目标 ≤8 轮
   - 单次扫描 ≤200K tokens
   - Action 仅限 api_map + 已知字典路径，禁止 LLM 自由编造 URL
   - 每次请求自动经过 QPS 5 限速

---

### 阶段 3: L1 + L5 — ✅ 低风险，建议提前

**L1 — LLM 子域名推测**:

- 让 LLM 根据机构全称生成缩写变体（"山东交通学院" → `sdjtu`, `sdjtxy`, `jiaotong`）
- 极低 token（~500/次），无 HTTP 交互，结果可复用
- **最该先做的功能**：5 个 prompt 跑通，立刻有成果给导师

**L5 — 报告生成**:

- 成功攻击链路 context → LLM 写漏洞描述 → Jinja2 套模板
- 直接出 EduSRC 提交格式，省人工编写
- 技术上简单，仅 prompt 设计有门槛

---

## 三、优先级重排

```
原: 阶段0 → 阶段1 → 阶段2 → 阶段3
新: 阶段0 → 阶段3(L1) → 阶段2(限定) → 阶段3(L5) → 阶段1(验证)
```

| 顺序 | 内容 | 耗时 | 理由 |
|------|------|------|------|
| 1st | **阶段 0** LLM 基建 | 1-2 天 | 地基 |
| 2nd | **阶段 3-L1** 子域名推测 | 0.5 天 | 低风险, 立刻有成果 |
| 3rd | **阶段 2** ReAct 限定版 | 3-5 天 | 核心价值 |
| 4th | **阶段 3-L5** 报告生成 | 1 天 | 锦上添花 |
| 5th | **阶段 1** JS 逆向 | 待定 | 先验证再决定 |

---

## 四、风险矩阵

| 风险 | 等级 | 缓解 |
|------|------|------|
| Token 成本失控 | 🔴 | 200K tokens/scan 硬预算 |
| 幻觉生成危险 Action | 🔴 | Action 空间硬约束 |
| 账号锁死 | 🟡 | 弱口令不接 LLM |
| 双模型维护税 | 🟡 | 统一走 DeepSeek |
| 阶段 1 命中率低 | 🟢 | 前置验证 |

---

## 五、结论

- **同意启动阶段 0** — LLM 基建无争议
- **建议阶段 3-L1 先做** — 低风险高可见度，对导师展示效果最好
- **阶段 2 需限定边界** — 弱口令不动，只做 unauth bypass 自动化
- **阶段 1 暂缓** — DeepSeek 跑通后再评估，避免双模型维护成本
- **Token 预算必须硬编码** — 不能交给 LLM 决定何时停止
