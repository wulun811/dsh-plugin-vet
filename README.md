# @jieai/dsh-plugin-vet — DSH 插件信任流水线

> 安装任何插件前，先让 dsh-plugin-vet 走一遍：静态规则给出 verdict（确定性、不可伪造），
> LLM 按编排查敏感点与质量问题（谁也无法替代），最终一张两分制评分卡交给人/模型决定。

@jieai/dsh-plugin-vet 是 deepseek-harness 生态的第一个"信任层"插件：占据
**下载 → 扫描 → 审计 → 评分 → 决定** 这一整套信任流水线。**不做**插件市场本体（目录/分发）。

---

## 安装

```sh
dsh plugin --profile <profile> add @jieai/dsh-plugin-vet
```

安装即生效链路：pnpm 安装 → `reconcilePlugins` 读 `dsh.bundle` → 下次启动 `loadProfile`
解析 bundle 挂载插件。默认配置见下方 Config（fail-open：只报告不拦截）。

## Config（cordis.yml）

| 键 | 默认 | 说明 |
|---|---|---|
| `mode` | `report` | `report` 只报告不拦截；`deny` 显式开启拦截 |
| `autoScan` | `true` | 新插件（`internal/plugin`）自动静态扫描 |
| `autoAudit` | `false` | 新插件自动 LLM 审计（花钱，默认关） |
| `provider` / `model` | — | LLM 路由覆盖（必须成对；否则回落会话当前模型） |
| `auditMaxTokens` | `2048` | 每轮审计输出上限 |
| `auditTimeoutMs` | `120000` | 每轮审计超时 |
| `scannerTimeoutMs` | `15000` | 静态扫描子进程超时 |
| `auditCacheTtlHours` | `168` | LLM 审计结果缓存（7 天） |
| `rules` | `{}`（全开） | 规则开关（R1-R7） |
| `denyOn` | `critical` | `mode: deny` 时的拦截阈值 |
| `allowlist` | `[]` | 包名/插件 id 白名单（跳过扫描） |

`@deepseek-ai/*` 官方包默认豁免（内置信任）。

## 工具

- **`scan_plugin`** — 确定性静态扫描：`target` = `dynamic-code`（源码字符串）/ `package`（包目录）/ `file`（单文件）。返回评分卡（verdict + staticScore + findings）。verdict 只由静态规则产出。
- **`audit_plugin`** — 深度审计：先静态扫描；**verdict=critical 直接短路**（不调 LLM）；否则按 `deep`（默认 true）跑 4 轮 LLM 审计（总览 → 敏感点 → 质量 → 汇总），或只跑轮 1+2（`deep: false`）。LLM 输出永远是建议/注释/质量分，绝不参与 verdict。

## 自动行为

- **`internal/plugin` 自动扫描**（`autoScan: true`）：新装第三方 npm 包加载时自动静态扫描；`deny` 模式 + verdict ≥ `denyOn` → 回滚加载。
- **`tools/execute` 拦截**：`cordis_define` / `cordis_run` / `run_code` / `workflow` 执行前扫描代码字符串；`report` 模式在结果文本加 `VET:` 前缀，`deny` 模式直接拦截（isError）。

## 静态规则表（R1-R7）

| ID | 名称 | 默认级别 | 适用场景 | 确定性 |
|---|---|---|---|---|
| R1 | constructor 链逃逸 | critical | code + files | certain/likely |
| R2 | 动态执行（eval/Function/import/require） | high（files）/ medium（code） | both | certain/likely |
| R3 | process 直接访问（按 runtime 分级） | critical（host）/ high（sandbox） | both | certain |
| R4 | 宿主闭包捕获（agent/TextEncoder…） | critical | code | certain |
| R5 | ctx 逃逸尝试信号（withheld 成员/未声明服务） | medium | 仅 code | likely |
| R6 | 字符串粗扫兜底 | info | both | heuristic |
| R7 | 硬编码密钥 | high | both | likely |

## 评分模型

`staticScore = max(0, 100 - Σ(severity 权重 × 命中数 × confidence 系数))`

verdict（唯一权威判定，heuristic 永不升级）：critical ≥ 1 → `critical`；否则 high ≥ 1 → `suspicious`；其余 → `clean`。**两分制不合并**：staticScore（确定性）与 qualityScore（LLM 主观）分开呈现。

## 信任边界

1. **verdict 只由确定性静态层产出**——LLM 可被提示注入欺骗，规则不能。
2. **静态层与插件代码物理隔离**——scanner 是独立进程，AST 只读、从不 eval。
3. **LLM 输入先过静态层**——critical 直接短路，不浪费 token；提示词要求以怀疑态度复核。
4. **两分制不合并**——禁止合成单一总分，防止 LLM 污染 verdict 边界。
5. **本产品不是安全边界**——是恶意代码的"减速带+取证层"（与 DSH 官方立场对齐）。
6. **fail-open 起步**——默认 `mode: report`，`deny` 由部署者显式开启。

## Known Limitations

1. **静态扫描不是安全边界**：混淆/编码/动态生成代码可绕过 AST 规则；R6 只提供"疑似"信号。
2. **LLM 审计可被提示注入**：verdict 永不来自 LLM，但 LLM 可能漏报——置信度字段让用户知晓。
3. **`internal/plugin` 守卫不覆盖运行时动态挂载逃逸**：vm 路径由 `tools/execute` 守卫在调用层拦截。
4. **R5 仅 code 场景**：files 场景的 ctx 访问默认不报（误报率高）。
5. **扫描耗时**：大插件包可能超时跳过（R8 info）；LLM 审计分钟级、按需调用。
6. **qualityScore 是模型主观判断**，不构成安全保证。
7. **`@deepseek-ai/*` 默认信任**：未来若官方生态被攻破需收紧（v1 留开关）。

## 开发

```sh
npm run build       # scanner-bin + src 编译到 lib/
npm run typecheck   # tsc --noEmit
npm test            # 构建 + vitest（50 用例）
```

目录：`scanner-bin/` 静态引擎（独立进程）；`src/` 插件本体（tools/guards/audit/report）；`test/` fixtures + 单测。权威计划见 `PLAN.md`（v1.1）。
