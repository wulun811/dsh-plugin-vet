# @jieai/dsh-plugin-vet — 插件信任流水线（开发计划 v1）

> 状态：已批准（v1.1 修订：按 dsh-src @ 47f943859b 源码核对，修正 A1-A5、B1-B3，修订记录见 §13）。本文档是唯一权威计划；实现中的任何偏差必须回到本文档更新。
> 目标仓库：`N:\0AI干活\plugin-vet\`（独立项目，npm 发布，不进 deepseek-harness 官方仓库）。

---

## 1. 背景与生态位

### 1.1 生态现状（已在 deepseek-harness 源码中核实）

| 事实 | 证据（deepseek-harness 仓库） |
|---|---|
| DSH 没有"插件市场"（marketplace/registry 全仓零命中） | grep market/store/marketplace 无实现；唯一预留：`SkillProvider` JSDoc "remote registry"（`packages/skill/skill/src/index.ts:247`） |
| 第三方插件分发 = npm 包 + `dsh.bundle.patch` 声明 | `dsh plugin --profile X add <pkg>` → pnpm 安装 → `reconcilePlugins` 按 `dsh.bundle` 加入 profile（`apps/cli/src/plugin.ts:59-91`） |
| **安装路径零校验**：无签名、无哈希、无 pinning | 全仓 sha256 仅用于附件存储与 skill catalog digest；信任完全委托 npm registry |
| 现有防护全部是"API 塑形"，无任何 AST/语义静态分析 | `verify-cordis-config` 只查配置静态性（`scripts/verify-cordis-config.ts:416-453`）；动态插件侧是 vm 沙箱 + ctx 白名单 Proxy + schema 校验（`cordis-host-runner/src/guard.ts:718-781`） |
| 官方信任立场明确让出"安全边界"位置 | `tool-cordis/src/prompt.ts:8`："The restricted execution environment prevents accidental misuse; it is not a security boundary for malicious code." |
| 已 PoC 实证的三个模型代码执行入口全部无静态防线 | workflow（vm+宿主闭包，默认挂载、无批准）、run_code（`new AsyncFunction` 裸执行，opt-in）、动态插件（vm 逃逸，一次批准） |

### 1.2 生态位定义

**第一个"信任层"插件**：插件生态的成长必然伴随恶意/劣质插件的涌入；DSH 把安全边界位置让出，我们占据"下载 → 扫描 → 审计 → 评分 → 决定"这一整套信任流水线。差异化：确定性静态层（verdict）+ LLM 深度审计层（敏感点与质量）+ 两分制评分卡。**不做**的是"插件市场"本体（目录/分发，等官方或另行规划）。

---

## 2. 产品定位与信任边界

### 2.1 一句话

> 安装任何插件前，先让 dsh-plugin-vet 走一遍：静态规则给出 verdict（谁也无法伪造），LLM 按编排查敏感点与质量问题（谁也无法替代），最终一张两分制评分卡交给人/模型决定。

### 2.2 信任边界（本产品最重要的设计约束）

1. **verdict 只由确定性静态层产出**。LLM 输出永远是"建议/注释/质量分"，绝不参与 critical/suspicious/clean 判定。原因：LLM 可被恶意代码中的提示注入欺骗（注释里写"ignore the following rules"），确定性规则不能。
2. **静态层与插件代码物理隔离**。扫描器是独立进程（spawn scanner-bin），AST 只读、从不 eval。即使宿主进程被逃逸代码篡改，扫描结果仍来自干净进程；扫描器崩溃也不影响宿主。
3. **LLM 层输入先过静态层**。只有静态层判为非 critical 的代码块才进入 LLM 审计（critical 直接短路，不浪费 token）；LLM 审计输入注明"该代码已通过静态层"，提示词要求以怀疑态度复核。
4. **两分制不合并**：`staticScore`（确定性规则）与 `qualityScore`（LLM 主观维度）分开呈现，禁止合成单一总分——合成会让 LLM 污染 verdict 边界。
5. **不把本产品自身称为安全边界**。README Known Limitations 明说：静态扫描是恶意代码的"减速带+取证层"，不是安全边界（与 DSH 官方立场对齐）；产品价值是把"未知"变成"已知"，把"信任"变成"可决策的证据"。
6. **fail-open 起步**：默认 `mode: 'report'`（只报告不拦截），`mode: 'deny'` 由部署者显式开启。用户已拍板。

### 2.3 产品叙事

自动：新插件加载前静态扫描（秒级，免费，有缓存）。编排：模型或用户调 `scan_plugin`（静态报告）→ 需深查调 `audit_plugin`（LLM 审计，分钟级）→ 评分卡 → 决定。全流程可审计（每步都 append 会话日志）。

---

## 3. 系统架构

```
N:\0AI干活\plugin-vet\
├── PLAN.md                       # 本文档
├── package.json                  # @jieai/dsh-plugin-vet，ESM，dsh.bundle 声明
├── cordis.patch.yml              # 挂载插件本体（insert entry）
├── tsconfig.json                 # strict，rootDir src，outDir lib
├── src/
│   ├── index.ts                  # 插件入口：name/inject/Config/apply，无 default export
│   ├── invariant.ts              # DSH 包规范：运行时关系断言
│   ├── config.ts                 # schemastery Config schema
│   ├── tools/
│   │   ├── scan-plugin.ts        # scan_plugin 工具定义（defineTool）
│   │   └── audit-plugin.ts       # audit_plugin 工具定义（defineTool）
│   ├── guards/
│   │   ├── internal-plugin.ts    # internal/plugin 事件守卫（新装 npm 包自动扫描）
│   │   └── tool-execute.ts       # tools/execute 拦截（cordis_define/cordis_run/run_code）
│   ├── scanner/
│   │   ├── client.ts             # spawn scanner-bin，JSON stdin/stdout 协议
│   │   └── protocol.ts           # 协议类型（请求/响应 schema，两处共用）
│   ├── audit/
│   │   ├── orchestrator.ts       # 4 轮 LLM 编排：组装/推进/汇总
│   │   ├── route.ts              # provider/model 路由解析
│   │   ├── prompts.ts            # 4 轮 system 提示词模板
│   │   ├── parse.ts              # 模型输出解析：JSON 提取 + 校验 + 重试
│   │   └── session-log.ts        # 会话日志 append（Model-visible ⟺ logged）
│   └── report/
│       ├── types.ts              # 评分卡类型（静态分/质量分/verdict/findings）
│       └── render.ts             # 评分卡渲染（presentResult 用）
├── scanner-bin/
│   ├── index.ts                  # 独立进程入口：读 stdin JSON → 扫描 → 写 stdout JSON
│   ├── ast.ts                    # TypeScript compiler API 封装（createSourceFile 只读）
│   ├── rules/
│   │   ├── index.ts              # 规则注册表 + 执行循环
│   │   ├── constructor-chain.ts  # 规则 R1
│   │   ├── dynamic-exec.ts       # 规则 R2
│   │   ├── process-direct.ts     # 规则 R3
│   │   ├── host-capture.ts       # 规则 R4
│   │   ├── ctx-verbs.ts          # 规则 R5
│   │   ├── string-heuristics.ts  # 规则 R6（粗扫兜底）
│   │   └── secrets.ts            # 规则 R7（硬编码密钥，静态启发）
│   ├── score.ts                  # 静态分公式 + verdict 逻辑
│   └── cache.ts                  # 扫描缓存（hash → 报告，跨调用复用）
└── test/
    ├── fixtures/                 # 正例/负例/模糊例（见 §9 测试矩阵）
    └── scanner.test.ts           # vitest 单元测试（scanner-bin 直测）
```

### 3.1 进程模型

- **scanner-bin**：`spawn(process.execPath, [scannerBinPath], { stdio: ['pipe','pipe','pipe'] })`，单次调用单扫描（请求-响应式，扫完即退出，避免常驻进程的生命周期管理）。恶意输入只会影响子进程自身。
- **audit**：不独立进程——直接消费 `ctx.llm`（DSH 能力缝），由 LLM provider 插件负责出网。
- 崩溃/超时：scanner 子进程 15s 超时 kill（`deadline`）；超时按"扫描失败"返回，不伪造 verdict。

---

## 4. 静态扫描引擎（scanner-bin）规格

### 4.1 进程协议（stdin/stdout JSON，单行）

```ts
// 请求（stdin，一行 JSON）
interface ScanRequest {
  kind: 'code' | 'files'
  language?: 'js' | 'ts'          // code 时必填；files 时按扩展名推断（.js/.ts/.mjs/.cjs）
  runtime?: 'host' | 'sandbox'    // code 时可选：run_code→host；cordis_run/workflow→sandbox（R3 分级用，默认 host）
  code?: string                   // kind='code'：源码字符串
  files?: string[]                // kind='files'：绝对路径列表（插件包 lib/）
  rules?: Record<string, boolean> // 规则开关（默认全开）
}

// 响应（stdout，一行 JSON）
interface ScanResponse {
  ok: boolean
  error?: string                  // ok=false 时的消息
  report?: ScanReport             // ok=true
}

interface ScanReport {
  engine: 'static-v1'
  sourceCount: number             // 扫描的文件/代码块数
  findings: Finding[]
  staticScore: number             // 0-100
  verdict: 'critical' | 'suspicious' | 'clean'
}

interface Finding {
  rule: string                    // 规则 ID，如 'R1'
  severity: 'critical' | 'high' | 'medium' | 'info'
  message: string                 // 人类可读描述（中文）
  evidence: string                // 命中的代码片段（截断 300 字符）
  file?: string                   // files 模式下文件名
  line?: number
  confidence: 'certain' | 'likely' | 'heuristic'
}
```

### 4.2 AST 解析

- 用 `typescript` 包：`ts.createSourceFile(filename, code, ts.ScriptTarget.Latest, /*setParentNodes*/ true, scriptKind)`。只读遍历，**永不** `ts.transpile`/`ts.createProgram`（不做类型检查，只做语法结构）。
- 遍历方式：`ts.forEachChild` 手写访问器（不用 transformer API，保持确定性）。
- 每文件扫描时长上限：文件数 × 单文件 2s（大文件节流，超时跳过并记 info finding `R8-scan-skipped`）。

### 4.3 规则集 v1（7 条）

#### R1 constructor-chain —— 构造器链逃逸（critical）

**动机**：已 PoC 实证。vm 沙箱内宿主函数（`TextEncoder`/`btoa`/`atob`/`agent`/`parallel` 等）的 `.constructor` 指向宿主 `Function`，`constructor("return process")` 即逃逸。

**AST 模式**：
```
PropertyAccessExpression: name === 'constructor'
  且 在 CallExpression 中作为 callee（MemberExpression 的 name 是 'constructor'）
  且 CallExpression 的 argument 是字符串字面量或可静态求值的字符串表达式
  且 字符串内容匹配 /return\s+\w*process|this\.constructor|process\./
```

**伪码**：
```ts
function checkR1(node: ts.Node, sf: ts.SourceFile): Finding[] {
  const found: Finding[] = []
  walk(node, n => {
    if (!ts.isCallExpression(n)) return
    const callee = n.expression
    if (!ts.isPropertyAccessExpression(callee)) return
    if (callee.name.text !== 'constructor') return
    const arg = n.arguments[0]
    if (!arg || !isStringyLiteral(arg)) return          // 字符串字面量或 + 拼接
    const text = stringyValue(arg)
    if (/return\s+process/.test(text)) {
      found.push({
        rule: 'R1', severity: 'critical', confidence: 'certain',
        message: '构造器链逃逸：宿主函数的 constructor 指向宿主 Function，可借此返回 process',
        evidence: n.getText(sf).slice(0, 300),
        line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1,
      })
    }
  })
  return found
}
```

**误报控制**：字符串内容必须命中逃逸特征（`return process` / `return global` / `this.constructor`），仅 `x.constructor` 访问（无调用/无危险字符串）不报。

#### R2 dynamic-exec —— 动态执行（high）

**AST 模式**：`new Function`、`new AsyncFunction`、`new (async()=>{}).constructor`、`eval(`、`Function(`、`vm.runInContext`/`runInNewContext`、`import(`、`require(`（裸调用/动态字符串）。

**命中清单**：
- callee 是 Identifier `eval` → high
- `new Function` / `new AsyncFunction` → high（参数含逃逸字符串升级 critical，见 R1 复用）
- `(async()=>{}).constructor` 捕获 → high
- `import()` 动态导入（字符串字面量非静态）/ `require` → medium（在插件上下文里 require 是逃逸通道，但某些合法插件也会用；给 medium + heuristic）

**误报控制**：`import x from 'y'` 静态导入不匹配；`require` 只在"非顶级常量"或"动态字符串参数"时报，顶级 `const fs = require('fs')` 在插件宿主中本就被 trap（sandbox.ts:111-119）——但我们要扫的是**宿主外**代码（npm 包），那里 require 就是真逃逸 → npm 包扫描时 R2 的 require 规则升为 high。**按扫描场景（code vs files）调整严重度**。

#### R3 process-direct —— 直接访问 process（critical/high）

**AST 模式**：Identifier `process`，且作用域内无遮蔽（同函数/块内无 `const/let/var process`、无参数名 process），随后任意成员访问：
- `.getBuiltinModule(` → critical（Node 22 任意内置模块加载）
- `.mainModule.require(`、`.module` → critical
- `.env` → high
- `.exit(` → critical（杀宿主进程）
- `child_process`/`fs`/`net`/`dgram`/`os`/`http` 经 `process` 可达路径 → high
- 裸 `process` 引用（无成员访问，如 `typeof process`）→ info

**作用域遮蔽**：`ts` 的 `setParentNodes: true` 后沿 parent 链收集最近作用域声明；命中声明即跳过（防误报 `function f(process) {...}` 等合法遮蔽）。**process 是否可达按 runtime 区分**：`process` 不在 NODE_API_REDIRECTS（sandbox.ts:96-108 仅 trap require/timers/fetch）；它是数据型全局，vm 沙箱不 trap、保持 `undefined`（sandbox.ts:90-94 注释）。`runtime='host'`（run_code：AsyncFunction 宿主域，bootstrap.ts:405，process 可达）→ 命中即 critical；`runtime='sandbox'`（动态插件/workflow：vm 域，process undefined）→ 裸 `process` 是未遂逃逸或 `typeof process` 探测，降为 high（真逃逸走 R1/R4）。协议新增 `runtime?: 'host'|'sandbox'`（tools/execute 守卫按工具名传入）。

#### R4 host-capture —— 宿主闭包捕获（critical）

**动机**：已 PoC 实证。workflow 沙箱把 `agent`/`parallel`/`pipeline`/`phase`/`log` 塞进 vm 全局；动态插件沙箱暴露 `TextEncoder`/`TextDecoder`/`btoa`/`atob`/`console`/`harness`。

**AST 模式**：Identifier 命中逃逸源名单：
```
逃逸源名单 = { agent, parallel, pipeline, phase, log, TextEncoder, TextDecoder, btoa, atob }
```
且该 Identifier 的 parent 链上出现 `.constructor` 访问、`.constructor(...)` 调用、`Function(` 转换、或作为 `Object.getPrototypeOf` 参数 → critical。

**误报控制**：单纯调用 `log('x')`、`agent(fn)` 不报（工具使用是合法场景）；只有"逃逸源 → 构造器链/原型链"组合才报。

#### R5 ctx-verbs —— ctx 逃逸尝试信号（medium）

**动机（已按源码修正）**：`CTX_VERBS`（guard.ts:636）是沙箱 ctx **白名单** = { effect, on, once, provide, timeout, interval, setTimeout, setInterval, throttle, debounce }——全是刻意放行的合法 fiber 动词，**不是危险词**；非白名单属性（plugin/emit/loader/inject/root/fiber/registry/extend…）被 sandboxContext 代理 `denyRead` 拒绝（guard.ts:723-735, 753-767，"Framework internals … withheld by design"）。因此 R5 检测的是**逃逸尝试信号**：沙箱代码访问被 withheld 的框架成员或未声明服务。

**AST 模式**：`ctx.<prop>` / `<ctx名>.<prop>`（ctx 名：ctx/context/self/pluginCtx）调用或访问，且 `prop ∉ CTX_VERBS ∪ {tools, get}` → medium / likely。

**误报说明**：无法静态得知 inject 声明，合法已声明服务（`ctx.fs` 等）会被误报——report 模式可接受（deny 阈值默认 critical 不受影响）。

**注意**：默认仅 code 场景启用（files 场景 npm 包用真实 ctx，误报率高），Config 可开。

#### R6 string-heuristics —— 字符串粗扫兜底（info/heuristic）

**动机**：模板拼接、编码混淆绕过 AST 精细匹配时的兜底层。

**模式**（字符串字面量/模板串内容正则，全部 `confidence: 'heuristic'`，级别 info，绝不参与 verdict 升级）：
- `/return\s*[+ ]*\s*['"]?process/`（拼接 `"return " + "process"`）
- `/getBuiltinModule/`
- `/child_process/`、`/require\(\s*['"](child_process|fs|net|vm)/`
- `/process\.(env|exit|mainModule)/`
- 混淆特征：`String\.fromCharCode`、`Buffer\.from\(.+base64\)`、`atob\(` 链、`charCodeAt` 循环

#### R7 secrets —— 硬编码密钥（high 当命中，级别按类别）

**模式**：
- API key 正则：`sk-[A-Za-z0-9]{16,}`、`AKIA[0-9A-Z]{16}`（AWS）、`AIza[0-9A-Za-z_-]{20,}`（GCP）、`gh[pousr]_[A-Za-z0-9]{20,}`（GitHub）、`xox[baprs]-`（Slack）
- `.env` 模式泄漏：`DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY\s*=\s*\S+`（非占位符）
- 特征 URL：`api\.deepseek\.com`/`api\.openai\.com` 等含 key 的 query 参数
- 阈值：命中即 high；占位符（`<...>`/`xxx`/`example`）排除。

#### 规则注册表

| ID | 名称 | 默认级别 | 适用场景 | 确定性 |
|---|---|---|---|---|
| R1 | constructor 链逃逸 | critical | code + files | certain |
| R2 | 动态执行 | high（files）/ high（code，逃逸串升级 critical） | both | certain/likely |
| R3 | process 直接访问 | critical/high | code + files | certain |
| R4 | 宿主闭包捕获 | critical | code（动态插件/workflow）| certain |
| R5 | 危险 ctx 动词 | medium | 仅 code | likely |
| R6 | 字符串粗扫 | info | both | heuristic |
| R7 | 硬编码密钥 | high | both | likely |

### 4.4 评分模型（确定性）

```
staticScore = max(0, 100 - Σ(severity 权重 × 命中数 × confidence 系数))
```

| severity | 基础权重 | confidence 系数 |
|---|---|---|
| critical | 45 | certain 1.0 / likely 0.8 / heuristic 0.4 |
| high | 20 | certain 1.0 / likely 0.8 / heuristic 0.4 |
| medium | 8 | certain 1.0 / likely 0.7 / heuristic 0.3 |
| info | 2 | 恒定 0.5 |

**verdict 逻辑（唯一权威判定）**：
```
critical 命中 ≥ 1            → verdict: 'critical'
无 critical 且 high ≥ 1      → verdict: 'suspicious'
其余（medium/info/无命中）    → verdict: 'clean'
```
- heuristic 级别的命中**永不**改变 verdict（R6 永不升级）。
- 得分与 verdict 独立呈现：verdict 由规则决定，staticScore 是连续量。README 需解释二者关系（verdict 是门禁，score 是直觉信号）。

### 4.5 缓存

- `kind: 'files'` 扫描结果按 `hash(路径+内容) → {report, ts}` 缓存到 `$TMPDIR/dsh-plugin-vet-cache/`（或 Config 可指定目录）；`audit` 层单独缓存 LLM 结果（见 §5.4）。
- 缓存键含 engine 版本（`static-v1`），升级规则集即失效。
- 缓存不覆盖 verdict 时效性：文件 mtime/内容变化即失效。

---

## 5. LLM 审计层（audit）规格

### 5.1 能力缝消费（已按 deepseek-harness 源码核实）

- `inject: ['llm', 'sessions']`
- 路由解析（`src/audit/route.ts`，模板=session-title-llm/src/index.ts:172-183）：
  1. Config 显式 `provider` + `model`（必须成对，成对校验；仅一个即 fail-loud）
  2. 回落会话当前模型路由：`session.requestHeader()?.config`（`packages/core/session/src/index.ts:670`）——**用户配啥模型就用啥**（注：session-title-llm 模板的 `resolveRoute` 收的是 `request.route`，src/index.ts:171-183，属服务方模式；本插件作为工具插件走 session 的 requestHeader）
  3. 都不可得 → 抛错（fail-loud，附教学信息"在 Config 配 provider/model 或先发起一次会话"）
- 调用（模板=session-title-llm/src/index.ts:246-287）：
  ```ts
  const options = deepFreeze({
    provider: route.provider,
    model: route.model,
    messages: [createUserMessage({
      content: [{ type: 'text', text: framedInput }],
      source: { kind: 'plugin', plugin: 'dsh-plugin-vet' },
    })],
    system: roundPrompt(round),
    maxTokens: config.auditMaxTokens,          // 默认 2048
    purpose: 'plugin-audit',                    // ⚠ GenerateOptions.purpose 是闭联合 'compaction'|'session-title'（llm:355）→ 需上游扩 union 或断言，否则省略该字段
    signal: deadline.signal,                    // 每轮独立 deadline，默认 120s
    sessionId: exec.agent?.session.id,   // exec 无 sessionId；经 exec.agent.session 取（tools/schema.ts:535、agent:476）
  })
  const assembler = new BlockAssembler()
  for await (const chunk of ctx.llm.stream(options)) assembler.push(chunk)
  const terminalError = finishError(assembler.finish)   // stop 才成功
  if (terminalError !== undefined) throw terminalError
  const text = assembler.blocks().filter(b => b.type === 'text').map(b => b.text).join(' ')
  ```
- 输入字节上限：每轮代码块 32KB，超限按文件分块（每块单独进轮 2/3 提示词）。
- 无 JSON mode（已核实全仓无 `response_format`）→ 结构化输出靠 prompt 框定 + 代码侧解析（§5.3）。

### 5.2 编排（4 轮，`src/audit/orchestrator.ts`）

```
轮 1 总览：system=prompts.round1；输入=静态报告摘要 + 代码（≤32KB）
        输出= {summary, dataFlow[], permissionBoundary[], riskNotes[]} JSON
轮 2 敏感点：system=prompts.round2；输入=轮 1 输出 + 代码全量（分块）
        输出= {findings: [{category, evidence, risk, suggestion}]} JSON
轮 3 质量：system=prompts.round3；输入=轮 1+2 输出 + 代码（分块）
        输出= {dimensions: {errorHandling, boundaryChecks, dependencies, maintainability, docs},
               qualityScore: 0-100, qualityNotes[]} JSON
轮 4 汇总：system=prompts.round4；输入=轮 1/2/3 全量输出 + 静态报告
        输出= {llmFindings: [...], qualityScore, confidence, summary, recommendation} JSON
```

- 每轮独立 `ctx.llm.stream` 调用（不跨轮保留上下文，显式传前轮输出——可重试、可缓存、可审计）。
- 中途失败（网络/超时/解析失败）：已有轮次结果保留，未完成轮跳过并标记 `partial: true`；绝不伪造后续轮。
- `audit_plugin` 工具调用期间模型等待（同步返回评分卡），不异步回调（v1 简化）。

### 5.3 输出解析与校验（`src/audit/parse.ts`）

- 提取：取文本中第一个 `{` 到最后一个 `}`（容忍 markdown 代码围栏）。
- `JSON.parse` → 校验 schema（`src/report/types.ts` 的判定函数：字段存在性/类型/枚举）。
- 校验失败：重试一次（同一轮，提示词追加"上一输出无效：<错误>，请只输出合法 JSON"）。
- 再次失败：该轮降级为 `{error: 'parse-failed', partial: true}`，流程继续（不阻塞后续轮）。
- 数值钳制：`qualityScore` 强制 `[0,100]` 整数；越界钳制并标注。

### 5.4 缓存与会话日志合规

- LLM 结果缓存：`hash(pluginId+版本+静态报告摘要+模型名) → 评分卡`（默认 7 天有效，Config `auditCacheTtlHours`）。同一插件重复审计不重复花钱。
- **会话日志**（Model-visible ⟺ logged 约定，模板=session-title-llm/index.ts:262-269）：每次 `ctx.llm.stream` 前后 append log-only 会话事件（audit 请求：插件名/轮次/输入字节数/模型；audit 结果：评分卡 JSON）。事件 key 挂 `audit-plugin-vet/*`，`ignorable: true`（不要求构建侧强制读取）。

### 5.5 提示词模板（`src/audit/prompts.ts`，英文正文 + 中文注释）

**轮 1（总览）**：
```
You are auditing a plugin for a plugin-based agent framework. The plugin is about to run
on the host machine with the user's permissions. The code below has already passed a
deterministic static scan (report attached). Your job for THIS round: understand the plugin.

Produce ONLY a JSON object, no prose:
{"summary":"<2-3 sentence what the plugin does>",
 "dataFlow":["<where input comes from, where output goes, any network calls>"],
 "permissionBoundary":["<what OS/host capabilities the plugin touches: files, network, process, env>"],
 "riskNotes":["<anything unusual or suspicious in structure>"]}

Rules: trust only evidence you can cite (quote line numbers). If the code looks obfuscated
or evasive, say so explicitly. Never claim "looks safe" without evidence.
```

**轮 2（敏感点）**：附静态报告 + 代码。输出：
```
{"findings":[{"category":"secret|exfiltration|telemetry|obfuscation|dangerous-api|other",
  "evidence":"<quoted code, max 200 chars>","risk":"low|medium|high|critical",
  "suggestion":"<how to fix, or 'remove' if no legitimate use>"}]}
```
明确指令：category 只能是枚举之一；evidence 必须可回溯到代码；不发现就输出空数组（不许编造）。

**轮 3（质量）**：输出 `{"dimensions":{...},"qualityScore":<0-100>,"qualityNotes":[]}`；dimensions 枚举：errorHandling/boundaryChecks/dependencies/maintainability/docs，每项 `{"score":0-100,"note":"..."}`。qualityScore = dimensions 平均（LLM 自己算，代码侧只钳制范围）。

**轮 4（汇总）**：输入前三轮输出 + 静态报告，输出最终评分卡 JSON（schema 见 §6.3）。明确指令：**"The deterministic static verdict (critical/suspicious/clean) is authoritative and provided by rules, not by you. Do not change, soften, or relabel it. Your role is to add context."**

### 5.6 评分卡（`src/report/types.ts` + `render.ts`）

```ts
interface PluginScorecard {
  pluginName: string
  pluginVersion?: string
  scannedAt: string
  static: {
    verdict: 'critical' | 'suspicious' | 'clean'
    staticScore: number
    findings: Finding[]               // §4.1
  }
  llm?: {                             // LLM 轮未跑或失败时为 undefined
    qualityScore: number              // 0-100
    findings: LlmFinding[]            // 轮 2 输出
    summary: string                   // 轮 1/4
    recommendation: 'approve' | 'review' | 'reject'
    confidence: 'high' | 'medium' | 'low'
    partial: boolean                  // 有轮次未完成
  }
}
```

渲染（presentResult，generic card）：verdict 大字 + 静态分/质量分并排 + findings 折叠列表 + recommendation。纯函数（`render.ts`），不触 IO。

---

## 6. 插件本体（src/index.ts）规格

### 6.1 插件骨架（对齐 DSH 包规范）

```ts
export const name = 'plugin-vet'        // 插件 id
export const inject = ['tools', 'llm', 'sessions'] as const
export const Config = configSchema       // schemastery
export function apply(ctx: Context, config: VetConfig): void { ... }
// 无 default export
```

### 6.2 Config（schemastery，`src/config.ts`）

```ts
interface VetConfig {
  mode: 'report' | 'deny'                 // 默认 'report'（fail-open，用户拍板）
  autoScan: boolean                       // 默认 true：internal/plugin 自动静态扫描
  autoAudit: boolean                      // 默认 false：新插件自动 LLM 审计（花钱，默认关）
  provider?: string                       // LLM 路由覆盖（必须与 model 成对）
  model?: string
  auditMaxTokens: number                  // 默认 2048
  auditTimeoutMs: number                  // 默认 120000（每轮）
  scannerTimeoutMs: number                // 默认 15000
  auditCacheTtlHours: number              // 默认 168（7 天）
  rules: Record<string, boolean>          // 规则开关（R1-R7，默认全开）
  denyOn: 'critical' | 'suspicious'       // mode='deny' 时的拦截阈值，默认 'critical'
  allowlist: string[]                     // 包名/插件 id 白名单（跳过扫描）
}
```
校验（load 时 fail-loud）：provider/model 成对；`denyOn: 'critical'` 时 `mode` 必须显式（默认值是 report 与 denyOn 的默认组合要自洽）。

### 6.3 工具 1：`scan_plugin`（`src/tools/scan-plugin.ts`）

```ts
defineTool({
  name: 'scan_plugin',
  description: 'Static-scan plugin code or an installed package for escape patterns, dangerous
    process access, hardcoded secrets. Deterministic rule engine in an isolated process; returns
    a scorecard with verdict (critical/suspicious/clean).',
  parameters: {
    target: { type: 'string', required: true, enum: ['dynamic-code', 'package', 'file'] },
    source: { type: 'string', required: false },   // dynamic-code: 源码字符串；file: 路径
    packagePath: { type: 'string', required: false }, // package: 插件包目录（绝对路径）
    reason: { type: 'string', required: false },
  },
  output: {
    schema: scorecardJsonSchema,
    render: (args, value) => [{ type: 'text', text: renderScorecard(value) }],
  },
  async execute(args, exec) { ... },      // → client.scan() → 评分卡
  presentCall: () => ({ card: 'generic', title: 'Scan plugin', kind: 'read' }),
})
```
- `presentationMeta` 无特殊（read 类）；工具注册走 `ctx.tools.register(tool)`（tools/schema.ts:1037，tool-skill:161 同款）。
- 结果即评分卡（§5.6 的 static 部分；无 LLM 段）。

### 6.4 工具 2：`audit_plugin`（`src/tools/audit-plugin.ts`）

- 参数：`target`/`source`/`packagePath` 同 scan_plugin + `deep: boolean`（默认 true：跑满 4 轮；false：只跑轮 1+2）。
- `timeoutMs: 600000`（10 分钟，覆盖 4 轮 × 120s + 重试余量）；`isConcurrencySafe: false`（LLM 请求贵，串行）。
- execute：先跑静态 scan（复用 scan_plugin 逻辑）→ **verdict=critical 直接短路返回评分卡（不调 LLM，省 token，附注 "skipped LLM audit: static verdict is critical"）** → 否则编排 4 轮 → 完整评分卡。
- 错误路径：LLM 全部轮失败 → 返回 static 评分卡 + `llm: { error: 'audit-failed', reason }`（fail-loud，不装成功）。

### 6.5 守卫 1：`internal/plugin` 自动扫描（`src/guards/internal-plugin.ts`）

- 挂载：`ctx.on('internal/plugin' as never, fiber => { ... })`（vendor cordis 内部事件，typert/loader 模板：packages/typert/loader/src/index.ts:411-422 同法）。
- 时机：fiber PENDING（apply 未跑）——只读检查，不拦加载（report 模式）；deny 模式 + verdict ≥ denyOn → 尝试 `fiber.dispose()` 并抛错（回滚加载；fiber.ts:299-306 支持同步 observer dispose）。`internal/plugin` 在 mount 与 dispose **都会触发**（fiber.ts:120-121 + :302）——仅处理 `fiber.state === PENDING` 的发射，dispose 发射直接忽略。
- 扫描对象：`fiber.entry?.options.name` 对应包的 lib/ 目录（files 模式）；entry 为 undefined（child/manual mount）直接跳过（loader.ts:412-413 同款）。**只扫 npm 安装的第三方包**：跳过 `@deepseek-ai/*` 白名单（官方包，内置信任）与 `allowlist`。
- 缓存：§4.5。
- 报告去向：`mode: 'report'` 时 append 会话日志事件（`vet/auto-scan`，含评分卡摘要）+ 在 `additionalContexts` 附加给模型（下一轮 pre-step 前可见——参照 repeat-tool-reminder 的附加方式，guard/repeat-tool-reminder/src/index.ts:213-224）。
- 注意：`internal/plugin` 事件对所有 `ctx.plugin` 触发（含本插件自己）——本插件 id 直接跳过（避免自扫死循环）。
- 局限（README 写明）：`internal/plugin` 只在插件**已在配置里**时触发；`dsh plugin add` 安装后首次启动加载即被覆盖，正确。

### 6.6 守卫 2：`tools/execute` 拦截（`src/guards/tool-execute.ts`）

- 挂载：`ctx.on('tools/execute', async (exec, next) => {...})`（timeout-policy 模板：guard/timeout-policy/src/index.ts:56-80）。
- 目标工具名：`cordis_define`、`cordis_run`、`run_code`（code-mode.ts:20 `RUN_CODE_NAME`）、`workflow`（workflow 工具接收 meta+script，脚本直达 worker vm）。`runtime` 映射：run_code→host；cordis_run/workflow→sandbox（供 R3/R4 分级）。
- 动作：从 `exec.arguments` 取代码字符串（cordis_define: `code.host`/`code.client`；run_code: `code`；workflow: `script`）→ scanner 扫（code 场景规则集：R1-R4、R6、R7 + R5；按工具名传 `runtime`）→
  - `mode: 'report'`：结果 append 会话日志 + 附加到工具结果文本（前缀 "VET: <verdict> ..."），**不拦截**；
  - `mode: 'deny'` 且 verdict ≥ denyOn：**不调 `next()`** 直接返回 `{ content: [{type:'text', text:'VET BLOCKED: ...'}], isError: true, error: { message } }`。
- 性能：code 场景每次调用都扫（代码短，ms 级）；不加缓存（同一代码重复跑——可加同内容 hash 缓存，Config 关闭）。

### 6.7 invariant.ts（DSH 包规范）

- 注册 manifest 名 `@jieai/dsh-plugin-vet`。
- 运行时断言（挂 `ctx.on('ready')` 或 apply 内，按仓库 invariant 约定断言**事件/数据关系**而非存在性——packages/AGENTS.md；模板 tools/schema.ts:128 `ctx.invariants.register(PACKAGE_NAME, install)`）：internal/plugin 观察到的第三方包数 ≥ auto-scan 产出数；tools/execute 拦截的每次 VET 结果都 append 了会话日志；scanner-bin 可执行（spawn 一次空扫验证 exit 0）。
- 断言失败 → fail-loud 抛错（含安装修复指引）。

---

## 7. 分发形态（bundle）

- `package.json`：
  ```jsonc
  {
    "name": "@jieai/dsh-plugin-vet",
    "version": "0.1.0",
    "type": "module",
    "main": "lib/index.js",
    "types": "lib/types/index.d.ts",
    "exports": {
      ".": { "types": "./lib/types/index.d.ts", "import": "./lib/index.js" },
      "./cordis.patch.yml": "./cordis.patch.yml",
      "./package.json": "./package.json"
    },
    "files": ["lib", "cordis.patch.yml", "README.md"],
    "peerDependencies": {
      "@deepseek-ai/cordis": "^4.0.0",
      "@deepseek-ai/dsh-tools": "^0.x",
      "@deepseek-ai/dsh-llm": "^0.x",
      "@deepseek-ai/dsh-session": "^0.x",
      "@deepseek-ai/dsh-invariants": "^0.x"
    },
    "dependencies": { "typescript": "^5.x", "@deepseek-ai/schemastery": "^2.x" },
    "dsh": { "bundle": { "patch": "./cordis.patch.yml" } }
  }
  ```
- `cordis.patch.yml`：
  ```yaml
  - insert:
      - id: plugin-vet
        name: '@jieai/dsh-plugin-vet'
        config:
          mode: report
          autoScan: true
          autoAudit: false
  ```
  （config 全静态字面量——verify-cordis-config 要求 metadata 静态；`!!js` 仅允许 config 内，但我们用字面量最稳。）
- 安装即生效链路（已核实）：`dsh plugin --profile web add @jieai/dsh-plugin-vet` → pnpm 装 → reconcilePlugins 读 `dsh.bundle` → 下次启动 `loadProfile` 解析 bundle 挂载插件。
- scanner-bin 构建（实现决策，已记录）：`tsc -p tsconfig.scanner.json` 产出到 `lib/scanner-bin/`（files 清单用 `"lib"` 覆盖，无需单独列 scanner-bin），运行时 `spawn(process.execPath, [scannerBinPath])`，路径经 `import.meta.url` 从 `lib/scanner/` 解析到 `lib/scanner-bin/index.js`，不依赖 cwd。

---

## 8. 依赖与工程约定

| 项 | 决策 | 理由 |
|---|---|---|
| AST 解析 | `typescript`（运行时依赖） | 仓库已验证可用；只读 API 稳定 |
| 运行时依赖 | typescript + @deepseek-ai/schemastery（peer: cordis） | 最小化；不引其他 |
| 测试 | vitest（scanner 单测）+ 手动本地 e2e | DSH 同款 |
| 语言 | TypeScript strict，ESM，无 default export | DSH 规范 |
| 编码 | 全部 UTF-8；提示词英文正文（模型指令稳定性），代码注释中文 | 可 i18n |
| lint | 至少 tsc --noEmit 过检；发布前 `pnpm pack --dry-run` 验 files | 防止漏包 |

---

## 9. 测试与验证矩阵

### 9.1 fixture（`test/fixtures/`）

| fixture | 内容 | 期望 |
|---|---|---|
| `escape-workflow.js`（正例） | `agent.constructor("return process")().getBuiltinModule('child_process').spawnSync('whoami')` | R1 critical + R6 info（字符串特征）；R3 不适用（无 `process` 标识符）→ verdict=critical |
| `escape-dynamic-plugin.js`（正例） | `TextEncoder.constructor("return process")().cwd()` | R1+R4 critical |
| `escape-run-code.ts`（正例） | `return process.getBuiltinModule('child_process').spawnSync('ls').stdout.toString()` | R3 critical（R2 不适用），verdict=critical |
| `clean-plugin.ts`（负例） | 简单工具注册插件（defineTool + register，无任何逃逸特征） | 零 finding，verdict=clean，staticScore ≥ 90 |
| `obfuscated-concat.js`（模糊例） | `const s = "return " + "process"; X.constructor(s)()` | R1 likely（字符串拼接求值）+ R6 heuristic；verdict=critical（R1 链仍在） |
| `shadowed-process.js`（负例-遮蔽） | `function f(process) { return process.pid }` | R3 不命中（作用域遮蔽），verdict=clean |
| `secret-in-plugin.js`（正例） | `const k = 'sk-123456789012345678901234567890'` | R7 high，verdict=suspicious |

### 9.2 测试层级

1. **scanner 单测**（vitest，`test/scanner.test.ts`）：协议往返、每规则正负例、评分公式边界（critical 门禁、heuristic 不升级）、遮蔽、超时跳过。
2. **parse 单测**：JSON 提取（markdown 围栏/前后杂文）、schema 校验失败、重试逻辑、数值钳制。
3. **route 单测**：provider/model 成对校验、回落 requestHeader、双缺 fail-loud。
4. **本地 e2e（手动脚本 `scripts/e2e-local.mjs`）**：
   - 在 deepseek-harness 仓库工作树（或临时 profile）执行 `dsh plugin --profile vet-test add <plugin-vet 本地路径>`（file: 依赖）
   - 起会话 → 让模型提交一个 `cordis_run`（用 PoC 逃逸代码）→ 断言 `mode:'report'` 时工具结果带 `VET:` 前缀；`mode:'deny'` 时被拦截（isError）
   - 断言 `scan_plugin` 工具对 3 个正例 fixture 返回 critical
   - 断言 `internal/plugin` 对 allowlist 外的第三方包触发 auto-scan 日志事件
   - e2e 需要 `DEEPSEEK_API_KEY`；无 key 时自动跳过 LLM 相关断言（同 DSH 的 test:e2e 惯例）

### 9.3 验收标准（Definition of Done）

- [ ] 7 条规则全部实现且有 fixture 正/负例覆盖
- [ ] scanner 单测全绿；评分公式边界用例覆盖 verdict 门禁
- [ ] audit 4 轮编排在真实 `ctx.llm`（DeepSeek）下跑通，评分卡 schema 校验通过
- [ ] 三守卫（internal/plugin、tools/execute、两工具）注册无异常；invariant 断言通过
- [ ] 本地 e2e 脚本可跑：report 不拦 / deny 拦截 / scan_plugin / auto-scan 四场景验证
- [ ] `dsh plugin --profile vet-test add <path>` 安装链路打通（bundle patch 生效）
- [ ] README 完成：安装、Config、规则表、信任边界、Known Limitations
- [ ] `pnpm pack --dry-run` 产物含 lib/scanner-bin/cordis.patch.yml/README

---

## 10. 阶段划分

| 阶段 | 内容 | 产出 | 验收 |
|---|---|---|---|
| 1 脚手架+引擎 | 目录/tsconfig/package.json + scanner-bin（ast/rules×7/score/cache/protocol）+ 单测 | scanner 可独立跑 | 9.3 前两项 |
| 2 插件本体 | config.ts/index.ts + scan_plugin + 两守卫 + invariant | 插件可挂载，静态链路通 | 9.3 3、4 项（静态部分）|
| 3 audit 层 | route/orchestrator/prompts/parse/session-log + audit_plugin | 评分卡全量产出 | 9.3 3 项（LLM 部分）|
| 4 包装+文档 | cordis.patch.yml/README/pack 校验 | 可发布 | 9.3 6-8 项 |
| 5 本地 e2e | scripts/e2e-local.mjs + DSH 测试 profile | 全场景验证 | 9.3 5 项 |
| 6 发布（用户执行） | npm publish + GitHub 仓库 | — | 用户手动 |

---

## 11. 风险与已知限制（Known Limitations 草稿）

1. **静态扫描不是安全边界**：混淆/编码/动态生成代码可绕过 AST 规则；R6 只提供"疑似"信号。与 DSH 官方立场一致——本产品是减速带+取证层，不是保险柜。
2. **LLM 审计可被提示注入**：恶意代码注释可试图操纵审计模型；因此 verdict 永不来自 LLM，且轮 2 指令要求"只信可引证的证据"。残余风险：LLM 可能漏报——置信度字段让用户知晓。
3. **`internal/plugin` 守卫不覆盖运行时动态挂载逃逸**（cordis-host-runner 的 vm 路径由 `tools/execute` 守卫在调用层拦截，代码字符串在到达 vm 前已被扫）。
4. **R5 仅 code 场景**（沙箱外 npm 包场景误报率高）；files 场景的 ctx 访问默认不报。
5. **扫描耗时**：大插件包（>100 文件）扫描可能超时跳过（info finding R8）；LLM 审计分钟级、按需调用。
6. **AI 质量分的局限性**：qualityScore 是模型主观判断，不构成安全保证；两分制分离呈现即是为此。
7. **白名单 `@deepseek-ai/*` 默认信任**：官方包不扫；未来若官方生态出现被攻破的包，需收紧（Config 可关闭该豁免——v1 留开关）。

---

## 12. 参考资料索引（deepseek-harness 源码，实现时对照）

| 主题 | 位置 |
|---|---|
| bundle 声明格式 | `packages/bundle/base/package.json:25-40`、`packages/boot/app-boot/src/profile.ts:41-45` |
| dsh plugin add 链路 | `apps/cli/src/plugin.ts:120-158`（reconcile :59-91）|
| 工具注册模板（skill 工具） | `packages/skill/tool-skill/src/index.ts:81-161` |
| tools/execute 拦截模板 | `packages/guard/timeout-policy/src/index.ts:56-80` |
| internal/plugin 挂法 | `packages/typert/loader/src/index.ts:411-422`；事件源 `vendor/cordis/src/fiber.ts:302` |
| ctx.llm 消费模板 | `packages/session/session-title-llm/src/index.ts:229-294`（路由 :172-183，日志 :262-269）|
| 压缩模板（JSON 框定） | `packages/compaction/compaction-basic/src/summarizer.ts:121-195` |
| 会话路由回退 | `packages/core/session/src/index.ts:670`（requestHeader config）|
| CTX_VERBS 白名单（R5 对照） | `packages/extensions/cordis-host-runner/src/guard.ts:636` |
| 逃逸机制实证（PoC） | workflow：`packages/workflow/workflow-worker-thread/src/runtime.ts:98-108`；run_code：`packages/code-runtime/code-runtime-worker-thread/src/bootstrap.ts:405-412`；动态插件：`packages/extensions/cordis-host-runner/src/sandbox.ts:137-140` |
| 官方信任立场 | `packages/extensions/tool-cordis/src/prompt.ts:8` |
| run_code 工具名 | `packages/core/tools/src/code-mode.ts:20` |
| approval 链（本插件不依赖，但 deny 语义对照） | `packages/interaction/user-approval/src/index.ts:304-344` |
| CTX_VERBS 全量（R5 白名单语义） | `packages/extensions/cordis-host-runner/src/guard.ts:636` |
| process 未 trap（数据型全局保持 undefined） | `packages/extensions/cordis-host-runner/src/sandbox.ts:90-94, 96-108` |
| purpose 闭联合（A1 对照） | `packages/llm/llm/src/index.ts:355` |
| workflow 工具定义（A4 对照） | `packages/workflow/workflow-worker-thread/src/index.ts:100` |
| exec 无 sessionId，经 exec.agent.session（A1 对照） | `packages/core/tools/src/schema.ts:535`、`packages/core/agent/src/index.ts:476` |
| invariant 注册模式（B2 对照） | `packages/core/tools/src/schema.ts:128`、`packages/AGENTS.md` |
| 工具注册 ctx.tools.register（B3 对照） | `packages/core/tools/src/schema.ts:1037`、`packages/skill/tool-skill/src/index.ts:161` |

---

## 13. 修订记录（v1 → v1.1）

| 项 | 内容 | 依据（dsh-src @ 47f943859b） |
|---|---|---|
| A1 | §5.1 sessionId 改为 exec.agent?.session.id；purpose 标注闭联合限制 | tools/schema.ts:535、agent:476、llm:355 |
| A2 | §4.3 R3：process 不在 NODE_API_REDIRECTS；按 runtime 分级（host→critical / sandbox→high）；协议新增 runtime 字段 | sandbox.ts:90-108 |
| A3 | §4.3 R5：CTX_VERBS 是白名单非黑名单；改为检测 withheld 框架成员/未声明服务 | guard.ts:636, 723-767 |
| A4 | §6.6 拦截清单增加 workflow 工具；runtime 映射 | workflow-worker-thread:100 |
| A5 | §7 peerDependencies 补 dsh-tools/dsh-llm/dsh-session/dsh-invariants | session-title-llm/package.json:34-44 |
| B1 | §6.5 跳过 dispose 发射与 entry-less fiber | fiber.ts:120-121, 302；loader.ts:412-413 |
| B2 | §6.7 invariant 断言事件/数据关系 | packages/AGENTS.md；tools/schema.ts:128 |
| B3 | §6.3 明确 ctx.tools.register | tools/schema.ts:1037 |
| FIX | §9.1 escape-workflow.js 期望修正（R3 不适用） | 无 process 标识符 |
| IMPL | §7 scanner-bin 构建产出 lib/scanner-bin | 构建决策 |
