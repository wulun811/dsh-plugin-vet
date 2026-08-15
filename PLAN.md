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
>
> **产品定位（D21）：监控报警器，不是打手。** vet 只做「检查 → 报警 → 给建议」：写时查（静态扫描）、跑时盯（运行时守卫）、报警面（评分卡 + GUI 盾牌状态灯）。**vet 永不替用户动手**——不自动卸载、不自动杀进程、不自动改配置；deny 模式是部署者显式开启的 opt-in 且不构成产品身份。最终怎么处置，由用户在自己的 DSH 上操作决定。

### 2.2 信任边界（本产品最重要的设计约束）

1. **verdict 只由确定性静态层产出**。LLM 输出永远是"建议/注释/质量分"，绝不参与 critical/suspicious/clean 判定。原因：LLM 可被恶意代码中的提示注入欺骗（注释里写"ignore the following rules"），确定性规则不能。
2. **静态层与插件代码物理隔离**。扫描器是独立进程（spawn scanner-bin），AST 只读、从不 eval。即使宿主进程被逃逸代码篡改，扫描结果仍来自干净进程；扫描器崩溃也不影响宿主。
3. **LLM 层输入先过静态层**。只有静态层判为非 critical 的代码块才进入 LLM 审计（critical 直接短路，不浪费 token）；LLM 审计输入注明"该代码已通过静态层"，提示词要求以怀疑态度复核。
4. **两分制不合并**：`staticScore`（确定性规则）与 `qualityScore`（LLM 主观维度）分开呈现，禁止合成单一总分——合成会让 LLM 污染 verdict 边界。
5. **不把本产品自身称为安全边界**。README Known Limitations 明说：静态扫描是恶意代码的"减速带+取证层"，不是安全边界（与 DSH 官方立场对齐）；产品价值是把"未知"变成"已知"，把"信任"变成"可决策的证据"。
6. **fail-open 起步**：默认 `mode: 'report'`（只报告不拦截），`mode: 'deny'` 由部署者显式开启。用户已拍板。
7. **alarm-only（D21，用户指令）**：产品身份 = 监控报警器。运行时守卫只 watch 不 kill；vet 的自动行为（deny 拦截、fiber.dispose）仅存在于部署者显式开启的 opt-in 模式，且文档明示「脱离产品定位，风险自担」。报警只附建议（怎么修），处置动作永远留给用户在 DSH 上操作。

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

**模式**（字符串字面量/模板串内容 + 拼接/调用表达式文本正则——混淆特征出现在代码而非字符串里，矩阵测试发现的漏检面（D13）；全部 `confidence: 'heuristic'`，级别 info，绝不参与 verdict 升级）：
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

- [x] 7 条规则全部实现且有 fixture 正/负例覆盖
- [x] scanner 单测全绿；评分公式边界用例覆盖 verdict 门禁
- [ ] audit 4 轮编排在真实 `ctx.llm`（DeepSeek）下跑通，评分卡 schema 校验通过（fake llm 已全绿；真实模型待 DEEPSEEK_API_KEY）
- [x] 三守卫（internal/plugin、tools/execute、两工具）注册无异常；invariant 断言通过
- [x] 本地 e2e 脚本可跑：report 不拦 / deny 拦截 / scan_plugin / auto-scan（keyless 部分已跑通 PASS；会话级断言按惯例无 key 自动跳过）
- [x] `dsh plugin --profile vet-test add <path>` 安装链路打通（bundle patch 生效，已实测 vet-test profile bundles 含插件）
- [x] README 完成：安装、Config、规则表、信任边界、Known Limitations
- [x] `pnpm pack --dry-run` 产物含 lib/scanner-bin/cordis.patch.yml/README

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

### v1.1 阶段 2 实现决策（已记录）

| # | 决策 | 依据 |
|---|---|---|
| D1 | dsh-tools 的 ValueSchemaSpec/ParameterPropertySpec **不支持 enum 字段**（类型无此声明，会使 defineTool 泛型推断崩）→ 参数选项写入 description，运行时校验照常 | node_modules/@deepseek-ai/dsh-tools/lib/types/index.d.ts |
| D2 | 输出 schema 必须**内联**在 defineTool 调用里（模块级常量丢失字面量推断，type: string 宽化报错）；object items 需带 additionalProperties | tool-skill 同款；schema.ts 泛型推断 |
| D3 | schemastery Schema 实例是**可调用**的（schema(value) 校验+归一化+抛错），无 .validate() 方法 | node_modules/@deepseek-ai/schemastery/lib/types/index.d.ts:123 |
| D4 | schemastery 可选字段用 .required(false)（无 .optional()） | 仓库 apiproxy 同款 |
| D5 | internal/plugin 事件在 cordis 事件表**有类型**（internal/plugin(fiber: Fiber)），无需 as never；fiber.entry 是 typert loader 附加元数据，用 Fiber & { entry? } 交集访问 | node_modules/@deepseek-ai/cordis/lib/types/events.d.ts:218 |
| D6 | deny 路径用 scanSync（spawnSync）在 observer 内**同步**判定 + 抛错（fiber.ts:299-306 同步 observer 可回滚挂载）；report 路径异步 | fiber.ts 发布语义 |
| D7 | scanner-bin 路径：lib/scanner/client.js → ../scanner-bin/index.js（import.meta.url） | 构建布局 |
| D8 | 客户端协议类型与 scanner-bin 重复（跨 rootDir 无法单源共享），KEEP IN SYNC 注释 + 往返测试保证一致 | 构建约束 |


### v1.1 阶段 3 实现决策（已记录）

| # | 决策 | 依据 |
|---|---|---|
| D9 | LlmSection 成功形态 qualityScore 可缺省（deep:false 或部分轮次失败时渲染 n/a，不合成不存在的主观分） | report/types.ts |
| D10 | 审计事件不能走 session.append（无 ignorable 参数，coordinator.ts:1063 对未知非 ignorable 类型拒读）→ inject 增加 sessionPersistence，走 persistence.append 完整信封 + ignorable: true；SessionEventMap 声明合并（session-events.ts） | coordinator.ts:1063；session/src/index.ts:604 |
| D11 | GenerateOptions.purpose 是闭联合（compaction/session-title，llm:355）→ 审计调用省略 purpose（A1 修正落地） | llm/lib/types/types.d.ts:355 |
| D12 | critical 短路返回 llm: { error: 'audit-skipped', reason }（错误变体扩为 audit-failed/audit-skipped），渲染区分"跳过/失败" | PLAN.md §6.4 附注落地 |


### v1.1 审核补漏（D13）

| # | 决策 | 依据 |
|---|---|---|
| D13 | R2 补 vm.runInContext/runInNewContext（PLAN.md §4.3 命中清单核对补漏）；R6 混淆特征扫描面扩展至调用表达式文本（String.fromCharCode/atob/charCodeAt/Buffer.from base64，矩阵测试发现"代码里的混淆特征"漏检）；新增 28 用例对抗矩阵 test/plugins-matrix.test.ts（真实 DSH 插件 0 误报） | 审核对照 §4.3；矩阵测试 |
| D14 | 能力边界诚实清单落地 README（判定级/提示级/明确不检测三档，间接引用与 base64 混淆漏检形态经实测确认）；README 用例数修正 50→78 | 实测探测：7 种间接/混淆形态全部漏检（仅 R6 info 或零 finding），正例对照 critical |

### v1.1 路线与引擎评估（D15）

| # | 决策 | 依据 |
|---|---|---|
| D15 | **AST 引擎评估（malong-parse）**：Rust tree-sitter 9 语言符号/引用/指标提取引擎（MIT）。本地 0bore/malong-parse v0.3.37 = 公开最新（GitHub v0.4.5-post6 的 Cargo.toml 同版本；Rust 引擎自 0.3.37 后未更新）。**「0.4.5.post7」不存在**：GitHub tags/releases 最新 v0.4.5-post6，npm @jieai/dsh-malong-bridge 最新 0.4.5-post6，PyPI 无此包。**结论：不引入替换型引擎**——malong-parse 是符号提取器非规则引擎，vet 的 R1-R9 依赖 TS 语义 AST（isShadowed 词法作用域 / stringyValue 静态求值 / node 类型判断），CST 移植需整体重写规则层。采纳**方案 A（两级扫描）**：TS compiler 保留为权威精扫（verdict 语义不变），复用 malong-parse 基础设施（parser pool / tree cache / npm 4 平台二进制发布机制）做 Rust tree-sitter **预筛层**，大包快速排除干净文件、可疑文件送精扫（解决 R8 超时）；方案 C（audit 层接入 extract_symbols/extract_references 作 LLM 代码地图）列为 audit 增强 | 调查：GitHub API / npm registry / PyPI / 本地 0bore/malong-parse 源码与二进制 |
| D16 | **R9-1 资源安全规则族落地**（§14.2）：ast.ts 新增 numberyValue 数字静态求值（字面量/**/<</*/一元/括号/const 绑定）；新增 rules/resource-safety.ts 三检测——(1) new Array/Array(n)/Array.from({length})/Buffer.alloc*/allocUnsafe 无界分配 ≥1e8 → high certain；(2) while(true)/for(;;) 无出口同步循环（无 break/return/throw/await）→ high certain，含 await 常驻循环 → info heuristic（不升级）；(3) 无出口循环内 spawn/exec/execFile/fork/new Worker → high likely（fork 炸弹）。severity 上限 high 落实 §14.1（critical 会短路 LLM）；矩阵新增 9 样本（5 正例 + 4 负例），87/87 全绿，真实 DSH 插件 0 误报 | 矩阵测试；真实插件回归 |
| D17 | **方案 A 实测后暂缓 + R9-2/3/R10/R11 落地**：实测 600 文件 engine.scan 直调 180ms（parse+全部规则）、20 文件 client.scan（spawn）443ms——**parse 不是瓶颈，spawn 固定开销是绝对大头**，vet 调用场景低频（工具/插件加载），R8 预算 files×2s 实际不触发 → **不引入 Rust tree-sitter 预筛**（收益≈0、复杂度高），D15 方案 A 取消，远期改为 scanner daemon 常驻（省 spawn 开销，保持子进程隔离）；malong-parse 保持远期选项（方案 C audit 代码地图）。规则落地：R9-2 ReDoS 嵌套量词（(a+)+ 类，正则字面量 + new RegExp 构造）+ 递归无终止粗检（直接自调用无条件，三元/if/&&/|| 视为有出口）；R9-3 循环内 +=/Map.set/Promise.all（info/medium 提示档）；R10 供应链（package.json install 钩子 high + 依赖清单 info，CVE 匹配待数据源选型）；R11 破坏性文件操作（fs 删除/敏感路径读写 high/medium，解构/别名 fs 漏检已记录 Known Limitations）。矩阵 87→105 全绿，真实插件 0 误报 | 实测 benchmark；矩阵测试 |
| D18 | **现场验证（web profile 实装）**：R5 在真实 apply(ctx) 参数形态下 isShadowed 误判 → 永远漏报（矩阵用顶层代码掩盖），LLM 审计现场发现，修复 + 矩阵改真实形态（109 tests，5f09827）；vet 自扫验证——scanner-bin 的合法 process 使用（env/stdin/stdout/execPath）被 R3 报 high，记录为"宿主工具包合法 process 靠信任豁免"边界（README 能力清单）；web 插件列表搜不到 = **vet 未发布 npm（404 实锤）**，阶段 6 publish 后才会出现在可安装列表 | 现场 scan_plugin/audit_plugin 实测；npm view |
| D19 | **评分模型修正（用户反馈驱动）**：staticScore 原含 info 级扣分（权重 2）——vet 自扫 68 分（R3/R6/R9 全 info）引发"低分=插件不好"质疑。修正：**info 级权重 2→0**（字符串特征/能力触达面/超时跳过是提示与取证，不构成威胁密度；score 只反映 decisive critical/high/medium），info 明细仍列 findings 并在评分卡 explainScore 展示；R9-3 循环内 += 增加 isArithmeticRhs 降噪（右侧算术表达式=数值累加，非字符串拼接，跳过）；vet 自扫验证 verdict=clean score=100（R3×9/R6×11/R9×1/R10×1 全 info） | 用户反馈：低分不可解释；vet 自扫实测 |
| D20 | **全量扫描验证 + generic 降级扩展**：批量扫描 dsh CLI 依赖树的 195 个真实安装 @deepseek-ai 官方包（6.5s）——首轮 44 suspicious 全为官方包正常功能误报（loader/worker/bundle 的 require+new Function、native postinstall、minified for(;;) 解析循环）→ generic 模式扩展降级：R2 动态执行 high/critical→medium、R10 install 钩子 high→info、R9 无出口循环 high→medium（R3 已降）；修复后 **195/195 全 clean**（117 个 100 分），0 critical 0 suspicious；第三方恶意插件（plugin 模式）判定不变 | 批量扫描实测：195 包 / 44 误报归零 |
| D21 | **产品定位变更为「监控报警器」（用户指令）**：vet = 检查→报警→给建议，**永不替用户动手**（不自动卸载/杀进程/改配置）；deny 保留为部署者显式 opt-in（脱离产品身份，风险自担）；运行时守卫只 watch 不 kill；PLAN §2 / README 同步改写 | 用户指令：只报警不搞事，用户自行操作 DSH |
| D22 | **GUI 盾牌可行性确认 + 运行时守卫两层（T1/T2）**：web 客户端是插件体系——dsh.client 声明包被 client-modules 扫描进 window.__DSH_BOOT__（**不限 @deepseek-ai/***，第三方可进浏览器花名册）；顶栏孔位 conversation.session.header.actions（ui-conversation 声明）；数据通道 = 宿主 webServer /vet/status.json（ctx.get('webServer') 可选服务，非 web profile no-op）+ 浏览器轮询。运行时守卫：T1 哨兵（子进程读 /proc 宿主 VmRSS/子进程数/fd，报警 JSON 行）；T2 进程内钩子（包装 fs/child_process，栈归因→插件包名，敏感路径/破坏性删除/spawn 报警，官方归因降噪；旁路：ESM 具名导入快照、worker 独立 realm、原生插件）；默认 runtimeGuard: 'off'（性能/稳定代价 opt-in），watch 只报警不动作 | 源码核实：client-modules 扫描逻辑、ui-conversation contract/slots.ts:52-68、ui-subagent client 模式、host/webserver register API |
| D23 | **OSV 已知漏洞核对落地 + LLM 质量审计提示词强化（用户指令）**：§14.6-1 从"评估未排期"转实现——scanner-bin 新增 osv.ts（queryOsv 注入式 fetch + 4s 超时），engine 新增 scanWithOsv（静态判定含缓存与 OSV 分离：缓存只存静态报告，OSV 每次实时查询保持新鲜）；**决策修正：OSV 命中 high/certain 进 verdict（suspicious）**（§14.6 原"绝不进 verdict"改为"命中=真实已知漏洞，进 verdict 抬升"——用户要"最新防护"；名称级查询有噪音已用 5 条封顶缓解）；request.osv 严格 opt-in（===true），插件侧 osvCheck 配置默认 true（schema default），internal/plugin 守卫 + scan_plugin 工具透传；网络失败/超时静默降级纯静态。实测 lodash 4.17.20 → 5 CVE（ReDoS/命令注入/原型污染）verdict suspicious score 0。LLM round3 提示词补"具体质量/bug 检出"指令（unhandled rejection/吞错/空指针/逻辑倒置/竞态/死循环/资源泄漏/静默失败，逐条标 bug 或 smell 并引行号）。介绍栏加宽 280 并补"三道防线 + OSV + 质量识别"卖点 | 实测：api.osv.dev 200/1.7s；scanner 子进程全链路 lodash 5 CVE；153 tests 全绿 |
| D24 | **盾牌迭代（用户反馈驱动）**：三态图标（绿√/黄?/红!）、暗色莫兰迪分支、RAM 字母标签、黄灯预警详情卡、?→右侧介绍栏（主框不动，介绍栏绝对定位贴右缘等高，宽度按右侧空间 160-280 自适应）、去掉"只报警不代劳"文案改"发给 DSH 里的 LLM 协助排查" | 用户反馈逐轮验收 |
| D25 | **运行时守卫实战修复（用户实装反馈）**：(1) 开启按钮链路三连修——ctx.baseUrl 是 file: URL（path.join 不认，fileURLToPath 规整）；patch 条目 id 必须用 loader 条目 id plugin-vet（bundle insert 定义）而非包名（裸 @ 还是 YAML 保留指示符，DSH 曾代加引号）；自愈旧形态条目（带/不带引号的包名 id）幂等重写；(2) T2 敏感路径判定从"子串包含"改"精确段名 + 密钥后缀 + 词边界关键词"（tokens 子串把合法库 js-tokens 的读取、沙箱清理临时文件误报成敏感读写/删除）；(3) growth 误报：dsh web 冷启动加载 bundle + 进程内构建 client bundle 会在数秒内推高 RSS 数百 MB，滑动窗口从启动瞬间起算把它当"疑似泄漏"——改为启动满 growthWindowMs 进入稳态后才开窗测漂移（基线取稳态后采样），mem/fork/fd 绝对阈值不受影响。实测：重启后 RSS 558→556→556 MB 平稳（非泄漏），三采样 25s 间隔线程数 12 不变 | 用户实装逐项复现；VmRSS 趋势采样；159 tests 全绿 |
| D26 | **运行时守卫规则全面审核（用户指令：勿误报勿漏报）**：逐条审计 T1/T2 报警规则——**漏报修复**：(1) fs.promises 是独立对象（require('fs').promises / node:fs/promises 同一对象），同步包装不覆盖 → Promise 式读写删对 T2 完全隐形，补单独包装；(2) 操作集补 fs.cp/cpSync（复制密钥出局）、fs.open/openSync（fd 读写）；(3) 敏感段名补 .netrc/.pgpass/.gitconfig。**误报修复**：(4) spawn 规则原先无条件全报（shellTokens 配置定义了却从未使用——死配置），改为整词命中 shell 解释器/下载外联关键词（sh/bash/zsh/cmd/powershell/pwsh/curl/wget/nc/ncat/telnet）才报，git/node/pnpm 等常规子进程不再误报，报警消息带完整命令行；(5) fs-read 不再把系统根前缀（/etc /usr /var…）当敏感——读系统目录下普通文件（库文件/配置）属正常，枚举目标 /etc/passwd、/etc/shadow 由精确段名覆盖不受影响；写/删保持系统根判定（篡改/破坏）——isSensitivePath 增加 read/mutate 分档。保持不报：官方归因 spawn 降噪、T1 绝对阈值。已知残余旁路不变（ESM 具名导入快照、worker realm、原生插件、process.binding）。回归：js-tokens/沙箱临时文件读取删除不报，git 子进程不报，/usr 库文件读取不报；.ssh/.env/credentials/.netrc/.pgpass 读写、/etc/passwd 读取、sh -c/curl/wget 子进程仍报 | 源码逐条核对（含未使用配置扫描）；40 guard tests / 159 全套全绿 |
| D27 | **蜜罐陷阱落地（用户拍板做 + 反蜜罐反馈）**：honeypot 配置（enabled 默认 false，需 runtimeGuard: watch；dir 空 = ~/.dsh/.local），ensureHoneypot 幂等播种诱饵（.env / credentials.json / .npmrc / .netrc / aws-credentials / 真实一次性 RSA 密钥对 id_rsa.pem+pub），T2 钩子把蜜罐根登记为独立报警类 kind='honeypot'（读/写黄、删红，消息标注"诱饵密钥文件被触碰（疑似翻找密钥）"），alarm-only 身份不变。**反蜜罐设计（用户反馈：目录名带 vet-honeypot 太显眼，关键词过滤即破）**：目录/文件名/内容均无 honeypot/vet/decoy/fake 关键词——目录伪装成 ~/.dsh 下普通隐藏位置（与真实凭据 .credentials.yaml 同层，正是翻找者会扫的地方）；诱饵值全部"格式正确但无效"（AKIA/npm_/sk- 前缀真实、密钥体随机）；RSA 用 crypto 生成真的一次性密钥对（最逼真、泄漏零危害）；被删诱饵下次启动自动重建（自愈）。诚实边界：只抓"主动翻找文件型密钥"的插件，抓不了纯网络外联/worker/原生绕过；正规全目录扫描工具（备份/同步）可能误读诱饵 → 黄灯归因由用户判断 | 用户拍板：做；用户反蜜罐反馈；45 guard tests / 167 全套全绿 |
| D28 | **vet 自身内存账目诚实化（用户问：咱们占多少 / V8 堆高是不是咱们）**：实测拆账——vet 本体 JS 在主进程 V8 堆只占 ~1-2MB（lib 全部 js 81KB + 状态），V8 堆 366MB 是 DSH 宿主自己的（web UI/会话/esbuild）；vet 真正的大头是**独立子进程**：T1 哨兵常驻 ~56MB（其中 ~44MB 是任何 Node 子进程的底价，vet 逻辑仅 ~12MB）+ 扫描中 scanner-bin 瞬时峰值 ~92MB（加载 typescript，扫完即退）。**修复**：盾牌"总内存"原先只算 主进程 RSS + MCP，**漏掉了 vet 自己的哨兵进程**（正是用户觉得"看不见"的部分）——metrics 新增 vetRssMb/vetCount（识别 vet-sidecar / scanner-bin 子进程），盾牌总内存 = RSS + MCP + vet 子进程，新增"vet 进程"指标行（含 hint：哨兵 ~56MB 中 ~44MB 是 Node 底价），文案 zh/en 同步（总内存改"含子进程"、ram.hint 补 vet 哨兵、otherHint 澄清 MCP/vet 单列）。客户端对旧服务端 JSON 缺字段做 ?? 0 兜底（重启前不显示 NaN） | 实测：裸 node 44MB 底价 / vet lib 加载 +3MB heap / 哨兵 55.8MB / scanner 峰值 92MB；167 tests 全绿 |
| D29 | **全面自审（用户指令：检查代码/架构缺陷）**：逐层审计 + 实测验证——**严重**：(1) resolvePackageRoot 用 createRequire(import.meta.url) 按 vet 的 realpath 向上找 node_modules，**vet 被符号链接进 dsh 后永远解析不到 profile node_modules 里的第三方插件** → internal/plugin 自动扫描对第三方插件静默失效、T2 栈归因拿不到 pluginHint（loader 实际用 ctx.baseUrl 解析，修复：resolvePackageRoot 增加 profile 基准 + file: URL 规整，回退 vet 自身）；(2) T2 漏报面：fs.createWriteStream 写敏感路径不报（WRITE_OPS 缺流写 API，createReadStream 却在 READ_OPS 里）、open/openSync 带写 flags（w/a/x）误按 fs-read 报、cp/rename 只查 src（dest 覆盖系统文件不报）→ 补 createWriteStream、open flags 细分、cp/rename 双向检查；(3) 审计轮 2/3 对超大代码无 chunk 上限（大包 LLM 成本爆炸）→ MAX_AUDIT_CHUNKS=12 封顶 + partial 标记 + 轮 1 总览不再只看第一块。**健壮性**：(4) scanner child stdin EPIPE/启动失败无兜底会崩宿主（补 stdin error handler + try/catch + finish 防重复 resolve）；(5) scanSync 无 try/catch（maxBuffer 超限会抛，deny 同步路径无保护）；(6) T1 哨兵死后只打日志不重拉、盾牌无感知 → 重拉上限 5 次 + 5s 退避 + sentinel-down 黄灯报警；(7) toggle 空 body/缺 enable 字段默认当"关闭"→ 可能误关守卫（改 400 拒绝，显式布尔）；(8) 蜜罐 enabled 但 guard 非 watch 时静默不生效 → 启动告警；(9) toggle body 无大小上限 → 8KB 封顶。**验证过的无问题项**：run_code runtime='host'（worker AsyncFunction realm，process 真实可达）与 cordis_run 'sandbox'（vm 沙箱 process undefined）映射正确；i18n zh/en 77 键齐；explainScore/computeScore 权重一致 | 逐层源码审计；真实 dsh profile 解析复现（修复前 undefined → 修复后命中）；runtime 规则验证；174 tests 全绿 |

## 14. 未来路线（v1.1 后，未排期）

### 14.1 静态→LLM 复核衔接（设计约束，已确认）

1. 流水线不变：静态扫描（verdict 权威）→ critical 短路（不调 LLM）→ 非 critical 走 4 轮 LLM 审计（轮 1 总览含静态摘要 → 轮 2 敏感点 LLM **独立**找 secret/exfiltration/telemetry/obfuscation/dangerous-api/other → 轮 3 质量 → 轮 4 汇总含静态报告，LLM 不得修改/软化/重贴 verdict）。
2. **R9 约束**：资源安全类规则默认 high/medium，**不升级 critical**——critical 会短路 LLM，而资源类问题（如 `while(true)`）需要 LLM 复核上下文（合法常驻服务循环），短路会丢失语义判断。
3. 新增规则族的 findings 自动并入轮 1 静态摘要与轮 4 静态报告，由 LLM 复核。

### 14.2 规则扩展路线（按优先级）

| 阶段 | 内容 | 检测面 | 判定档 |
|---|---|---|---|
| R9-1 | 资源安全：无界分配字面量（`new Array(2**31)`/`Buffer.alloc(huge)`）、无出口同步循环、无界 spawn（fork 炸弹） | AST 数字字面量求值 + 控制流 | high/medium |
| R9-2 | ReDoS 嵌套量词正则、递归无终止粗检 | 正则 AST | medium |
| R9-3 | 循环内字符串 `+=`、无界 Map 增长、Promise.all 无界并发 | 结构启发式 | info/medium |
| R10 | 供应链：`package.json` scripts/install 钩子、依赖清单、已知漏洞（数据源选型） | 包元数据 | high（install 钩子）/ info |
| R11 | 破坏性行为：fs 删除 / 敏感路径写入模式 | 调用模式 | high（需降噪） |

### 14.3 AST 引擎评估（malong-parse，详见 D15）

- **能力**：Rust tree-sitter 9 语言（js/ts/python/go/rust/c/cpp/java/bash）符号/引用/指标提取；Unix socket JSON 帧服务（parser pool、tree cache、source cache、并发信号量、动态超时预算、认证 token、health）；MIT；已具备 npm 4 平台二进制发布机制（parse-bin.js）。
- **vet 现状**：TS compiler API（语义 AST），78 测试绿；短板是大包扫描超时（R8 info）。
- **方案**：
  - **A（实测后暂缓，D17）两级扫描**：Rust tree-sitter 预筛。实测 600 文件 parse+全部规则仅 180ms、R8 预算 files×2s 实际不触发 → 预筛收益≈0，取消引入；远期优化方向改为 scanner daemon 常驻（省 spawn 固定开销，保持子进程物理隔离）。
  - B（远期）规则引擎整体 Rust 化：需重写 R1-R9 + 自实现词法作用域/静态求值，双引擎一致性风险。
  - C（audit 增强）接入 `extract_symbols`/`extract_references` 作 LLM 代码地图输入。
  - D（不引入）维持现状，R8 边界已在能力清单诚实记录。
- **前置条件**：tree-sitter 是 CST（无类型/绑定信息），预筛层只能做语法级模式匹配；遮蔽分析、字符串静态求值、R5 的变量身份判断保留在 TS 精扫层。

### 14.4 运行时配合（上游建议，vet 不实现）

动态插件跑主进程 `node:vm` 无堆上限（vm 无 resourceLimits），分配炸弹可拖垮整个 harness。vet 侧：R9-1 静态标记 + deny 模式拦截明确模式；真隔离（插件跑进有堆上限的 worker/子进程）是 DSH 上游 cordis-host-runner 改造，记录为建议项。

### 14.5 运行时监控（D22：T1 哨兵 + T2 进程内钩子 + 盾牌状态灯）

**定位**：alarm-only。任何一层只报警给建议，不自动拦截/杀进程/卸载（§2.1 D21）。

| 层 | 机制 | 能抓 | 代价/局限 |
|---|---|---|---|
| T1 哨兵 | 子进程每 intervalMs 读 /proc/<宿主pid>：VmRSS、task children 数、fd 数；窗口内 RSS 净增长按倍数报警（泄漏） | 内存炸弹、**内存持续膨胀（疑似泄漏）**、fork 炸弹、fd 激增 | 10-30MB + 轮询 CPU；粒度=宿主全局（插件共用进程，无法归因） |
| T2 钩子 | 进程内包装 fs/child_process 导出；危险操作取栈→根目录→插件包名（best-effort 归因） | 敏感路径写入/删除（/etc、~/.ssh、.env…）、第三方 spawn、读密钥文件 | 每次调用包装开销（I/O 密集 <5%，热点 10-20% 级）；旁路：ESM 具名导入快照、worker_threads 独立 realm、原生插件、process.binding |
| 盾牌 | webServer /vet/status.json + 浏览器 5s 轮询；注册进 conversation.session.header.actions | 用户可见绿/黄/红灯 + 报警计数 | 需要 dsh web 重启激活；client 半区不能编译期依赖私有 @deepseek-ai/dsh-client-*（本地最小类型 + esbuild 打包 react） |

**已知边界（README 同步）**：T1/T2 是"防盗摄像头"不是"保险柜"——抓明显搞事，抓不了 worker/原生模块/低流量慢外联；T2 对官方包 spawn 降噪（官方能力授权）；网络行为监控（http/net 包装）v1 不做（宿主自身流量噪声大），列远期。

### 14.6 数据源与反混淆

1. **R10 CVE 匹配（已实现，D23）**：**OSV.dev**（免费、无 key、覆盖 npm）。实现 = package.json name → OSV 查询（注入式 fetch、4s 超时）→ 命中追加 high/certain finding（封顶 5 条）→ **进 verdict 抬升 suspicious**（D23 决策修正：用户要"最新防护"，CVE 是真实事实非启发式；名称级查询噪音用 5 条封顶缓解）。缓存策略：静态报告（含缓存）与 OSV 分离，OSV 每次实时查询保持数据新鲜（"自动更新"）。配置 osvCheck 默认 true（可关；离线自动降级纯静态；依赖清单出网属隐私边界，README 已注明）。NVD（要 key）/GitHub Advisory 备选。
2. **轻量反混淆（现在能做，确定性）**：扩展 stringyValue 为纯 AST 常量求值器（字面量拼接 + String.fromCharCode 链 + base64 字面量解码 + 简单 XOR），修 D14 记录的 base64 混淆漏检；**绝不 eval**（保住扫描器物理隔离）。重量级反混淆（控制流平坦化等）不做（军备竞赛）。
3. **scanner daemon 常驻**（D17 远期）：省 spawn 固定开销，保持子进程隔离。

