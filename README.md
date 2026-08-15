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
| `rules` | `{}`（全开） | 规则开关（R1-R7、R9-R11） |
| `denyOn` | `critical` | `mode: deny` 时的拦截阈值 |
| `allowlist` | `[]` | 包名/插件 id 白名单（跳过扫描） |

`@deepseek-ai/*` 官方包默认豁免（内置信任）。

## 工具

- **`scan_plugin`** — 确定性静态扫描：`target` = `dynamic-code`（源码字符串）/ `package`（包目录）/ `file`（单文件）。返回评分卡（verdict + staticScore + findings）。verdict 只由静态规则产出。
- **`audit_plugin`** — 深度审计：先静态扫描；**verdict=critical 直接短路**（不调 LLM）；否则按 `deep`（默认 true）跑 4 轮 LLM 审计（总览 → 敏感点 → 质量 → 汇总），或只跑轮 1+2（`deep: false`）。LLM 输出永远是建议/注释/质量分，绝不参与 verdict。

## 自动行为

- **`internal/plugin` 自动扫描**（`autoScan: true`）：新装第三方 npm 包加载时自动静态扫描；`deny` 模式 + verdict ≥ `denyOn` → 回滚加载。
- **`tools/execute` 拦截**：`cordis_define` / `cordis_run` / `run_code` / `workflow` 执行前扫描代码字符串；`report` 模式在结果文本加 `VET:` 前缀，`deny` 模式直接拦截（isError）。

## 静态规则表（R1-R11）

| ID | 名称 | 默认级别 | 适用场景 | 确定性 |
|---|---|---|---|---|
| R1 | constructor 链逃逸 | critical | code + files | certain/likely |
| R2 | 动态执行（eval/Function/import/require） | high（files）/ medium（code） | both | certain/likely |
| R3 | process 直接访问（按 runtime 分级） | critical（host）/ high（sandbox） | both | certain |
| R4 | 宿主闭包捕获（agent/TextEncoder…） | critical | code | certain |
| R5 | ctx 逃逸尝试信号（withheld 成员/未声明服务） | medium | 仅 code | likely |
| R6 | 字符串粗扫兜底 | info | both | heuristic |
| R7 | 硬编码密钥 | high | both | likely |
| R9 | 资源安全（无界分配/无出口同步循环/循环内 spawn/ReDoS/递归无终止/循环内增长模式） | high（分配/死循环/fork）/ medium（ReDoS/递归/Map.set）/ info（常驻循环/+=/Promise.all） | both | certain/likely/heuristic |
| R10 | 供应链（package.json install 钩子/依赖清单） | high（install 钩子）/ info（依赖清单） | files | likely/heuristic |
| R11 | 破坏性文件操作（fs 删除/敏感路径读写） | high（敏感路径）/ medium（删除） | both | likely |

## 评分模型

`staticScore = max(0, 100 - Σ(severity 权重 × 命中数 × confidence 系数))`

verdict（唯一权威判定，heuristic 永不升级）：critical ≥ 1 → `critical`；否则 high ≥ 1 → `suspicious`；其余 → `clean`。**两分制不合并**：staticScore（确定性）与 qualityScore（LLM 主观）分开呈现。

## 能力边界（诚实清单）

> 静态扫描是"减速带 + 取证层"，不是安全边界。以下按**判定影响**分两档，
> 并如实列出**明确不检测**的形态（均已实测验证）。

### 能检测 —— 判定级（会改变 verdict）

| 规则 | 检测的问题类 | 命中 → verdict | 验证 |
|---|---|---|---|
| R1 | 构造器链逃逸：`x.constructor("return process")`（字符串参数静态可求值：字面量/模板/拼接/const 绑定） | critical | 矩阵 + 多文件 ✓ |
| R2 | 动态执行：`eval()` / `Function()` / `new Function`/\`new AsyncFunction\`（参数含逃逸串 → critical）/ `(async)=>{}.constructor` 捕获 / `vm.runInContext`/\`runInNewContext\` / 动态 `import()` / `require()` | high（files）/ medium（code，逃逸串 critical） | 矩阵 ✓ |
| R3 | process 直访：`getBuiltinModule`/\`mainModule\`/\`module\`/\`exit\` → critical；其余成员 → high；`runtime='sandbox'` 封顶 high | critical / high | 矩阵 ✓ |
| R4 | 宿主闭包捕获：agent/parallel/pipeline/phase/log/TextEncoder/TextDecoder/btoa/atob 的 `.constructor` 读取或 `Object.getPrototypeOf` 投喂 | critical | 矩阵 ✓ |
| R7 | 硬编码密钥：`sk-` / `AKIA` / `AIza` / `gh[pousr]_` / `xox[baprs]-` / 环境变量赋值 / URL 内嵌 key（占位符排除） | high → suspicious | 矩阵 ✓ |
| R9 | 资源安全：`new Array(2**31)` / `Buffer.alloc(1GB)` 无界分配（≥1e8）、`while(true)`/`for(;;)` 无出口**同步**循环（卡死宿主）、无出口循环内 `spawn`/`exec`/`fork`/`new Worker`（fork 炸弹） | high → suspicious；ReDoS 嵌套量词 `(a+)+$`、递归无终止、循环内 `Map.set` → medium（不进 verdict）；含 `await` 常驻循环仅 info（§14.1 不短路 LLM） | 矩阵 ✓ |
| R10 | 供应链：`package.json` scripts 的 preinstall/install/postinstall/uninstall 钩子（安装期任意代码执行）→ high；依赖清单 → info（已知漏洞匹配待数据源选型） | high → suspicious（install 钩子） | 矩阵 ✓ |
| R11 | 破坏性文件操作：`fs.unlink/rm/rmdir(+Sync)` 删除敏感路径（/etc/root/.ssh 等）→ high，普通删除 → medium；`fs.writeFile` 等写入敏感路径 → high；`fs.readdir` 遍历敏感目录 → medium | high → suspicious（敏感路径）；medium 不进 verdict | 矩阵 ✓ |

### 能检测 —— 提示级（只降分，永不改变 verdict）

| 规则 | 检测的问题类 | 说明 |
|---|---|---|
| R5 | ctx 逃逸尝试信号：访问沙箱 withheld 框架成员/未声明服务（`ctx.plugin` 等） | 仅 code 场景；medium |
| R6 | 字符串粗扫：拼接逃逸特征、`getBuiltinModule`/\`child_process\`/危险 require 模块引用、混淆特征（`String.fromCharCode`/\`Buffer.from(base64)\`/\`atob(\`/\`charCodeAt\`） | info/heuristic |
| R8 | 扫描超时/文件过大跳过 | info 元规则 |

### 明确不检测（实测验证）

| 形态 | 实测结果 |
|---|---|
| 间接引用：别名函数 `const f = Function; f(...)`、计算访问 `x["constructor"]` / `process["getBuiltinModule"]`、`globalThis.process`、间接 eval `(0, eval)` | 仅 R6 info 或零 finding，verdict=clean |
| 运行时/外部构造载荷：base64 串、hex/charCode 拼装、网络/环境变量/参数读码、自修改代码 | base64 构造器串实测**零 finding** |
| 非源码文件：`.jsx`/\`.tsx\`/\`.vue\`/\`.json\`/二进制/wasm/shell 脚本 | 不在扫描面（仅 .js/.ts/.mjs/.cjs） |
| 依赖链/供应链：import/require 图、依赖版本漏洞、`package.json` scripts/install 钩子、许可证、作者信誉 | 不解析 |
| 运行时行为：网络外传、原型污染、死循环/资源耗尽、时序、权限滥用 | 无数据流/行为分析 |
| 语义知识：插件实际注入的服务、bundler polyfill 中的 `process`、遮蔽判定边界 | R5 只认 4 个变量名；遮蔽检查是 v1 启发式（偏少报） |
| 宿主工具包的合法 `process` 使用（`process.env` 读配置、`process.stdin/stdout` 协议、`process.execPath` spawn） | R3 对任何包一视同仁——vet 自扫自身 scanner-bin 即报 high/suspicious（实测验证）；靠部署信任（allowlist/官方豁免）而非规则区分 |

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
8. **R10 已知漏洞匹配未做**：install 钩子与依赖清单已扫；CVE 匹配需数据源选型（OSV/NVD），待定。
9. **R11 只认 `fs.*` 形态**：解构/别名调用（`const { unlinkSync } = require('fs')`）与运行时路径漏检（已实测记录，属静态边界）。

## 开发

```sh
npm run build       # scanner-bin + src 编译到 lib/
npm run typecheck   # tsc --noEmit
npm test            # 构建 + vitest（105 用例）
```

目录：`scanner-bin/` 静态引擎（独立进程）；`src/` 插件本体（tools/guards/audit/report）；`test/` fixtures + 单测。权威计划见 `PLAN.md`（v1.1）。
