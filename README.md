# @jieai/dsh-plugin-vet — DSH 插件信任流水线

[![npm version](https://img.shields.io/npm/v/@jieai/dsh-plugin-vet)](https://www.npmjs.com/package/@jieai/dsh-plugin-vet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D22.19-339933)](package.json)

> 安装任何插件前，先让 dsh-plugin-vet 走一遍：静态规则给出 verdict（确定性、不可伪造），
> agent 按 vet-audit-protocol 技能排查敏感点与质量问题（谁也无法替代），最终一张评分卡交给人/模型决定。
>
> **定位：监控报警器，不是打手。** vet 只做「检查 → 报警 → 给建议」：写时查（静态扫描）、
> 跑时盯（运行时守卫）、报警面（评分卡 + GUI 盾牌状态灯）。**vet 永不替用户动手**——不自动卸载、
> 不自动杀进程、不自动改配置；deny 模式是部署者显式开启的 opt-in，不构成产品身份。最终怎么处置，
> 由用户在自己的 DSH 上操作决定。

@jieai/dsh-plugin-vet 是 deepseek-harness 生态的**信任层插件**：占据
**下载 → 扫描 → 审计 → 评分 → 决定 → 运行时盯梢** 这一整套信任流水线。运行时盯梢内置**蜜罐诱饵**：谁偷偷翻找密钥文件，当场现形（opt-in，`honeypot.enabled`）。**不做**插件市场本体（目录/分发）。

- 📚 架构设计：[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 🧾 审查协议：[AUDIT_PROTOCOL.md](AUDIT_PROTOCOL.md)
- 🛡️ 安全政策：[SECURITY.md](SECURITY.md)
- 🤝 贡献指南：[CONTRIBUTING.md](CONTRIBUTING.md)

---

## 安装

```sh
dsh plugin --profile <profile> add @jieai/dsh-plugin-vet
```

安装即生效链路：pnpm 安装 → `reconcilePlugins` 读 `dsh.bundle` → 下次启动 `loadProfile`
解析 bundle 挂载插件。默认配置见下方 Config（fail-open：只报告不拦截）。

**本地 tarball 安装**（离线/先验证再发版场景）：

```sh
dsh plugin --profile <profile> add ./jieai-dsh-plugin-vet-0.1.0.tgz
# 或直接解包到 profile 的 node_modules：
# tar -xzf jieai-dsh-plugin-vet-0.1.0.tgz -C ~/.dsh/profiles/<profile>/node_modules/@jieai/
// 并在 profile 的 cordis.patch.yml 里 insert 挂载条目：
//   - insert:
//       - id: plugin-vet
//         name: '@jieai/dsh-plugin-vet'
//         config:
//           mode: report
//           autoScan: true
```

> 路径/相对路径/URL 均可（`dsh plugin add` 走 pnpm 的 `file:` 协议兜底，本地 tgz 直接解析）。
>
> **首次安装耗时提示**：`dsh plugin add` 首次安装到大型 profile 可能耗时数分钟——
> 期间 pnpm 会做全量依赖解析、更新 500+ 包的 lockfile 并对整棵依赖树做供应链策略校验
> （vet 自身只带 2 个运行时依赖，耗时大头是 profile 已有依赖树的解析/校验，不是 vet）。
> 校验完成后再次安装/更新只需秒级（复用校验结果）。


> **兼容性**：vet 面向 DSH 0.1.0-rc.6+（peer 范围 `^0.1.0-rc.6`）。安装时 pnpm 可能提示
> unmet peer dependency——这是预期的：profile 模板 `autoInstallPeers: false`，运行期从 DSH 安装闭包
> （`$DSH_HOME/profiles/node_modules` 回退层）解析，无需也不能在 profile 里另装一份 cordis 全家桶。

> **监控范围 = 安装 vet 的 profile。** vet 的守卫是进程内事件（`internal/plugin`）——
> vet 装进哪个 profile，就只守那个 profile 实例加载的插件。多 profile 部署时，
> 每个要守的 profile 都要装一份 vet（`dsh plugin --profile <name> add @jieai/dsh-plugin-vet`），
> 并把 requireAudit 配到对应 profile 的 cordis.patch.yml。

## Config（cordis.yml）

| 键 | 默认 | 说明 |
|---|---|---|
| `mode` | `report` | `report` 只报告不拦截；`deny` 显式开启拦截 |
| `autoScan` | `true` | 新插件（`internal/plugin`）自动静态扫描 |
| `scannerTimeoutMs` | `15000` | 静态扫描子进程超时 |
| `requireAudit` | `false` | 审计门槛（opt-in）：开启后新插件加载时检查 `~/.dsh/vet/audits/` 健康档案——无档案则 `report` 模式记录黄色 `audit-required` 告警、`deny` 模式拦截。档案由 agent 按 `vet-audit-protocol` 技能审查后手写落盘 |
| `rules` | `{}`（全开） | 规则开关（R1-R12） |
| `denyOn` | `critical` | `mode: deny` 时的拦截阈值 |
| `allowlist` | `[]` | 包名/插件 id 白名单（跳过扫描） |
| `runtimeGuard` | `off` | 运行时守卫（性能/稳定代价 opt-in）：`off` 关；`watch` 启用 T1 哨兵 + T2 钩子，**只报警不动作** |
| `runtimeIntervalMs` | `2000` | T1 哨兵 /proc 采样间隔 |
| `runtimeMemLimitMb` | `2048` | T1 内存报警阈值（宿主 VmRSS，超限 → red） |
| `runtimeForkBurstN` | `5` | T1 子进程突增报警阈值（单轮增量，→ red） |
| `runtimeFdLimit` | `512` | T1 文件描述符报警阈值（→ yellow） |
| `runtimeGrowthMb` | `256` | T1 内存持续膨胀报警阈值（**完整窗口**内 RSS 净增长，→ yellow 疑似泄漏；起窗初期的瞬时尖峰不构成窗口级持续膨胀，不会误报） |
| `runtimeGrowthWindowMs` | `600000` | 膨胀检测窗口（默认 10 分钟） |
| `honeypot.enabled` | `false` | 蜜罐诱饵（需 `runtimeGuard: watch`）：往 `honeypot.dir` 放假密钥诱饵，T2 对诱饵路径的触碰（读/写/删）单独报 `honeypot` 类报警。目录/文件名/内容均无蜜罐关键词（反蜜罐），默认位置 `~/.dsh/.local`，诱饵值全是格式正确但无效的假凭据 |
| `honeypot.dir` | `''` | 诱饵目录；空 = `$HOME/.dsh/.local` |
| `osvCheck` | `true` | 扫描 package.json 时向 Google OSV 查询已知漏洞（**仅精确版本**查询：range（*、>=、^）与无 version 的主包跳过，P3-1/P3-3——避免陈旧全量历史误报）；核对面 = 插件自身 + 直接依赖（上限 8 个，`@deepseek-ai/*` 官方包跳过，P3-10）；间接传递树超出 OSV v1 范围与扫描预算。默认开启会外发包名到 api.osv.dev，网络失败静默降级。介意隐私可设 false |

`@deepseek-ai/*` 官方包默认豁免（内置信任）。

## 工具

- **`scan_plugin`** — 确定性静态扫描：`target` = `dynamic-code`（源码字符串）/ `package`（包目录）/ `file`（单文件）。返回评分卡（verdict + staticScore + findings）。verdict 只由静态规则产出。
- **`vet-audit-protocol`（技能）** — 审查流程协议（`AUDIT_PROTOCOL.md`）：agent 按预设步骤审查新插件——scan_plugin 静态判据（含 R12 Cordis/DSH 契约）→ 读清单/源码 → 逐条核实发现 → 主动深挖（网络/文件/进程/凭据/库语义）→ **契约与代码质量审计**（4.5 步：入口/Config schema 一致性、错误处理/同步阻塞/资源泄漏/异步正确性等「写得烂」问题——静态干净≠值得装）→ 用系统写入能力手写健康档案到 `~/.dsh/vet/audits/<plugin>-<version>-<ts>.md`。vet 不内置审计工具、不替 agent 调查，只给判据与落盘约定。

## 自动行为

- **`internal/plugin` 自动扫描**（`autoScan: true`）：新装第三方 npm 包加载时自动静态扫描；`deny` 模式 + verdict ≥ `denyOn` → 回滚加载。
- **审计门槛**（`requireAudit: true`）：无健康档案的第三方插件加载时——`report` 模式记录黄色 `audit-required` 告警（进 /vet/status.json 告警列表，插件照常加载）；`deny` 模式回滚加载（引用 `vet-audit-protocol` 提示先审查）。**档案按版本精确匹配**（P-1）：插件升级后旧版本档案不放行新版本——重新审查才能消除告警/拦截。
- **`tools/execute` 拦截**：`cordis_define` / `run_code` / `workflow` 执行前扫描代码字符串（`cordis_run` 的真实 schema 无 code 载荷，保留守卫位不生效，P3-11 同步）；`report` 模式仅在非 clean 结果时加 `VET:` 前缀（干净执行不污染机器可读输出），`deny` 模式直接拦截（isError）。
- **运行时守卫（`runtimeGuard: watch`）**——alarm-only：
  - **T1 哨兵**：旁路子进程每 `runtimeIntervalMs` 读宿主 /proc（VmRSS / 子进程数 / fd 数），报警 JSON 行回传宿主 → 盾牌变黄/红。
  - **T2 钩子**：进程内包装 fs / child_process（含 fs.promises），危险操作（敏感路径写入/删除、读密钥文件、含 shell/下载外联关键词的子进程、蜜罐诱饵触碰、`~/.dsh` 配置根侦察）取栈归因到插件包名后报警；官方包归因全类降噪（能力授权——官方包是平台本体，高频读写 `~/.dsh` 会话/配置/存储不刷屏；第三方无法伪造归因）。**从不阻断调用**。自伤豁免（实测误报后修复）：
    - **node_modules 包目录豁免**：包名/包内文件是公开工件——含 credential/secret 等词的包名是正常生态（`@aws-sdk/credential-provider-*`、`@deepseek-ai/dsh-credentials-local` 等），宿主模块解析（require.resolve 内部 realpathSync/stat 包内 package.json）与 vet 扫描读取都会高频触碰，不再误报 fs-probe；node_modules 之前的段照常判定（`~/.ssh/node_modules/x` 仍命中 .ssh），写删系统根（/usr 等）仍报警。
    - **归因排除 vet 自身**：包装器帧永远是报警栈栈顶，vet 根不参与归因映射——宿主/无主报警不再栽到 vet 头上（报警照发，归因到真实调用方）。
    - 工具链临时产物（tsc `<源名>.<pid>.<uuid>.tmpdir`、`*.tmp`、`*.temp`、`*.swp` 等）自动豁免——名字里的 secrets/credentials 只是被编译的源文件名，删它是清理不是破坏；父段照常判定（`~/.ssh/config.bak` 仍报警）。
- **GUI 盾牌**：浏览器半区注册进 `conversation.session.header.actions`，轮询 /vet/status.json 显示绿/黄/红灯 + 报警计数。激活需 `dsh web` 重启（重启后 client-modules 才扫描到 `dsh.client` 声明）。
  - 交互：**可点击**——点击展开报警面板（**实时指标**：内存/CPU/I-O/子进程/fd；**守卫状态**：未开启时可一键写入 runtimeGuard: watch 配置（重启生效）；**报警列表**含严重度/归因/**逐条建议**；最近扫描回显、刷新、更新时刻），外部点击自动关闭；有报警时盾牌旁显示计数徽标（绿/黄/红主题色，明暗自适应）。
  - **单条忽略**：每条报警可点「忽略」——只影响展示（不再计入盾牌等级与计数），记录保留可随时「恢复」；报警停止后忽略自动失效，将来复发会重新可见（可再忽略）。忽略状态与报警存储同生命周期（重启即重置）。鉴权边界（P3-12 记录）：dismiss/restore 仅做同源校验（alarm-only 展示层风险——同源页面脚本可隐藏报警，但记录不删、不影响其他能力，体系内可接受）。
  - **展示上限**：面板展示最近 8 条报警；存储为环形缓冲上限 20 条，同 id 60 秒内去重，24 小时 TTL 过期（持续触发会自然续期）——100 条不会全量展示，也无需展示（新报警会顶掉最旧的）。最近扫描回显（suspicious → 黄灯）同样按 24h TTL 过期（P3-2：一次可疑扫描不再永久黄，持续扫描自然续期）。

## 静态规则表（R1-R12）

| ID | 名称 | 默认级别 | 适用场景 | 确定性 |
|---|---|---|---|---|
| R1 | constructor 链逃逸 | critical | code + files | certain/likely |
| R2 | 动态执行（eval/Function/import/require） | high（files）/ medium（code） | both | certain/likely |
| R3 | process 直接访问（按 runtime 分级） | critical（host）/ high（sandbox） | both | certain |
| R4 | 宿主闭包捕获（agent/TextEncoder…） | critical | code | certain |
| R5 | ctx 逃逸尝试信号（withheld 成员/未声明服务；`ctx.logger` 等官方注入服务白名单放行） | medium | 仅 code | likely |
| R6 | 字符串粗扫兜底 | info | both | heuristic |
| R7 | 硬编码密钥 | high | both | likely |
| R9 | 资源安全（无界分配/无出口同步循环/循环内 spawn/ReDoS/递归无终止/循环内增长模式） | high（分配/死循环/fork）/ medium（ReDoS/递归/Map.set）/ info（常驻循环/+=/Promise.all） | both | certain/likely/heuristic |
| R10 | 供应链（package.json install 钩子/依赖清单） | high（install 钩子）/ info（依赖清单） | files | likely/heuristic |
| R11 | 破坏性文件操作（fs 删除/敏感路径读写） | high（敏感路径）/ medium（删除） | both | likely |
| R12 | Cordis/DSH 契约（入口文件/bundle patch 声明/name/engines.node） | high（patch 缺失/入口缺失）/ medium（无入口/缺 name）/ info（node 版本低） | files | certain/likely |

## 评分模型

`staticScore = max(0, 100 - Σ(severity 权重 × 命中数 × confidence 系数))`

verdict（唯一权威判定，heuristic 永不升级）：critical ≥ 1 → `critical`；否则 high ≥ 1 → `suspicious`；其余 → `clean`。**verdict 只由静态层产出**：staticScore 与 verdict 分开呈现，不合成单一总分。

## 能力边界（诚实清单）

> 静态扫描是"减速带 + 取证层"，不是安全边界。以下按**判定影响**分两档，
> 并如实列出**明确不检测**的形态（均已实测验证）。

### 能检测 —— 判定级（会改变 verdict）

| 规则 | 检测的问题类 | 命中 → verdict | 验证 |
|---|---|---|---|
| R1 | 构造器链逃逸：`x.constructor("return process")` / `x["constructor"]("return " + "process")`（点访问与元素访问双形态；字符串参数静态可求值：字面量/模板/拼接/const 绑定） | critical | 矩阵 + 多文件 ✓ |
| R2 | 动态执行：`eval()` / `Function()` / `new Function`/\`new AsyncFunction\`（参数含逃逸串 → critical）/ `(async)=>{}.constructor` 捕获 / `vm.runInContext`/\`runInNewContext\` / 动态 `import()` / `require()` | high（files）/ medium（code，逃逸串 critical） | 矩阵 ✓ |
| R3 | process 直访：`getBuiltinModule`/\`mainModule\`/\`module\`/\`exit\` → critical；其余成员 → high；`runtime='sandbox'` 封顶 high | critical / high | 矩阵 ✓ |
| R4 | 宿主闭包捕获：agent/parallel/pipeline/phase/log/TextEncoder/TextDecoder/btoa/atob 的 `.constructor` 读取或 `Object.getPrototypeOf` 投喂 | critical | 矩阵 ✓ |
| R7 | 硬编码密钥：`sk-` / `AKIA` / `AIza` / `gh[pousr]_` / `xox[baprs]-` / 环境变量赋值 / URL 内嵌 key（占位符排除） | high → suspicious | 矩阵 ✓ |
| R9 | 资源安全：`new Array(2**31)` / `Buffer.alloc(1GB)` 无界分配（≥1e8）、`while(true)`/`for(;;)` 无出口**同步**循环（卡死宿主）、无出口循环内 `spawn`/`exec`/`fork`/`new Worker`（fork 炸弹） | high → suspicious；ReDoS 嵌套量词 `(a+)+$`、递归无终止、循环内 `Map.set` → medium（不进 verdict）；含 `await` 常驻循环仅 info（§14.1 不短路审查） | 矩阵 ✓ |
| R10 | 供应链：`package.json` scripts 的 preinstall/install/postinstall/uninstall 钩子（安装期任意代码执行）→ high；依赖清单 → info（已知漏洞核对：OSV 精确版本查询，osvCheck 可关） | high → suspicious（install 钩子） | 矩阵 ✓ |
| R11 | 破坏性文件操作：`fs.unlink/rm/rmdir(+Sync)` 删除敏感路径（/etc/root/.ssh 等）→ high，普通删除 → medium；`fs.writeFile` 等写入敏感路径 → high；`fs.readdir` 遍历敏感目录 → medium | high → suspicious（敏感路径）；medium 不进 verdict | 矩阵 ✓ |
| R12 | Cordis/DSH 契约：`dsh.bundle.patch` 声明的文件缺失 → high；无 入口（无 main/exports["."] 且根无 index.js）→ medium；声明的入口文件缺失 → high；插件意图包缺 name → medium；`engines.node` 主版本低于 22 → info | high → suspicious（声明即挂载点/入口，缺失必失败）；medium/info 不进 verdict | 矩阵 ✓ |

### 能检测 —— 提示级（只降分，永不改变 verdict）

| 规则 | 检测的问题类 | 说明 |
|---|---|---|
| R5 | ctx 逃逸尝试信号：访问沙箱 withheld 框架成员/未声明服务（`ctx.plugin` 等） | 仅 code 场景；medium |
| R6 | 字符串粗扫：拼接逃逸特征、`getBuiltinModule`/\`child_process\`/危险 require 模块引用、混淆特征（`String.fromCharCode`/\`Buffer.from(base64)\`/\`atob(\`/\`charCodeAt\`） | info/heuristic |
| R8 | 扫描超时/文件过大跳过 | info 元规则 |

### 运行时监控（`runtimeGuard: watch` 时启用）——只报警

| 层 | 机制 | 能抓 | 局限 |
|---|---|---|---|
| T1 哨兵 | 子进程轮询宿主 /proc | 内存炸弹（>memLimit）、**内存持续膨胀（泄漏，窗口净增长按倍数报警）**、fork 炸弹（子进程突增）、fd 激增 | 粒度=宿主全局（插件共用进程，无法归因到插件） |
| T2 钩子 | 进程内包装 fs/child_process（含 fs.promises） | 敏感路径写入/删除（/etc、~/.ssh、.env…）、读密钥文件、含 shell/下载外联关键词的 spawn | 栈归因 best-effort；每次调用包装开销（I/O 密集 <5%，热点 10-20% 级） |
| 盾牌 | 浏览器 `conversation.session.header.actions` + /vet/status.json | 绿/黄/红灯 + 报警计数 | 需 `dsh web` 重启激活 |

### 明确不检测（实测验证）

| 形态 | 实测结果 |
|---|---|
| 间接引用：别名函数 `const f = Function; f(...)`、`process["getBuiltinModule"]`、`globalThis.process`、间接 eval `(0, eval)` | 仅 R6 info 或零 finding，verdict=clean |
| 运行时/外部构造载荷：base64 串、hex/charCode 拼装、网络/环境变量/参数读码、自修改代码 | base64 构造器串实测**零 finding** |
| 非源码文件：`.jsx`/\`.tsx\`/\`.vue\`/\`.json\`/二进制/wasm/shell 脚本 | 不在扫描面（仅 .js/.ts/.mjs/.cjs） |
| 依赖链/供应链：import/require 图、依赖版本漏洞、`package.json` scripts/install 钩子、许可证、作者信誉 | 不解析 |
| 运行时行为：网络外传、原型污染、死循环/资源耗尽、时序、权限滥用 | 无数据流/行为分析 |
| 语义知识：插件实际注入的服务、bundler polyfill 中的 `process`、遮蔽判定边界 | R5 只认 4 个变量名；遮蔽检查是 v1 启发式（偏少报） |
| 宿主工具包的合法 `process` 使用（`process.env` 读配置、`process.stdin/stdout` 协议、`process.execPath` spawn） | 已解决：targetKind 分级——非 DSH 插件包/官方包（generic）下 R3/R2/R10/R9 死循环降级为能力触达面/提示（info/medium），不进 verdict；DSH 插件包保持严格。实测 195 官方包全 clean |

## 信任边界

1. **verdict 只由确定性静态层产出**——规则是正则/AST 判定，不可被提示注入欺骗。
2. **静态层与插件代码物理隔离**——scanner 是独立进程，AST 只读、从不 eval。
3. **审查走 agent 协议**——agent 按 vet-audit-protocol 技能步骤复核（静态判据先行，敏感点逐条深挖），verdict 不受审查环节影响。
4. **不合成单一总分**——禁止把 verdict 与主观评估合并，防止污染 verdict 边界。
5. **本产品不是安全边界**——定位是"减速带+取证层"（具体可绕过形态见下方 Known Limitations 1，与 DSH 官方立场对齐）。
6. **fail-open 起步**——默认 `mode: report`，`deny` 由部署者显式开启。
7. **alarm-only**——运行时守卫只 watch 不 kill；vet 的自动行为（deny 拦截）仅存在于部署者显式开启的 opt-in 模式。报警只附建议，处置永远留给用户在 DSH 上操作。

## Known Limitations

1. **静态扫描不是安全边界**：混淆/编码/动态生成代码可绕过 AST 规则；R6 只提供"疑似"信号。
1b. **源码枚举限制**：internal/plugin 自动扫描只递归收集 ≤6 层深、非隐藏（非 `.` 开头）的 .js/.ts/.mjs/.cjs 文件——深层或隐藏目录里的源码静默不扫（无提示）；需要全量时可手动用 scan_plugin(target=package) 扫整个目录。
2. **agent 审查可被提示注入**：verdict 永不来自审查环节，但 agent 可能漏报——置信度字段让用户知晓。
3. **`internal/plugin` 守卫不覆盖运行时动态挂载逃逸**：vm 路径由 `tools/execute` 守卫在调用层拦截。
4. **R5 仅 code 场景**：files 场景的 ctx 访问默认不报（误报率高）。
5. **扫描耗时**：大插件包可能超时跳过（R8 info）；agent 审查按 vet-audit-protocol 步骤进行。
6. **verdict 是静态层确定性判定**；agent 的主观判断记录在健康档案里，不构成安全保证。
7. **/vet/status.json 无鉴权**：盾牌轮询需要匿名 GET，路由本身不鉴权——若 dsh web 绑定非回环地址，局域网内可读扫描结论/报警目标。vet 是 alarm-only 观测器，不做越权的访问控制；介意就保持回环绑定或信任网络（POST 开关守卫已有同源校验，无 Origin 拒绝）。
8. **`@deepseek-ai/*` 默认信任**：未来若官方生态被攻破需收紧（v1 留开关）。
9. **R10 已知漏洞核对依赖 OSV 网络查询**：默认开启会把「包名+精确版本」发到 api.osv.dev（README 配置节有披露，介意可设 `osvCheck: false`）；网络失败/超时静默降级为跳过（不误拦）；仅对精确版本查询——`*`/`>=`/`^` 区间与无版本主包跳过（P3-1/P3-3），间接传递依赖不在核对面。
10. **R11 只认 `fs.*` 形态**：解构/别名调用（`const { unlinkSync } = require('fs')`）与运行时路径漏检（已实测记录，属静态边界）。
11. **T1/T2 是"防盗摄像头"不是"保险柜"**：抓明显搞事（内存/fork 炸弹、敏感路径操作、第三方 spawn），抓不了 worker 线程/原生插件/低流量慢外联；T2 对 ESM 具名导入快照、`process.binding` 等旁路不覆盖。
12. **T2 归因与降噪**：栈归因是 best-effort（共享服务/定时器跨插件会误归因）；官方包 spawn 默认不报警（能力授权）。
13. **盾牌激活需要 `dsh web` 重启**：client-modules 在启动时扫描 `dsh.client` 声明；重启前浏览器不会加载盾牌，但 /vet/status.json 端点与运行时守卫（宿主侧）重启即生效。
14. **运行时守卫默认关闭**（`runtimeGuard: 'off'`）：包装 fs/child_process 有性能与稳定代价，opt-in 开启。

## 开发

```sh
npm run build       # scanner-bin + src 编译到 lib/ + client bundle
npm run typecheck   # tsc --noEmit 全量
npm test            # 构建 + vitest（218 用例，含覆盖率阈值）
npx vitest run --coverage   # 覆盖率报告（lines/functions >= 70%，branches >= 50%）
```

目录：`scanner-bin/` 静态引擎（独立进程）；`src/` 插件本体（tools/guards/audit/report/guard）；
`src/client/` GUI 盾牌；`test/` fixtures + 单测 + 对抗矩阵。架构见 `docs/ARCHITECTURE.md`。

## 许可证

[MIT](LICENSE)。