# Architecture

> 公开版架构文档（由内部开发计划提炼，2026-08）。描述当前实现，不含开发过程编号。
> 组件清单以 `src/`、`scanner-bin/` 实际代码为准。

## 1. 系统总览

`@jieai/dsh-plugin-vet`（简称 vet）是 deepseek-harness（DSH）的**信任层插件**：占据
**下载 → 扫描 → 审计 → 评分 → 决定 → 运行时盯梢**整条信任流水线。

**产品定位：监控报警器，不是打手。** vet 只做「检查 → 报警 → 给建议」：
写时查（静态扫描）、跑时盯（运行时守卫）、报警面（评分卡 + GUI 盾牌状态灯）。
vet **永不替用户动手**——不自动卸载、不自动杀进程、不自动改配置；`deny` 模式是部署者
显式开启的 opt-in，不构成产品身份。最终处置永远由用户在自己的 DSH 上决定。

```
DSH 宿主进程:
  tools/execute 守卫 ── 拦截 cordis_define/cordis_run/run_code/workflow
  internal/plugin 守卫 ── 新装第三方 npm 包自动静态扫描 + requireAudit 门槛
  T1 哨兵 ── 旁路子进程轮询宿主 /proc（内存/子进程/fd）→ JSON 报警行回传
  T2 钩子 ── 进程内包装 fs/child_process（含 fs.promises）→ 危险操作报警
  蜜罐 ── 隐蔽位置放假密钥诱饵，触碰即高置信翻找密钥信号
  webServer /vet/* ── GET status.json（盾牌轮询）、POST runtime-guard 开关
        │
        ▼  spawn 独立进程（请求-响应式，扫完即退出）
scanner-bin:
  读 stdin JSON → AST 解析（TypeScript compiler API，只读）→ 规则执行
  → 评分/verdict → 写 stdout JSON（单行）
  缓存：内容 hash + engine 版本 + 规则集 + targetKind/runtime → 报告
  OSV：package.json 有 name 时按安装版本查已知漏洞（网络失败静默降级）
```

## 2. 信任边界（最重要的设计约束）

1. **verdict 只由确定性静态层产出**。规则是正则/AST 判定，不可被提示注入欺骗。
   agent 审查的输出永远是建议/档案，绝不参与 `critical/suspicious/clean` 判定。
2. **静态层与插件代码物理隔离**。scanner 是独立子进程，AST 只读、从不 eval。
   即使宿主被逃逸代码篡改，扫描结果仍来自干净进程；扫描器崩溃不影响宿主。
3. **不合成单一总分**。`staticScore`（确定性）与 verdict 分开呈现，禁止合并
   成单一分数，防止主观判断污染 verdict 边界。
4. **fail-open 起步**。默认 `mode: report`（只报告），`deny`（拦截）由部署者显式开启。
5. **alarm-only**。运行时守卫只 watch 不 kill；vet 的自动行为（deny 拦截）只存在于
   显式开启的 opt-in 模式。

## 3. 进程模型

- **scanner-bin**：`spawn(process.execPath, [scannerBinPath], { stdio: ['pipe','pipe','pipe'] })`，
  单次调用单扫描（请求-响应式，扫完即退出）。恶意输入只影响子进程自身。
- **运行时守卫 T1 哨兵**：旁路子进程每 `runtimeIntervalMs` 读宿主 /proc
  （VmRSS / 子进程数 / fd 数 / 内存增长窗口），报警 JSON 行回传宿主。
  单例锁：env 注册表 `DSH_VET_SIDECAR_PID` + 同 PPID 兄弟扫描，配置热重载不叠加。
  意外退出自动重拉（上限 5 次 + 5s 退避），off/卸载场景不复活。
- **崩溃/超时**：scanner 子进程超时 kill，按「扫描失败」返回，绝不伪造 verdict；
  deny 模式下扫描失败 fail-closed（拦截 + 告警）。

## 4. 静态扫描引擎（scanner-bin）

### 4.1 进程协议

stdin/stdout 均为单行 JSON：

```jsonc
// request
{ "kind": "code" | "files", "code"?, "language"?, "files"?, "rules"?, "targetKind"?, "runtime"?, "osv"? }
// response
{ "ok": true, "report": { "engine", "sourceCount", "findings", "staticScore", "verdict" } }
```

### 4.2 AST 解析

TypeScript compiler API（`createSourceFile`）只读解析 .js/.ts/.mjs/.cjs。
辅助：字符串/数值静态求值（字面量/模板/拼接/const 绑定）、词法遮蔽检查。

### 4.3 规则集（R1–R12）

| ID | 名称 | 默认级别 | 确定性 |
|---|---|---|---|
| R1 | constructor 链逃逸 | critical | certain/likely |
| R2 | 动态执行（eval/Function/import/require，含遮蔽检查） | high（files）/ medium（code） | certain/likely |
| R3 | process 直接访问（按 runtime 分级；round-7.1：只读成员降 info、副作用成员 high、逃逸成员 critical） | critical（host）/ high（sandbox） | certain |
| R4 | 宿主闭包捕获（agent/TextEncoder…）+ 宿主全局原型污染（round-7；round-7.1：files 一律 high，与 targetKind 无关） | critical（code）/ high（files） | certain/likely |
| R5 | ctx 逃逸尝试信号 | medium | 仅 code |
| R6 | 字符串粗扫兜底（混淆特征需与动态执行组合证据，round-7） | info | heuristic |
| R7 | 硬编码密钥（占位符按段排除） | high | likely |
| R9 | 资源安全（无界分配/死循环/循环内 spawn/ReDoS/递归；round-7：组后 ? 不判 ReDoS、有界遍历递归不判无终止） | high/medium/info | certain/likely/heuristic |
| R10 | 供应链（install 钩子/依赖清单） | high/info | likely/heuristic |
| R11 | 破坏性文件操作（fs 删除/敏感路径读写） | high/medium | likely |
| R12 | Cordis/DSH bundle 契约（入口文件/bundle patch 声明/name/engines.node） | high/medium/info | certain/likely |

规则开关：`rules: { "R7": false }` 可关单条。

### 4.4 评分模型

`staticScore = max(0, 100 - Σ(severity 权重 × 命中数 × confidence 系数))`

verdict（唯一权威判定）：`critical ≥ 1 → critical`；否则 `high ≥ 1 → suspicious`；其余 → clean。
**heuristic 置信度永不升级 verdict**（R6 只提示不判定）。

### 4.5 目标身份分级（targetKind）

- `plugin`（DSH 插件包：依赖 @deepseek-ai/cordis 等）：严格——process 访问、危险 require 按逃逸面报。
- `generic`（普通 npm 包/官方运行时）：能力触达面降级（info/medium），不进 verdict。
- 自动扫描按插件语义（严格）执行；`scan_plugin` 按 package.json 依赖判定。
- **自豁免 realpath 化（round-7.1 P-3）**：vet 自身（name 匹配）必须 realpath 验证目标就是当前 vet 实例才判 generic——本地 file: 安装无 registry 校验，只比 name 可被冒名伪造（恶意 tarball 冒充 @jieai/dsh-plugin-vet 骗过降级）；同名冒名包按最严格 plugin 判定。
- **包形态降级（round-7）**：engine 读 package.json `bin` 字段注入 RuleContext——应用型包（`appShape`：声明 bin 的 CLI/TUI/server，process 即产品功能）R3 整体降 info；bin 入口文件（`cliFiles`，永远独立运行的 CLI 脚本）R2/R3 按通用代码判定、R9 死循环降 medium。package.json 内容在缓存 hash 内，形态变化自然失效。

### 4.6 缓存

内容 hash + engine 版本 + 规则集 + **targetKind/runtime** → 报告文件（0700 目录/0600 文件，
严格形状校验防伪造）。不同上下文不串味。

### 4.7 OSV 已知漏洞核对

package.json 有 name 时按**安装版本（仅精确版本）**查询 Google OSV（`api.osv.dev/v1/query`），
服务端按 affected ranges 过滤；命中追加 high finding 并重算 verdict。网络失败静默降级。
`osvCheck: false` 可关（默认开启会外发包名，介意隐私可关）。
核对面 = 插件自身 + 直接依赖（上限 8 个，`@deepseek-ai/*` 官方包跳过）；
`*`/`>=`/`^`/`~` 区间与无版本主包跳过查询（P3-1/P3-3，避免陈旧全量历史误报；
round-7 修正：range 不再剥前缀当下界精确版查询——下界受影响但实际已装版本已修复时会误报）。

## 5. 运行时守卫（T1 + T2 + 蜜罐，alarm-only）

### 5.1 T1 哨兵（旁路监视器）

- 每 `runtimeIntervalMs`（默认 2s）读宿主 /proc：VmRSS、子进程数、fd 数、窗口内内存增长。
- 超限 → 报警 JSON 行回传宿主：内存超限 red、fork 突增 red、fd 超限 yellow、膨胀 yellow。
- 粒度=宿主全局（插件共用进程，无法归因到插件）。

### 5.2 T2 钩子（进程内包装）

包装 `fs`、`fs.promises`、`child_process` 的内置导出（属性级包装，ESM 具名导入
快照是已知旁路）：

- 危险操作 → 取栈 → 归因插件包名（栈帧路径 ↔ 插件根目录最长前缀匹配）→ 报警。
- 覆盖：敏感路径写入/删除、读密钥文件、含 shell/下载外联关键词的子进程、
  破坏性命令（rm/mv/dd/mkfs…）命中敏感路径、shell 重定向到敏感路径、
  侦察原语（readdir/stat/access 敏感路径）、蜜罐诱饵触碰。
- **从不阻断调用**；官方归因的 spawn 降噪。

### 5.3 蜜罐诱饵

- 默认位置 `~/.dsh/.local`：目录名/文件名/内容均无蜜罐关键词（反蜜罐）。
- 诱饵值全是格式正确但无效的假凭据（AWS/OpenAI/npm 前缀真实、密钥体随机；
  id_rsa 是真实格式的一次性 RSA 密钥对，未在任何地方使用）。
- 幂等：已存在的诱饵不重写；被删的自动重建。权限 0700/0600。

### 5.4 报警聚合（VetStatus）

- 环形缓冲（默认 20 条）+ 同 id 去重窗口（60s）+ **TTL 过期（默认 24h）**——
  一次误报不会让盾牌永久黄/红。
- 盾牌 level：任一 red → red；任一 yellow 或最近扫描非 clean → yellow；否则 green。

## 6. 审计协议（vet-audit-protocol 技能）

vet 不内置 LLM 审计工具。审查由 **agent 按技能步骤执行**（`AUDIT_PROTOCOL.md`）：

scan_plugin 静态判据 → 读清单/源码 → 逐条核实发现 → 主动深挖
（网络/文件/进程/凭据/库语义）→ 用系统写入能力手写健康档案到
`~/.dsh/vet/audits/<plugin>-<version>-<ts>.md`。

`requireAudit: true` 时，无档案的第三方插件加载 → report 报警 / deny 拦截。
档案命名严格（`<name>-<version>-<ts>.md`），防前缀伪造。

## 7. 插件本体与分发

- 入口 `src/index.ts`：name/inject/Config/apply，无 default export。
- 配置：schemastery schema（`src/config.ts`），全部字段见 README Config 表。
- 工具：`scan_plugin`（确定性静态扫描，verdict 只来自静态层）。
- 守卫：`internal/plugin` 自动扫描 + requireAudit 门槛；`tools/execute` 拦截。
- 盾牌：浏览器半区（`conversation.session.header.actions`），轮询 /vet/status.json，
  可一键写 runtimeGuard 配置（重启生效）。
- 分发：`cordis.patch.yml` 挂载补丁（insert 语义）；`files` 含 lib/ + 文档 + patch。

## 8. 已知边界（诚实清单）

- 静态扫描是「减速带 + 取证层」，不是安全边界。
- 间接引用（别名函数、计算访问、globalThis.process、间接 eval）仅 info 或零 finding。
- 运行时构造载荷（base64 串、hex 拼装、自修改代码）可绕过 AST 规则。
- 非源码文件（.jsx/.tsx/.vue/二进制/wasm/shell 脚本）不在扫描面。
- T1/T2 抓不了 worker_threads 独立 realm、原生插件、process.binding、低流量慢外联。
- T2 对 ESM 具名导入快照不覆盖（README 已知旁路）。
- internal/plugin 自动扫描只收集 ≤6 层深、非隐藏源码（深层静默不扫）。
- /vet/status.json 无鉴权（盾牌轮询需要匿名 GET）；dsh web 绑定非回环地址时
  局域网可读扫描结论，介意保持回环绑定。