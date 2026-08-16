# Changelog

所有重要变更记录于此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

- **round-5（外部 DSH 实测评估）修复**：
  - R1 元素访问形态漏检：x["constructor"]("return " + "process") 此前完全绕过（verdict=clean）——恶意代码最常用的形态之一，现点访问/元素访问双形态 + 拼接/模板/const 绑定参数静态求值全部命中 critical。
  - R3 信号处理误报：process.on/once('SIG*') 注册与信号回调内的 process.exit（优雅退出）是 MCP server 等常驻插件的正常操作面，降级 info 不进 verdict；裸 process.exit（错误路径等）保持 critical。
  - R5 ctx.logger 误报：cordis 官方注入服务（DSH mcp-client 等大量使用）加入白名单，不再报 medium。
  - R9 ReDoS 误报重写：旧正则把 (?:x)? 组首 '?' 修饰符误当量词，所有单可选组误报 medium——改为函数式判定（组内顶层量词 + 组后量词叠加才算），(a+)+ 类真 ReDoS 仍报。
  - 以上全部带回归测试（+7，225 总用例）。
- **构建卫生：lib/ 旧残留清理**：
  - build 前加 clean 步骤（rm -rf lib 再编译）——已删除源文件的旧编译产物此前残留 lib/ 并随 tgz 发布（session-events.js、tools/audit-plugin.js、audit/ 下 6 个废弃模块 js + 对应 d.ts，均为旧 LLM 审计工具的兼容壳）；清理后 tarball 从 83 文件降到 66 文件，vitest.config.ts 同步移除两条指向废弃文件的 coverage exclude。
- **round-4 审查修复（开源准备）**：
  - R12 nodeMajorBelow22 单数字主版本漏检：旧实现假定主版本两位数（two=s[0]+s[1]），4.0.0 / 8.17.0 / 2.0.0 / 6.0.0 / 9.0.0 / 3.x / 5.5.0 全部漏提示——改为解析数字前缀主版本与 22 比较，并顺带支持 v 前缀（v18.0.0）。
  - R12 pickEntry 补两种合法形态：exports 字符串形态（Node 合法）此前被跳过 → 无 main 且根无 index.js 时产生 medium 误报；exports 条件对象新增 node 条件（DSH 运行在 Node，node 条件最常见）——旧列表只有 import/require/default/types。
  - P2-2 修复缺口：nearestPackageRoot 的 existsSync 探测未包 withVetSelfIo——扫描 ~/.dsh 下非 node_modules 文件时产生无主 fs-probe 自报警；已包直通（与 detectTargetKind/listSourceFiles/readPackageVersion 对齐）。
  - budgetMs 移除 DSH_PLUGIN_VET_SCAN_BUDGET_MS env 覆盖：设大值会绕过宿主超时对齐，再次让 R8-skip 不可达（子进程被杀 → deny fail-closed 误拦）；测试用 timeoutMs 参数控制预算。
  - 锁文件切换 npmjs 官方源：package-lock.json 全部 resolved 从 registry.npmmirror.com 重生成到 registry.npmjs.org（含完整 integrity），npm ci 冒烟验证 137 包干净安装。
- **开源发布前自检（dogfood 实测）**：
  - 蜜罐诱饵 R7 自命中修复：诱饵前缀（sk-/AKIA）改常量拼接，模板串拼接文本不再被自己的 R7 判 high——发布物自扫从 suspicious 转 clean，deny 模式重装 vet 不再自锁；加回归测试。
  - esbuild 声明为直接 devDependency（此前靠 vitest 传递依赖，脆弱）。
  - README 数字/表述同步：用例数 189→214；Known Limitations #8 改为 OSV 现状（精确版本查询、网络失败静默降级、可关闭）。
  - 清理仓库内不存在的 PLAN.md 注释引用（19 处）；.gitignore 补 *.tgz（npm pack 产物）。
- **三轮审查修复 + 审计协议扩展（P-2 计划项落地）**：
  - P2-1 扫描预算与宿主超时失配：engine 预算原来 files×2s 无界，deny 15+/report 31+ 文件包在 R8-skip 触发前就被宿主 kill → 误报 scan-fail（deny fail-closed 会误拦合法大包）。现在请求携带宿主计划超时（protocol.timeoutMs），engine 预算=min(files×2s, 超时-1.5s)——R8-skip 恒先于 kill，优雅降级结构上可达；scan_plugin 工具超时改与 internal/plugin 同公式（按文件数放大、60s 封顶）。
  - P2-2 vet 自查 IO 未纳入 vetSelfIo：archive.hasAuditRecord 的 ~/.dsh 目录 readdir 与 scan_plugin 的 listSourceFiles/detectTargetKind 读用户路径，在 .dsh 敏感段下产生无主 fs-probe 自报警——全部 withVetSelfIo 直通（盾牌轮询同款）。
  - P2-3 跨模块重复安装 + 5s respawn 窗口竞态监控静默死亡：exit handler 在 decideRespawn=false 且 env 指向存活 pid 时记 warn + 黄灯 t1:sentinel-taken-over——接管换手可观测而非静默。
  - P3-1/P3-3 OSV 只查精确版本：*、>=、^ 与无 version 主包跳过查询（isExactVersion 字符判定），消除按 range/全量历史查询的陈旧误报。
  - P3-2 lastScan 加 TTL（24h，复用 alarmTtlMs）：一次 suspicious 扫描不再让盾牌永久黄；持续扫描自然续期。
  - P3-4 file 目标身份识别：父目录有 package.json 时 detectTargetKind（插件文件逃逸判定不再恒 generic）。
  - P-1 档案版本精确绑定：requireAudit 门槛按装机版本匹配档案（internal/plugin 提前解析根目录读版本）——插件升级后旧档案不放行新版本，必须重新审计。
  - 新规则 R12（Cordis/DSH bundle 契约）：dsh.bundle.patch 声明缺失/入口文件缺失 → high（suspicious）；无入口（无 main/exports 且无 index.js）→ medium；插件意图包缺 name → medium；engines.node 主版本低于 22 → info。确定性清单检查，非插件意图包不判。
  - scan_plugin 输出补 pluginVersion（档案/版本核对用）；AUDIT_PROTOCOL 新增 4.5 步「契约与代码质量审计」（错误处理/同步阻塞/资源泄漏/异步正确性/生命周期卫生与热重载幂等）+ 档案模板质量小节 + 结论判据加入质量维度（静态 clean 但有拖垮宿主类缺陷 → review）。
  - P3-5 记录（非问题）：readHostMetrics 每次 5s 轮询全量扫 /proc 子进程——子进程多时开销随规模线性放大，当前量级可接受，留待后续按需缓存/降频。
  - 误报修复（盾牌实测）：atomic-write 协议锁（`<file>.lock`）的删/写豁免——DSH 写 `~/.dsh/.credentials.yaml` 用 dsh-atomic-write（wx 创建仅含 PID 的锁兄弟文件、写完 finally 删锁），宿主每次保存凭据都触发无主 fs-destroy red 误报；锁文件非凭据本体，单路径写/删不再归敏感（凭据本体与 cp/rename 双路径语义不变）。
- **二轮审查修复（全部 14 项核实并处理）**：
  - P1-1 `guardDisabled` 不对称重置：off→watch 转换后哨兵永不启动——watch 分支开头复位（原 fresh-spawn 分支检查后直接 return，无任何日志）。
  - P1-2 T1 复用模式报警丢失：复用旧哨兵 = 新实例没有其 stdout 管道，T1 报警全写进已废弃 VetStatus——改为清 env + 终止旧哨兵 + 全新 spawn（新管道新监听器）。
  - P1-3 `rootIndexing` 标志泄漏：归因构建（loader.entries()/ctx.baseUrl）抛错时标志永久滞留 → 所有 T2 报警静默 bypass——整个构建体纳入 try/finally，包装器对归因失败 try/catch（报警保留无主，fs 调用永不中断）。
  - P2-4 环形缓冲 replace 语义：窗口外同 id 重发先移除旧副本再入列——持续报警不再占满 20 槽（alarmCount 虚高、挤掉其他报警）。
  - P2-5 M5 半实现：clean 结果不再前置 `\n\n`（此前 notes 为空也污染机器可读输出）。
  - P2-6 `~/.dsh` 敏感段：配置根侦察（readdir/stat/读配置）此前完全不可见——加入敏感段；配套官方包归因全类降噪（平台本体高频 IO 不刷屏）+ vet 自 IO 直通（withVetSelfIo，盾牌轮询不自报警）。
  - P2-7 deny 同步冻结：同步路径剔除 OSV 网络查询 + 超时封顶 30s（此前按文件数放大到 60s + OSV 4s；超时仍 fail-closed 反扫描规避）。
  - P2-8 vet 条目匹配规则统一：strip/extract/read 三处此前 trim 与顶格不一致——缩进嵌套条目被误读/摘不掉；统一为只认顶格。
  - P3-9 enable 分支缩进复用：写 runtimeGuard 不再硬编码 4 空格，复用原 config 缩进（非 4 空格配置不再写出损坏 YAML）。
  - P3-10 OSV 依赖树：核对面从插件自身扩展到直接依赖（上限 8 个，官方包跳过，独立超时静默降级）。
  - P3-11 README 同步：cordis_run 无 code 载荷不生效（保留守卫位），移除拦截宣称；M5 行为同步。
  - P3-12 鉴权边界记录：dismiss/restore 同源校验（alarm-only 展示层，README 记录）。
  - P3-13 判定：保留 deny 扫描失败 fail-closed（M9 反扫描规避），OSV 已移出 deny 同步路径（网络抖动不再影响）；README/CHANGELOG 记录取舍。
  - P3-14 清理：osv.ts 过期注释同步、data/code-index.sock 工作残留删除、render.ts 文件尾补换行。
- **生命周期补漏（Cordis 规范）**：T2 钩子与 T1 哨兵是全局资源（fs/child_process 猴子补丁 + 哨兵子进程），此前只在重新 apply 时清理——条目被彻底移除会遗留到进程退出。现在 apply 用 `ctx.effect` 注册 disposer（cordis fiber 卸载时运行；核验时发现 `ctx.on('dispose')` 不在 cordis 类型化事件面内、编译报错，改用 effect 挂载）；disposer 幂等（与 prevGuardDisposer 双保险）。
- 开源发布准备：MIT 许可证、CONTRIBUTING/SECURITY/CODE_OF_CONDUCT、公开架构文档、npm 元数据。
- 误报修复（实测两条）：
  - T2 fs-destroy：工具链临时产物豁免——tsc 增量编译在源文件旁建的 `<源名>.<pid>.<uuid>.tmpdir`（`*.tmp`/`*.temp`/`*.swp` 等）随用随删，名字里的 secrets 只是被编译的源文件名；末段临时后缀不参与敏感词判定，父段照常判定（`~/.ssh/config.bak` 仍报警）。
  - T1 growth：测量跨度必须覆盖完整窗口——起窗初期 20 秒内涨 274MB 的瞬时尖峰不再被标成"10 分钟持续膨胀疑似泄漏"。
- 新功能：报警单条忽略/恢复——面板每条报警可「忽略」（不再计入盾牌等级与计数，记录保留、可「恢复」；报警停止后忽略自动失效，复发重新可见；与报警存储同生命周期，重启重置）。
- **R31 崩溃修复（watch 模式实测崩溃，实为递归爆栈）**：T2 报警归因阶段（rootIndex 遍历 100+ 插件根）自身的 fs 探测再次进入被包装的 fs → 敏感包名（dsh-credentials / dsh-token-meter 等，实测递归 4041 层）再次 alarm → 归因 → 无限递归 → 每层重建正则 → V8 RegExpCompiler 栈耗尽，误报 OOM 进程崩溃。修复：归因期间置直通标志，包装器直通原始 fs 断开递归；segmentHasKeyword 正则按关键词缓存。护栏标志模块私有（不挂 globalThis——挂在全局等于给恶意插件一把让 vet 全体失明的钥匙）。
- **A9 自伤修复（用户实测）**：T2 把 vet 自己误报成警报源的两条根因一并修掉：
  - 归因排除 vet 自身：包装器帧（runtime-hooks.js）永远是报警栈栈顶，vet 根在归因映射里时一切宿主/无主报警都会栽到 vet 头上（实测 fs-probe realpathSync(...@deepseek-ai/dsh-credentials-local/package.json) 被归因为 @jieai/dsh-plugin-vet）。现在归因映射排除 vet，报警照发但归因到真实调用方（官方包/无主）。
  - node_modules 包目录豁免：包名/包内文件是公开工件，含 credential/secret 等词的包名是正常生态（本机实测 12 个：@aws-sdk/credential-provider-*、@deepseek-ai/dsh-credentials(-local) 等）——宿主模块解析（require.resolve 内部 realpathSync/stat 包内 package.json）与 vet 扫描读取都会高频触碰，既往全部误报成 fs-probe。node_modules 段之后的路径段不再做敏感匹配；node_modules 之前的段照常判定（~/.ssh/node_modules/x 仍命中）；mutate 下系统根前缀（/usr 等）仍生效。
  - rootIndex 归因映射只建一次并缓存：原来每次被分类的 fs 调用都重建（N×require.resolve），报警风暴时放大为 CPU 空转。
- 安装可用性对照 DSH 官方 bundle 契约验证并修正：
  - peerDependencies 对齐 DSH 0.1.0-rc.6 版本族（原 `^0.0.1-rc.1` 与真实安装版本不符，纯属侥幸可用）。
  - 新增 `prepublishOnly`：发布前强制构建，防止 lib/（含 client bundle）缺失或过期。
  - 清理 cordis.patch.yml 中指向已删除 PLAN.md 的内部注释。
  - 端到端模拟全新用户安装全链路通过：`dsh plugin --profile <name> add <tarball>` → reconcilePlugins 识别 `dsh.bundle` → loadProfile 解析 bundle 层 → composeEntries 挂载 vet 条目 → client-registry 条件（`dsh.client`/exports["./client"]/inject 边）全部满足。

## [0.1.0] - 2026-08-16

首个可发布版本。

### Added

- 静态扫描引擎（scanner-bin）：R1-R11 规则集、确定性 verdict、评分模型、内容哈希缓存、OSV 已知漏洞核对（按版本过滤）。
- 目标身份分级（targetKind）：DSH 插件包严格判定，普通 npm 包降级能力触达面——195 官方包 0 误报。
- `scan_plugin` 工具：dynamic-code / package / file 三种扫描目标，verdict 只来自静态层。
- `vet-audit-protocol` 技能：agent 引导的插件审查协议（AUDIT_PROTOCOL.md），健康档案落盘约定。
- `requireAudit` 审计门槛：无档案的第三方插件加载 → report 报警 / deny 拦截（档案前缀防伪造）。
- `tools/execute` 守卫：cordis_define / cordis_run / run_code / workflow 执行前代码扫描。
- 运行时守卫（runtimeGuard: watch，alarm-only）：
  - T1 哨兵：旁路 /proc 监视（内存/子进程/fd/膨胀窗口），单例锁防热重载叠加，意外退出自动重拉。
  - T2 钩子：包装 fs / fs.promises / child_process，敏感路径操作/侦察/破坏性命令/蜜罐触碰报警，栈归因到插件包名。
  - 蜜罐诱饵：隐蔽位置放假密钥，反蜜罐设计（无关键词），0700/0600 权限，幂等自愈。
- GUI 盾牌：会话头部状态灯（绿/黄/红 + 计数徽标），报警面板、实时指标、守卫一键开关（重启生效），莫兰迪双主题。
- 报警聚合：环形缓冲 + 同 id 去重 + TTL 过期（24h），一次误报不会永久黄/红。

### Fixed

- 哨兵 respawn 死代码（env 先删后比恒 false）——监控崩溃后现在会自动恢复。
- report 模式扫描同步阻塞事件循环——改异步子进程，大包不再冻结宿主。
- T2 报警 id 缺 pluginHint 导致跨插件报警互吞。
- fs.open 把首参路径误当 flags（open('auth.txt','r') 误报写入）。
- exec 破坏性命令（rm -rf ~/.ssh 等）与敏感路径重定向漏检。
- 扫描缓存键缺 targetKind/runtime 导致的跨上下文串味。
- OSV 查询不带版本导致的已修复版本误报。
- R7 硬编码密钥整段占位符误杀（真实 key 混 example 漏报）。
- R11 fsBase 用 startsWith('fs') 误伤 fsmap 等自定义对象。
- R2 eval/Function 缺遮蔽检查、factory 注入 require 嵌套函数误报。
- 蜜罐文件权限 0644 同机可读（收紧 0600/0700）。

### Security

- scanner 独立子进程，AST 只读、从不 eval，恶意输入不影响宿主。
- 扫描失败 deny 模式 fail-closed（拦截 + 告警，不静默放行）。
- 缓存严格形状校验防本地伪造。
- 档案命名严格正则防前缀伪造。
