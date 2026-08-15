# Changelog

所有重要变更记录于此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

- 开源发布准备：MIT 许可证、CONTRIBUTING/SECURITY/CODE_OF_CONDUCT、公开架构文档、npm 元数据。
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
