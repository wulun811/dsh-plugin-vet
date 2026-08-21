# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [0.2.3] - 2026-08-21

三轮全量代码审查产出（每项修复均带回归测试）：

### Fixed（用户反馈：宿主家务操作误报降噪）
- **DSH web 状态临时产物无归因高频误报**：宿主 web 层保存 UI 状态（.shortcut-bar.json 等）走原子写协议，每次保存高频产生 `.名.json.<pid>.<uuid>.tmpdir` 的 lstat+rmdir 清理；栈里只有宿主帧 → 无归因 → 每次都刷 red fs-destroy / yellow fs-probe（用户反馈「真的好烦」）。现 fs 包装器对**无归因且归因链未被篡改**的该类目标豁免报警——刻意不做「无归因一律不报」（那正是异步隐藏归因的恶意插件想要的静默通道），豁免边界：插件归因碰这些路径照报（碰宿主状态=信号）、真敏感路径照报、非临时产物照报、蜜罐/完整性金丝雀不受豁免；凭据面（.credentials.yaml 原子写临时件）与 sessions/** 刻意不在豁免目录内。

### Fixed（五轮复审补遗）
- **check-pack-integrity 相对引用闭合检查静默空转（发布门禁失效）**：REL_REF_RE 正则字面量误写 `\\.{1,2}`——正则字面量里 `\\` 匹配字面反斜杠而非转义点号，真实构建产物上相对导入零命中，检查 #3 完全空转却照印「✓ 全部闭合」，且脚本此前无任何测试覆盖——0.2.2 的 files 白名单事故今天重演它也拦不住。现改正则为 `\.{1,2}`；脚本内加已知样本自检（正则失效即 exit(1)，防同类退化再静默）；脚本本体纳入 vitest 门禁（任一完整性项不过 → 测试红）。

### Fixed（四轮复审补遗）
- **vet_label 渲染层对残缺能力清单仍有崩溃面**：loadCapabilities 对单条记录零结构校验，且 label() 单记录路径不触碰 .capabilities——一条缺字段的记录（手改/半写/旧版升级遗留）可让 manifest 经 execute 键省略 + JSON 往返变成 undefined，`=== null` 守卫穿透后在 m.hasNetwork 崩溃（与 DSH.SO 反馈 bug 同族）；manifest 缺数组字段时 m.hosts.length 同崩。现 null/undefined 双拦截 + 各段 Array.isArray 兜底按空渲染；latest/note 同款穿透一并收紧。
- **registry 成员预检漏反斜杠成员**：'..\\..' 形态成员在 GNU tar 里是字面字符无险，但 Windows bsdtar 提取时会当路径分隔符转换越界。现预检一并拒绝含反斜杠的成员——npm 官方 pack 归一化路径分隔符，正常 tarball 不含反斜杠成员，误杀风险为零。

### Fixed
- **scanner 并发上限失效（排队路径不记账）**：withScanSlot 排队分支只跑任务、不增减 activeScans，pump 的 while 条件看不到占位，一口气放空整个队列——8 任务仿真实测真实并发峰值 7（上限 2）。首次启动批量加载正是该上限要防的 spawn 风暴场景。现排队路径自行记账并在完成后 pump。
- **upstream-radar 从被扫描包目录链解析执行（隔离破口）**：queryUpstreamRadar 用 require.resolve(..., { paths: [packageRoot] }) 探测，会优先命中被扫包自带/伪造的 node_modules/upstream-radar 并被 execFile 直接执行——恶意包塞同名假包即可在 scanner 子进程里运行任意代码，破坏「静态分析、不执行被扫代码」承诺。现仅在 vet 自身模块树解析（不带 paths），并对解析结果落在被扫包目录内的情形纵深拒绝。
- **registry 对账解包无成员名防护 + dist.tarball 主机未钉死**：hashPackTarball 直接 tar -xzf 不可信 tarball（GNU tar 默认不拦 '..' 成员，可写出 tmpdir 之外）；doVerify 对 packument 返回的任意 tarball URL 直接 fetch（SSRF 面）。现解包前 -tzf 列成员预检（拒绝对路径/'..'/盘符）；tarball 主机钉死到 registry 源；baseline-reconcile 测试夹具的 tarball URL 同步对齐真实 npm 行为。
- **vet_label / vet_diff 单版本记录渲染崩溃（DSH.SO 反馈 bug）**：execute 对 null 字段整键省略，JSON 往返后 render 收到 undefined 而非 null，原 `!== null` 守卫穿透后读 .from 抛 “Cannot read properties of undefined (reading 'from')”。两工具渲染守卫改 null/undefined 双拦截；vet_diff 为排查中发现的同款隐患一并修复。

### Changed
- **移除僵尸运行时依赖 typescript**：dependencies 声明但 src/scanner-bin/scripts 零引用（构建期 tsc 由 devDependencies 覆盖）——安全工具不该让用户为无用依赖扩安装面。已同步 lockfile。

## [0.2.2] - 2026-08-21

### Fixed
- **npm 包 files 白名单漏收散件目录（发布阻断）**：files 原只列 index.bundle/gate/gate-cli/client + guard/scanner/scanner-bin/types，漏了 lib/tools、lib/audit、lib/guards、lib/pkg-root.js、lib/invariant.js 等编译产物——npm 包内 gate.js（→ ../tools/scan-plugin.js）、runtime-guard.js（→ ../pkg-root.js + ../invariant.js）、version-diff.js（→ ../audit/archive.js）会 ERR_MODULE_NOT_FOUND，散件入口一装就崩（主 bundle 因内联侥幸可用）。现 files 改为收全整个 lib 目录，tarball 相对 import 全部闭合，gate/bundle/gate-cli 加载验证通过。
- **fetch 包装器 Request 形态 body 盲点（二轮审查 #1/#6）**：fetch(new Request(url, { body })) 时 body 在 Request 内部，原实现三路观测（字节台账/金丝雀扫描/密钥外泄匹配）全部失效。现在同步 clone（不消费原流）后异步补观测，字符串 body 与 Request body 统一走金丝雀/密钥扫描；body 表达式只计算一次。
- **持久化忽略热路径同步读盘（二轮审查 #2）**：isPersistentlyDismissed 原实现每次 record()（每次 T2 报警收口）都 readFileSync 读盘——报警风暴时叠加大量同步 I/O。现改为内存缓存 Set（O(1) 查询），dismiss/restore 同步更新缓存。
- **saveDismissed 目录硬编码（二轮审查 #3）**：原实现写 ~/.dsh/vet/ 而非 dirname(DISMISSED_FILE)——测试自定义路径（setDismissedFileForTest）时会建错目录。现以 dirname(DISMISSED_FILE) 为准。
- **fetch 包装器缺失 C4 归因篡改检测（二轮审查 #5）**：归因链被篡改（prepareStackTrace / stackTraceLimit）时其余网络模块会报 attribution-tampered red，fetch 分支此前静默降级为无主。现已对齐：篡改 + 敏感出口 → 独立 red 报警。无主密钥泄漏保持静默（0.2.1 设计：宿主对话含 PEM 为正常行为，不回归）。
- **取证文件无限增长（二轮审查 #10）**：取证 jsonl 文件名不再固定 <plugin>.jsonl（每次 DSH 重启 append 同一文件），改为 <plugin>-<会话毫秒时间戳>.jsonl 按会话轮转；模块注释如实标注「无自动 TTL 清理，保留供审计」。

### Changed
- **依赖范围升至 ^0.1.1-rc.1（DSH 0.1.1 兼容）**：peer/dev 中 @deepseek-ai/dsh-invariants/llm/session/tools 从 ^0.1.0-rc.8 升到 ^0.1.1-rc.1——semver 预发布规则下 ^0.1.0-rc.8 不满足 0.1.1-rc.1，不升级会在 DSH 0.1.1 环境报 peer 冲突。API 面已验证零差异（lib 全量 diff 空）。
- **路径模式匹配正则缓存（二轮审查 #4）**：patternMatchPath 含通配符模式每次调用都 new RegExp，现按规范模式缓存编译结果。
- **发布完整性检查增强（check-pack-integrity）**：原来只校验 resolveVetFile/resolvePkgRoot 引用的文件在 files 覆盖内，这次 files 白名单漏目录它没拦住。现新增四道检查——(1) lib/** 全部相对 import/export/require 在发布集内闭合；(2) bin 与 exports 声明的入口全部可达（package.json 等 npm 强制随包文件豁免）；(3) 发布集边界：禁止 src/、scripts/、test/、scanner-bin/*.ts 等非发布物混入；(4) files 条目不存在时报错（防手误）。prepublishOnly 门禁在发布前强制运行。

## [0.2.1] - 2026-08-21

### Added
- **N3 密钥外泄归因分级**：无主（宿主自身流量）降 yellow「格式命中待人工研判」，删除「100% 确认」过度声明；归因插件保持 red。金丝雀命中不受影响。
- **capability 提取降噪**：hosts 形状校验（拒绝模板拼接残片）；裸字面量 fsPath 收紧（仅路径前缀+无空白+非相对模块引用）；hasExec 门控（裸 spawn/exec/fork 仅在文件引用 child_process 时计为执行能力）；Function("return this") realm shim 豁免。
- **baseline-mismatch 定性重构**：report 模式 mismatch 时异步对账 npm registry（同版本发布内容不可变=内容真值）——字节一致→基线陈旧，自动刷新+yellow；不一致→红警坐实；对账不可用→维持红警 fail-closed。新增配置 `acknowledged-package-hashes`（键 `name@version`，值 sha256 hex）：登记的本机合法修改豁免比对并记一次性 yellow 提示，透明不静默。

### Fixed
- N3 无主流量误报：宿主会话体/文档天然含密钥样文本（安全报告、测试夹具），形状命中≠外泄实锤，原「100% 确认」措辞过度。
- capability 提取器噪声：bundle 自带同名辅助函数（fork/exec）误触 upgrade-cold「执行+网络双高」；注释样文本/报错文案/相对模块引用混入 fsPaths；模板拼接残片（如 `[`）混入 hosts。
- baseline-mismatch 误判方向：同版本号重装/本机补丁触发红警「疑似供应链篡改」，实际可能是基线陈旧或合法修改。registry 对账+补丁登记双机制解决。

## [0.1.21] - 2026-08-20

### Added

- **Forensics mode (P0-2, cross-hardening #6)**: once a plugin is confirmed malicious (N4 canary leak),
  `arm` puts it under forensics and every subsequent fs/child_process/network op of that plugin is appended
  to `~/.dsh/vet/forensics/<plugin>-<ts>.jsonl` (0600/0700). Wired into `recordCanary` and the N3 ledger
  fs/net observers (new `src/guard/forensics.ts`). Fail-open, no session-content capture (same data plane as
  the N3 ledger). Tests `test/v2-forensics.test.ts` (7 cases).


- **`vet_label` tool (M2 capability nutrition label, P0-1)**: prints a human-readable "nutrition label" for a
  plugin package — the files it touches (with sensitive-path marking), the hosts / subprocesses it references,
  its third-party imports (capability unknown), and its network/exec capability flags (incl. the ESM named-import
  blind-spot marker), plus a one-line summary of the last upgrade diff. Read-only, purely local, reads the same
  N6 capability history (`~/.dsh/vet/capabilities.json`); no scan, no network. It reports *declared* static
  capabilities; runtime observed/dormant capabilities stay with the running shield. New `label()` query in
  `src/guard/version-diff.ts`; registered in `src/index.ts`.

- **Ghost/zombie dependency audit (P0-2, cross-hardening #9, new rule R16)**: the scanner (files mode +
  package.json) reconciles *declared* (dependencies/devDependencies/peerDependencies/optionalDependencies) vs
  *referenced* (code imports) vs *installed* (node_modules): ghost deps (imported but undeclared) and zombie
  deps (declared but missing) are emitted as info/heuristic `R16` findings and recorded into the N1 manifest
  as `ghostDeps`/`zombieDeps`, which `vet_label` (M2) prints and N6's version diff displays. `@deepseek-ai/*`
  is never flagged (host trust boundary). The declared/installed state feeds the scanner cache key (`deps`
  fingerprint) so results never go stale; gate `rules:{R16:false}`. ENGINE static-v12 → static-v13 (caches
  invalidate). Tests `test/v2-ghost-zombie.test.ts` (14 cases).

- **M1 semantic-contract core (P0-5, record stage)**: new `src/guard/contract.ts` — a deterministic,
  offline contract schema + laxity validator + scope matchers + three-level trust priority
  (code facts > runtime observations > contract promises). A contract the user's own agent authors locally
  (`vet.contract.json`, schema 1: fs paths, hosts/ports, commands, env) is validated: bare `**`/`*`/empty
  paths, mid-globstar, wildcard hosts/commands and bad schema are rejected deterministically; bounded forms
  (`/<dir>/**`, `/tmp/<seg>/out`, `*.example.com`) are accepted. Contracts never override code facts or
  swallow out-of-scope observations, and the record stage never intercepts (N7 untouched). Tests
  `test/contract.test.ts` (27 cases).

- **M1 contract wired into runtime T2 sink / N1 diff (P0-5, 方案 A record-stage)**: with config
  `contract.enabled` (default on) plus a per-plugin contract file, runtime alarms are reconciled against
  the contract: out-of-scope → info `m1:contract-violation` (collapses by source/kind/plugin/field),
  rejected contract → yellow `m1:contract-rejected` (once per plugin), and a *code fact* (N1 hidden
  capability) contradicting the contract → yellow `m1:contract-distrusted` (once per plugin). The contract
  is strictly advisory — it never suppresses code-fact or observation alarms and never intercepts (N7
  untouched); no contract file = byte-for-byte zero behavior change. Tests
  `test/v2-m1-wiring.test.ts` (10 cases).

- **T2 hook integrity heartbeat (P0-2, cross-hardening #2)**: every T2 wrapper (fs / fs.promises / child_process
  / http / https / net / http2 / tls via patchModule/patchNetworkModule, plus the manual dgram.createSocket and
  globalThis.fetch wrappers) is branded with a module-closure-private `Symbol` (`brandVetHook`) — an extractable
  marker that a copied `toString()` cannot spoof. `hookHeartbeat()` re-checks the current module exports for the
  brand (registry keyed by module object); in `runtimeGuard: watch` a periodic timer (runtimeIntervalMs × 4,
  min 5s, unref'd, cleared on dispose) raises a yellow `t2:hook-heartbeat` alarm listing the stripped ops if any
  wrapper was removed/replaced (e.g. a plugin rewriting `require.cache` exports to bypass T2). Zero config, zero
  network, alarm-only. Tests `test/v2-hook-heartbeat.test.ts` (6 cases).

- **Self-scan trust annotation — vet 扫 vet（0.1.21，self-scan Trusted 卡）**: `scan_plugin` 扫 vet 本体
  （realpath 判定，非包名）时输出 `selfScan` 数据块 + 评分卡 Trusted/Review-required 卡——本体自扫从原始
  雷达式 116 Critical 呈现为 Trusted（已声明能力面 · 有界豁免），原始 findings 原样保留、可折叠展开。
  - ① 能力声明降级：危险 token（模块/出站目标/env/敏感路径/子进程）逐个对比声明清单，任一个未声明
    （出站非回环 host、未知 `process.env.*`、凭据/密钥路径、shell 管道、worker_threads·vm·cluster）→
    该 finding 保留原 severity（新增能力照旧 red）；检测规则数据/诱饵/文案/开发夹具按文件级豁免，仅
    pinned-match 生效。
  - ② 每版本产物钉扎：`vet-self-pins.json`（版本 → 扫描集 sha256，按版本发布不写死单 hash；升级同版
    不误报，字节不符任一发布钉扎 → 豁免失效按陌生人全扫）；扫描集 = 权威源码集（`src/report/self-scope.ts`
    排除 gitignore 非本体目录 lib/dsh-src/plugin-scan-tmp 等，跨机可复现）。
  - ③ 展示：`scan_plugin` 输出 `selfScan`（isTrustLayer/version/pin/verdict/staticScore/annotation），
    dsh.so 面板改走 vet 出口即得 Trusted 卡。
  - ④ 发布自扫门禁 `scripts/check-self-contract.mjs`（挂 `prepublishOnly`）：版本未钉扎 / 字节不符 /
    已使用但未声明的 decisive 能力 → 拒绝发布。
  Tests `test/self-scan.test.ts`（27）+ `test/self-pin.test.ts`（6）；端到端实测本体自扫 pinned-match+
  clean、325 findings 全分类（declared 128 / datasetRef 11 / devFixtures 186 / retained 0）。

### Changed

- **Structure refactor of the runtime guard (P0-4, zero behavior change)**: `src/guard/runtime-hooks.ts`
  (1011 lines) is now a public-API barrel over 8 focused submodules — runtime-ops (op tables & HookConfig/
  HookAlarm types), runtime-count (stream byte counters), runtime-heartbeat (hook brand + heartbeat),
  runtime-denoise (path sensitivity / lock-sibling / session-log / stack-tamper / vet-self-io passthrough),
  runtime-classify (classifyOp), runtime-attrib (pluginFromStack / isOfficial), runtime-net (network
  classification), runtime-patch (patchModule / patchNetworkModule). `src/guard/runtime-guard.ts`
  (762 → 492 lines) keeps the `installRuntimeGuard` assembly; the T1 sentinel lifecycle moved to
  `runtime-sidecar.ts` and the T2 alarm/ledger/canary/key-leak/forensics pipeline to `runtime-sink.ts`
  (`createT2Sink(status)`). All public symbols re-exported unchanged from the same module paths — no import-site
  changes; `rootIndexing`/`vetSelfIo` stay module-private, and the sidecar flags write via setters (ESM
  read-only imports). Regression: 35 files / 634 tests green.

- **Code-review batch (0.1.21, zero behavior change)**: `installRuntimeGuard` (380-line single function)
  split into three module-level assemblers — `installSidecar` (T1 spawn/stdout/respawn), `installT2`
  (T2 hooks + network egress patching, sharing rootIndex/sink/hookCfg in one scope) and
  `installHookHeartbeat` — leaving a 48-line assembly body; `validateContract` de-nested into
  `checkScope/checkFs/checkNetwork/checkSpawn/checkEnv/checkMeta` guard-clause sub-checks; five genuinely
  dead exports removed (`resetCapabilityDiff`, `CapabilityDiffStore.hasStatic/staticOf`,
  `ConfirmBlock.isFamily1Blocked`, `isGuardDisabled`). All findings from the full code review were
  verified first — the reported unused-imports and Shield components were false positives and kept.
  Regression: 37 files / 673 tests green.

### Fixed

- **Contract laxity check now rejects unreachable path patterns**: `isValidPathPattern` was written during
  M1 development but never wired into `validateContract` (which only used `isLaxPathPattern`), so
  home-glob (`~/data`), root (`/`) and relative (`./data`) path patterns passed validation while
  `patternMatchPath` could never match them against absolute runtime paths — a contract that silently
  explains nothing. The validator now uses `isValidPathPattern` (plus a new `./`-prefix rejection;
  previously only exact `./` was rejected). Contracts containing such patterns are rejected at load
  (N1 falls back to declared-vs-scanned) instead of loading as dead scope. Tests extended in
  `test/contract.test.ts` (29 cases).

- **Windows/macOS explicit platform gate for the T1 sentinel (P0-6)**: `spawnSidecar` now checks
  `sidecarSupportedOn(process.platform)` (Linux only) and skips spawning the sidecar on other platforms.
  Previously the sidecar would launch, fail its first `/proc/<host>/stat` read, exit 0, and the host would
  treat that as an unexpected exit and respawn it up to 5× with 5s backoff (≈6 wasted node spawns + a
  `t1:sentinel-down` alarm per watch-mode start). Now no sentinel is spawned, the `DSH_VET_SIDECAR_PID`
  env registry is cleared, and a single `info` log explains T1 is unavailable on this platform. In-process
  T2 hooks and the static layer are unaffected. `sidecarSupportedOn` is exported and unit-tested
  (Linux → supported; win32/darwin/freebsd/sunos/openbsd/aix → skipped) — makes the non-Linux degradation
  intentional instead of an accidental spawn-and-exit loop.

## [0.1.20] - 2026-08-20

### Added

- **Defense statistics panel**: shield panel now shows cumulative stats at the bottom — scanned plugin count, alarms recorded, blocked attempts. Lets users see "how much they've been protected". Persisted in `~/.dsh/vet/stats.json` (atomic write, 0600).
- **Startup file existence check**: if `guard/runtime-watch.js` sidecar is missing at startup, emits a red `vet-self-broken` alarm instead of silently degrading. Catches install corruption / accidental deletion (prepublish check catches pack omissions; this catches post-install damage).
- **Correlation detection (4 new alarm types)**:
  - **Key exfiltration content matching**: detects PEM private keys (`-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? PRIVATE KEY-----`) and AWS Access Key Ids (`(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`) in outbound network data (http/https/net/http2/tls + fetch + dgram). 100% confirmation of key exfiltration, not just "possible". AWS's documented never-valid example keys (containing "EXAMPLE") are excluded.
  - **spawn + network correlation**: detects when plugin spawns an exfiltration tool (curl/wget/nc/ncat/telnet — only such tools count) then connects to the same target via network within 10s window. Target hostnames are normalized (lowercased, port-stripped) on both sides, and only spawn-then-network ordering counts. Confirms exfiltration sequence.
  - **Write-then-delete correlation**: detects files written then deleted within 10s window (classic ransomware pattern: encrypt then delete original). Only genuine content writes (writeFile/appendFile/streams) count — copy/rename don't.
  - **High-frequency small file reads**: detects 5+ distinct small files (< 1KB) read within 10s window (credential hunting pattern: scanning ~/.ssh/ for keys). Re-reads of the same file don't accumulate.

### Changed

- **Alarm merge/dedup to cut event-storm noise**: correlation-signature alarms (n3-*, canary-leak, n3-key-leak) now collapse by (source, kind, pluginHint) ignoring target -- e.g. a plugin hitting 20 different hosts via spawn+network, or leaking 20 distinct keys, now shows one row with a count badge instead of flooding the 20-slot buffer. Per-file T2 hook alarms (fs-destroy, net, etc.) keep their precise per-target dedup. Merged rows accumulate count, refresh their timestamp, and take the higher severity. This directly reduces alert fatigue from a single plugin generating many distinct-target alarms of the same type. Shield panel now shows the xN badge.


- **esm-guard-coverage dedup**: ESM named import coverage alarm now fires only once per plugin per session (architectural limitation, repeated alerts = alert fatigue).
- **upgrade-cold linked to audit records**: cold-start alarm (`exec + network` combo) now suppressed if an audit record exists for that plugin version — user's audit effort has visible payoff.
- **Red upgrade-diff message**: high-sensitivity capability combo alarm now explicitly tells user to re-run `vet-audit-protocol` skill; message clarifies "alarm auto-dismisses after audit completes".
- **README upgrade guide**: added "Notable changes since 0.1.x" section summarizing major version changes (N1-N6, security hardening, bug fixes) so users don't have to read 7 CHANGELOG entries.

### Fixed

- **spawn + network red false positive (code review)**: the correlation formerly triggered on *any* spawn carrying an HTTP(S) URL in its args (e.g. a plugin spawning its own helper that points at its SaaS) followed by a connection to the same host — a legit integration pattern, reported as red. Spawn targets are now recorded only when the spawned command is an exfiltration tool (curl/wget/nc/ncat/telnet), and matching requires spawn strictly before network (no reversed-order `Math.abs`).
- **Key-leak detection gaps (code review)**: PEM/AWS content matching only reached http/https/net/http2/tls. `globalThis.fetch` and `dgram.send` paths (which already ran inline canary matching) never scanned for key formats — leaks via fetch/UDP were silently missed. Both now run the shared key-leak + canary scan.
- **spawn/net target normalization (code review)**: spawn targets were taken raw from the URL (case preserved, port included) while network targets were lowercased and port-stripped — the same host in different case or with a port never matched. Both sides now normalize via `URL.hostname` / `extractNetworkTarget`.
- **High-frequency read counted re-reads (code review)**: a poller re-reading the same small file inflated the counter; reads now dedupe by path within the window (only distinct small files count).
- **Copy/rename counted as write-then-delete (code review)**: `copyFile`/`cp`/`rename` then deleting the source (a legit move-by-copy) was counted as write-then-delete. Only content writes (writeFile/appendFile/streams) feed write-then-delete and write-amplify now.
- **suspected threshold scaling (code review)**: `markSuspected` (honeypot/canary confirmation) reduces mass-delete/rename/in-place/write-amplify thresholds but left the new high-freq-read and write-then-delete thresholds unscaled. Scaled via `suspectedFactor` now.
- **Empty key-leak test (code review)**: the "key exfiltration content matching" test never exercised detection — only asserted byte counters. Replaced with real `detectKeyLeak` unit tests (PEM variants, AWS match, EXAMPLE exclusion, negatives). Example keys constructed dynamically to avoid triggering secret scanners.
- **PEM key dedup by type, not by content (second review)**: all RSA keys from the same plugin were deduped as one alarm because the match was just the header (identical for all keys of the same type). Now PEM keys are hashed with 200 chars of surrounding context, so different keys in different requests get different alarms.
- **PEM + AWS in same text only reported PEM (second review)**: `detectKeyLeak` returned the first match only. Replaced with `detectKeyLeaks` that returns all matches (both PEM and AWS), so a request containing both key types reports both.
- **IPv6 spawn target mismatch (second review)**: spawn targets with IPv6 addresses had brackets (`[2001:db8::1]`) while net targets had no brackets (`2001:db8::1`), causing misses. Spawn targets now strip brackets to align with net side.
- **Test coverage gaps (second review)**: added 8 tests for `suspectedFactor` scaling (highFreqRead/writeThenDelete thresholds), `hashShort` collision resistance (different content → different hash, same content → same hash, base36 encoding), and fetch/dgram key-leak detection code path verification (via code review, not runtime integration test due to complexity).
- **n3-exfil lifetime yellow false positive (code review)**: n3-exfil yellow formerly fired whenever a secret had ever been read AND any network write occurred in the plugin's lifetime (cumulative counters) — so reading one env token at startup then doing any telemetry POST lit a permanent yellow. Now it only fires when the read→write gap is within the association window exfilAssocWindowMs (default 120s) but beyond the tight sequence-red window — a secret read followed by outbound data hours later no longer triggers. Sequence-red and magnitude-red are unchanged.
- **Strip internal mergeKey from status payload (code review)**: VetStatus.snapshot no longer serializes the internal mergeKey (used only for alarm aggregation) into /vet/status.json; the shield frontend never consumed it.
- **Unattributed key-leak no longer silently dropped (code review)**: recordKeyLeak used to return early on unknown attribution, so a leaked key with no plugin owner never surfaced. Now it records with an empty plugin hint and merges into a single row (consistent with canary-leak), so unattributed key exfiltration is still visible without flooding the buffer.
- **Defense stats no longer hit disk on every alarm (perf)**: incrementAlarmsRecorded/incrementScanned/incrementBlocked used to do a synchronous read-modify-write of stats.json on every call — and sink calls them on every fs/net hook event, i.e. directly in the hot path (event storm = per-op disk I/O). Counters now update an in-memory mirror and only persist on the 5s shield poll (getStats). This removes synchronous file I/O from the guard hot path and fixes the counter inflating on deduplicated alarms.

## [0.1.19] - 2026-08-20

### Fixed

- **rc.8 subpath entryName handling**: DSH rc.8 changed some plugin entryName format to include subpath (e.g. `@deepseek-ai/dsh-tool-subagent-control/list-agents`). VET's `resolvePackageRoot` couldn't resolve such names → `packageRoot === undefined` → `isExempt` returned false → spurious `audit-required` alarms. Added `extractPackageName` to strip subpath before resolution.
- **Unattributed session-log deletion silence**: DSH compresses/rotates `~/.dsh/sessions` logs (zstd removes `session.jsonl.zstd.xxx` shards) as high-frequency unattributed ops — every compression previously produced a yellow `fs-destroy` alarm, flooding real alerts. Now `fs-destroy + sessionLog + unattributed` is fully suppressed; attributed session-log deletion stays red (evidence destruction), unattributed non-session-log sensitive deletion (e.g. `.credentials.yaml`) still alerts.
- **DSH install-tree exemption widened to all profile layouts**: the `~/.dsh/**/node_modules/**` exemption regex previously matched only `profiles(?:/<name>)?` layouts. On machines where the profile dir sits directly under `~/.dsh` (e.g. `~/.dsh/web/node_modules/`), DSH upgrade reinstalling deps (`@joplin/turndown-plugin-gfm`, `@mixmark-io/domino`, …) triggered a flood of unattributed `fs-probe`/`fs-read` false alarms. Regex now matches `~/.dsh/(?:[^/]+/)*node_modules/` — per-profile, hoisted, and root layouts all exempt; real credential surfaces (`~/.dsh/.credentials.yaml`, `~/.dsh/sessions/**`) still alert.

## [0.1.18] - 2026-08-19

### Added

- **prepublish integrity check**: `scripts/check-pack-integrity.mjs` verifies all runtime dependencies (`resolveVetFile`/`resolvePkgRoot` calls) are included in `package.json` `files`. Hooked into `prepublishOnly` to catch missing files before npm publish.

## [0.1.17] - 2026-08-19

### Fixed

- **npm pack missing `lib/guard/`**: `runtime-guard.ts` uses `resolveVetFile('guard/runtime-watch.js')` to locate the T1 sentinel sidecar binary, but `package.json` `files` did not include `lib/guard/` — after `npm install @jieai/dsh-plugin-vet`, the sidecar file was absent and the runtime guard failed to start. Added `lib/guard` to `files`.

## [0.1.16] - 2026-08-19

### Security hardening (post-review batch — C1–C4 critical, M5–M9 major/minor, rule patches)

- **C1 — publish artifact hardening**: the host-side plugin is now published as a single esbuild bundle
  (`lib/index.bundle.js`); the `files` whitelist no longer ships `lib/{guard,guards,tools,audit,skills,
  config,invariant}`. All module-level guard state (`setRootIndexing`, `withVetSelfIo`, `confirmBlock`,
  `canaryStore`, `capabilityDiff`, …) is closure-private — a malicious plugin can no longer reach vet's
  internals via absolute-path `require` (previously verified reachable: full in-process T2/N7/N4/N1 disable,
  `confirmBlock.setMode('off')`, permanent `rootIndexing` blind). Tests still run against per-file `lib/**`;
  `test/bundle.test.ts` verifies bundle shape + closure privacy.
- **C2 — ESM named-import T2 blind spot made explicit**: Node's ESM↔CJS interop snapshots named exports, so
  `import { readFileSync } from 'node:fs'` bypasses all T2 hooks (empirically verified for fs, fs/promises and
  named network imports). The N1 manifest now flags `esmNamedBuiltins` for named/namespace imports of
  fs/fs·promises/child_process/http/https/http2/net/tls/dgram/worker_threads/vm; with `runtimeGuard: watch`
  the guard records a yellow `esm-guard-coverage` notice for such plugins (T1 sentinel + audit protocol remain
  the runtime defense — documented boundary, no silent coverage illusion).
- **C3 — cache & store env hardening**: `DSH_PLUGIN_VET_BASELINE_DIR` and `DSH_PLUGIN_VET_CACHE_DIR` are
  snapshotted at module load (vet loads before third-party plugins), so in-process tampering of
  `process.env` can no longer redirect the capability store, baseline or scanner cache (previously read
  dynamically per call — verified redirect). The scanner cache now verifies a host-injected per-process random
  nonce (stored with the entry, checked on read): an attacker who can compute the content-addressed cache key
  can no longer pre-seed a forged `clean` report into the deny path (verified forgery previously succeeded).
  Redirect is now explicit (`request.cacheDir`, test setters).
- **C4 — attribution tamper detection**: vet snapshots `Error.prepareStackTrace` at module load; when it is
  replaced (forged official frames) or `Error.stackTraceLimit` is dropped below 2 (hint-less → N7 skip,
  family-3/4 suppress), stack attribution is untrustworthy. Sensitive operations then emit a red
  `attribution-tampered` alarm (withholding attribution is itself an attack signal) and N7 family-2
  credential destruction still blocks via a sentinel identity (previously `hint === undefined` bypassed the
  only interception).
- **M5 — T2 ops surface**: added `symlink/link/chmod/chown/mkdir/mkdtemp/utimes/lutimes` (+Sync) to the
  write surface (symlink-target redirection, permission widening, `/etc/cron.d` placement were previously
  invisible) and `lstat/lstatSync` to the probe surface (symlink reconnaissance).
- **M6 — R9 fork-bomb**: `spawnSync/execSync/execFileSync` added to the in-loop spawn set
  (`while (1) { execSync() }` previously evaded R9-1).
- **M7 — vet-store tamper self-check**: capability and baseline stores keep an in-process hash of vet's own
  writes; a load whose content no longer matches (external overwrite by an in-process plugin — neutering
  upgrade-diff or poisoning the baseline) sets a flag surfaced as a yellow `vet-store-tamper` alarm on the
  next scan completion.
- **M8 — N6 sensitive-path matching**: `isSensitiveFsPath` now matches path *segments* (exact, or `-`/`.`
  bounded prefix/suffix) instead of substring — `my-credentials-manager`, `application-credentials-rotation.log`
  etc. no longer false-escalate to red (prefix hits like `shadow-utils` remain flagged, consistent with the
  T2 keyword semantics).
- **M9 — sidecar PID reuse protection**: before SIGTERM, the guard verifies `/proc/<pid>/cmdline` contains the
  vet-sidecar marker (Linux); on mismatch the kill is refused and a warning is logged — an exited sidecar whose
  PID was reused by another process is no longer killed.
- **Rule patches (ENGINE static-v11 → static-v12)**: R2 finds indirect/global eval forms (`globalThis.eval`,
  `window.eval`, `globalThis['eval']`, `(0, eval)`/`(0, Function)`) and folds `require('child' + '_process')`;
  R3 classifies `globalThis.process.exit/mainModule/…` by the same member policy as bare `process.*`
  (previously defaulted to info); R4 accepts `Reflect.defineProperty`; R9's ReDoS parser skips escaped
  parentheses in group-depth counting; R10 adds the npm `prepare` install hook; R14 adds python/ruby/perl
  `-c/-e` download-and-exec patterns; R15 recognizes `undici.request/stream/pipeline/upgrade`.

### dsh.so 静态注册站接入准备（scanner-only 集成）

- **R3 测试/CI 文件上下文降级**：`coverage.*`、`*.test.*`、`*.spec.*`、`*.e2e.*`、`vitest.*`、`jest.*` 及 `test/ tests/ spec/ specs/ __tests__/ scripts/ .github/` 目录内的 `process` 访问按能力触达面降 info（不进 verdict），与 bin/appShape/generic 同构，但比 pilot 的“全部降级”更精准——真实源码里的 `process.exit` 仍 critical（详见 `docs/integration-dsh-so.md`）。
- **R12 `scanBasis` 字段**：`ScanRequest` 新增 `scanBasis: 'git' | 'npm'`；git 基础上“声明入口文件缺失/无入口”降 info（构建产物通常不提交），npm 基础保持 high（发布物契约失败为真）；`scanBasis` 并入缓存 key，git/npm 结果互不污染。
- **`scan_plugin` 工具暴露 `capabilities`**：output schema 和 execute 返回值新增 `capabilities` 字段（N1 能力清单：hosts/fsPaths/spawnCmds/imports/hasNetwork/hasExec/esmNamedBuiltins），供门户/审计工具入库作能力索引；code 模式无文件上下文时不输出。

### Fixed: bundle-form 包根定位回归（C1 伴生，启动阻断）

- **症状**：main 切到打包版 `lib/index.bundle.js` 后（C1），按旧逐文件形态固定上溯两级的包根定位
  在 bundle 形态多上一级越出包根 —— `loadAuditProtocolContent` 读 `AUDIT_PROTOCOL.md` 直接 ENOENT，
  重启 DSH 启动失败；同类固定级数定位还潜伏在 `SELF_ROOT`（scan-plugin）、`SCANNER_BIN`
  （scanner/client）、T1 哨兵 sidecar 路径（runtime-guard）三处。
- **修复**：新增 `src/pkg-root.ts` —— `resolvePkgRoot` 向上搜索 package.json 定位包根、
  `resolveVetFile` 按候选目录存在性（lib/ → 根 → src/）解析包内资源，形态无关；4 处调用点全部迁移，
  两个函数支持注入解析起点（回归测试用）。
- **回归测试**：`test/pkg-root.test.ts` 覆盖 bundle 形态（lib/index.bundle.js → 包根，不再越出）、
  逐文件形态、resolveVetFile 的三级候选回退。

### Fixed: 代码审查 17 条核实修复（0.1.16 批次）

- **#1-3 过时文档**：package.json description、runtime-hooks/runtime-guard 模块注释原写
  「alarm-only / 绝不拦截」——N7（0.1.14 起）confirmBlock 默认 block，族 1/2 确认破坏即抛错拦截。
  已改为「默认报警；N7 确认破坏类 fs 操作（族 1/2）抛错拦截」。
- **#4 fetch(Request) 网络出口盲点**：`fetch(new Request(url, init))` 此前在 extractNetworkTarget
  无分支 → classify/台账/金丝雀全失明。新增 Request 实例（含 .url 对象）目标提取，出口回到观测面。
- **#5 scripts/ 白名单过宽**：scripts/ 目录多为产品代码（CLI/构建脚本），其中 process.exit 不应降级。
  isTestOrCiFile 移除 scripts/（保留 test/tests/spec/specs/__tests__/.github 与文件名模式）。
- **#6 缓存 key 整读大文件**：cacheKey 曾对所有文件 readOrDefault（含超 8MB 将被 R8-skip 的大文件）；
  改为 stat 先行、超限文件以尺寸标记参与 key，避免散列阶段内存峰值。
- **#7 dgram.send 字节计数**：形态 1（msg,offset,length,port,address）此前计整块 buffer；按 length 切片计。
- **#8 OSV ↔ upstream-radar 跨源去重**：两处各用各的 seenVuln → 同一 CVE 报两条（OSV 与 OSV-T）。
  现共享去重集合；并新增 radarImpl 注入点（测试用，与 fetchImpl 同款）。
- **#9/#12 正则提为模块常量**：isSensitivePath 的 ~/.dsh/profiles 豁免、isSessionLogFile 会话目录/
  扩展名正则从每次调用内联改为模块级常量（高频路径）。
- **#10 credentialFiles 记忆化**：decideBlock 高频路径不再每次重建 11 元素数组 + homedir()，按 HOME 缓存
  （HOME 变化自动重算，测试注入安全）。
- **#11 README_ASSIGNED 重命名**：改为 isReadDataOp（原名误导为 README 文件相关）。
- **#13 KEYWORD_REGEX_CACHE 上限**：超 512 清空，防异常增长无界缓存。
- **#14 generateYamlFromObject 单次解析**：同一 existingContent 不再二次 yaml.load。
- **#15 upstreamRadarWarned 可重置**：导出 resetUpstreamRadarWarned()（进程内测试状态隔离）。
- **#16 allocFinding NaN 防护**：非有限值跳过歧义 finding（Infinity ≥ LIMIT 仍正确告警）。
- **#17 open flags 复合形态**：识别 wx+/ax+/as+/rs+/rs（旧 `^[rwax]+?$` 漏复合 → 写意图按读报）。
- **回归测试**：新增 #4 fetch(Request) / #5 scripts / #6 大文件 R8-skip / #8 跨源去重 / #17 复合 flags。

### Security review scope

Full code review (three deep-dive passes + manual empirical verification): scanner static engine, runtime
guard layer, storage/governance. 51 new tests (533 total); coverage still above the 70/50 thresholds
(Lines 83.9% · Branches 83.7% · Functions 91.2%).

## [0.1.15] - 2026-08-19

### Added

- **N5 dynamic-string provenance (NEXT-GEN-PLAN)**: "deliberately built so the static layer cannot
  see the target" is itself a signal (G1 complement to N2). New static rule **R15**
  (`scanner-bin/rules/dynamic-targets.ts`) inspects network sinks — `fetch` / `new WebSocket` /
  `http(s).request|get` (incl. `require('http').request`) / `net.connect|createConnection` — and flags a
  target argument that cannot be statically resolved to a string (`stringyValue` + N2 `tryDecodeLiteral`
  both fail) as **info/heuristic**: "网络目标动态构造，静态不可审计（N5）". The N1 manifest cannot name
  this runtime target, so runtime observation is the only evidence (N1's hidden-capability red alarm is the
  escalation; R15 stays at info per the v2 "escalate only when stacked" policy). Noise controls:
  http(s) options-object form and unresolved plain identifiers there are skipped (ambiguous with the options
  form), fetch/WebSocket first args and net host args are URL/string by contract so unresolved identifiers
  flag; one finding per call site; resolvable targets (literal/constant concat/static template/N2-decodable)
  are never flagged. **ENGINE_VERSION static-v10 → static-v11** (rule-set change; old disk caches invalidate),
  R15 added to RULE_IDS.

- **N6 upgrade behavioral diff (NEXT-GEN-PLAN)**: version-aware capability tracking — the supply-chain
  blind spot "poisoning lives in the diff between old and new versions" (G4). Every auto-scan now records the
  N1 capability manifest per `name@version` into `~/.dsh/vet/capabilities.json` (0600, atomic write, LRU
  keeps the most recent 1000 versions by recordedAt; reuses the content-baseline store infra, same env
  override for tests).
  - On upgrade (a different version of the same package is scanned), the new manifest is diffed against the
    previous recorded version (chosen by recordedAt, no semver parsing): newly added hosts/fsPaths/spawnCmds/
    imports or a gained network/exec capability → yellow `upgrade-diff`; a new high-sensitivity combination
    (exec+network / sensitive-path+network / sensitive-path+exec) → red. Removed capabilities are audit-only,
    never alarmed (narrowing is benign). Cold start (first install) records only; a new manifest declaring
    exec+network double-high gets a yellow `upgrade-cold` notice instead of silence. Same-version
    re-installs refresh recordedAt without diffing; missing version/manifest or storage corruption → no-op,
    fail-open (never disturbs plugin loading).
  - New `vet_diff` tool (registered alongside `scan_plugin`): read-only, purely local — prints a package's
    stored version history and the behavior changelog between its last two recorded versions (added|removed
    hosts/fsPaths/spawnCmds/imports, network/exec flips) for pre-upgrade review and audit.
  - Wiring: `internal/plugin` auto-scan completion (`src/guards/internal-plugin.ts`) → `recordScan`
    (`src/guard/version-diff.ts`); alarms via VetStatus with kind `upgrade-diff`/`upgrade-cold`.
  - Fully offline and alarm-only; the diff compares *declared* manifests only (runtime-hidden/dependency-carried
    capability changes remain covered by N1 hidden-capability + N2 decoding, documented boundary).

## [0.1.14] - 2026-08-19

### Added

- **N3 exfiltration & destruction ledger (NEXT-GEN-PLAN)**: a per-plugin runtime ledger
  (`src/guard/exfil-ledger.ts`) fed by an optional observe channel on the T2 wrappers (near-zero overhead
  when unwired) — never inspects session/chat content, only bytes + operation shapes.
  - Byte counters (lifecycle cumulative): sensitive-path reads (actual result/chunk lengths) and writes to
    non-allowlisted hosts (counted on the request object write/end, incl. streams); both > 0 → yellow
    `n3-exfil`; magnitudes within [0.4×, 3×] (≥512B) → red `n3-exfil-match` (whole-package exfil).
  - Sequence signatures (30s read→action window): READ_SECRET → SPAWN(curl|wget|nc) and READ_SECRET →
    NET_WRITE → red (`n3-seq-read-spawn` / `n3-seq-read-net`).
  - Destruction signature family (10s sliding window): MASS_DELETE / MASS_RENAME_EXT (encryption-marker
    rename) / IN_PLACE_OVERWRITE (read→write same path) / WRITE_AMPLIFY → yellow; two+ families together →
    red `n3-ransom`. node_modules/.git/build outputs, atomic-write locks and transient temp files are
    noise-skipped; conservative thresholds (miss > false-positive); `markSuspected()` (honeypot/canary
    confirmation, N4) lowers a plugin thresholds.
  - Idle ledgers pruned on the VetStatus TTL cadence; alarm-only, never intercepts.
- **N4 canary watermark & integrity canaries (NEXT-GEN-PLAN)**: honeypot lure values now embed one unique
  high-entropy canary (40-hex, keyword-free — preserves the anti-honeypot guarantee); the active set lives in
  memory only. Network wrappers scan URL (once per request) and body text (per chunk, cross-chunk accumulation,
  64KB tail cap); dgram/fetch/spawn are scanned too, with direct / URL-decode / one base64-decode matching
  variants. A canary found outbound → red `canary-leak` (100% exfil confirmation) and the plugin is marked
  suspected in the N3 ledger. Integrity canaries (`ensureIntegrityCanaries`, ~/.dsh only) place two marker
  files (fixed content + self sha256); write/delete → red kind `integrity` — earliest ransomware trigger
  on the profile/credentials surface, backstop to the N3 destruction signatures. Canary sharding/reassembly
  is a documented out-of-scope boundary.

- **N7 confirmation block (NEXT-GEN-PLAN, the only interceptor)**: wrapper-level interception of
  irreversible destruction only (`src/guard/confirm-block.ts` + wiring in `runtime-guard.ts`/`runtime-hooks.ts`).
  - Families 1/2 (default `block`): family 1 — after a certain destructive confirmation (N3 `n3-ransom`
    signature combination / integrity-canary write-delete / N4 canary leak) the plugin's destructive fs ops
    (write/unlink/rename/cp/truncate/createWriteStream, incl. Sync) throw; family 2 — single-shot immediate
    block of credential-body deletion and overwrite-to-existing (exact files: ~/.ssh/id_*, ~/.dsh/.credentials.yaml,
    ~/.aws/credentials, .pgpass, .netrc, .git-credentials, .npmrc). Every block throws an actionable message
    and writes a red `n7-block` alarm.
  - Families 3/4 (default `alarm`): `classifyOp` flags persistence/privilege-surface writes
    (bashrc/cron/systemd/ld.so.preload/sudoers.d/profile.d/autostart/authorized_keys/hosts/ssl) → yellow
    `persistence-write` and supply-chain/install-state writes (node_modules package files, cordis.patch.yml /
    cordis.yml / plugin.json) → yellow `install-write`; copy-pair ops check both source and destination.
    Explicit `confirmBlockFamily3/4: block` upgrades a family to intercept (user opt-in, still never on
    appendFile/new-file writes).
  - Zero-false-intercept guards: official attribution / unattributed ops / vet self IO never blocked, exact
    file-level credential matching, fail-open decision path (any internal error passes the call through),
    process-memory blocked set (restart clears; config changes need restart). `confirmBlock` mode
    (`block`/`alarm`/`off`) + family overrides in `src/config.ts`; T2 classification tests updated for the
    more specific kinds (node_modules write → `install-write`, authorized_keys/cp-to-/etc/hosts →
    `persistence-write`).

## [0.1.13] - 2026-08-19

### Added

- **N1 cross-layer capability diff (NEXT-GEN-PLAN)**: the scanner now produces a per-package capability
  manifest (`ScanReport.capabilities` — hosts/fsPaths/spawnCmds/imports/hasNetwork/hasExec, declaration-side
  facts only, conservative over-collection, module-binding aware: fs/child_process bound via import/require
  incl. destructuring). `internal/plugin` auto-scan registers it at load time; the T2 sink diffs each
  sensitive runtime observation (net-egress/spawn/fs-read/fs-write/fs-destroy/fs-probe) against it — an
  observed sensitive action with zero static footprint (incl. imports) is a **hidden capability** → red
  `n1-hidden` alarm (confidence certain). Imports non-empty conservatively covers any action (capability
  unknown, never-alarm bias). Dormant capabilities are recorded for the future nutrition label (M2).
  Engine version bumped to `static-v10` (cache invalidated).
- **N2 literal decode preprocessor (anti-obfuscation)**: `scanner-bin/decode.ts` statically decodes
  all-literal base64 (`atob`, `Buffer.from(…, base64)`), hex, `String.fromCharCode`, constant
  concatenation and static template strings (≤4KB, ≤2 nesting layers, never executes code, dynamic args →
  undefined) and feeds the decoded corpus back into R13 (exfil endpoints), R7 (hardcoded secrets) and R11
  (sensitive paths) with unchanged rule predicates — hits carry `decodedFrom` + original line for audit.
- **Scan concurrency cap (tech-debt repayment)**: the host-side scanner client now limits concurrent scanner
  subprocesses to 2 (FIFO queue) — bulk plugin loads at first boot no longer spawn unbounded processes.
- **Large-file precheck (tech-debt repayment)**: the engine stats each source file before reading and skips
  files > 8MB with an R8-scan-skipped info finding instead of loading them whole.

## [0.1.12] - 2026-08-18

### Fixed

- **Top-level DSH install tree exemption (fs-probe false-positive flood)**: the install-tree exemption
  regex `/\/.dsh\/profiles\/[^/]+\/node_modules\//` required a profile-name segment between
  `profiles/` and `node_modules/`, so the top-level hoisted tree
  (`~/.dsh/profiles/node_modules`, the pnpm workspace root layout) did not match and fell through to
  the `.dsh` sensitive segment — every DSH restart/plugin-tree re-resolve replayed
  realpathSync(package.json) on top-level `@deepseek-ai/*` packages and flooded the shield with ~20
  (unattributed) fs-probe yellow alarms. The regex now uses an optional segment
  (`(?:\/[^/]+)?`) covering both per-profile (`profiles/<name>/node_modules`) and top-level
  (`profiles/node_modules`) trees. Real credential surfaces (`~/.dsh/.credentials.yaml`,
  `~/.dsh/sessions/**`) and `~/.ssh/node_modules/x` remain fully sensitive — the exemption only
  applies under `.dsh/profiles`. Regression assertions added for isSensitivePath and classifyOp
  (realpathSync/realpath/statSync → no alarm).

## [0.1.11] - 2026-08-18

### Added

- **P-5 official-package content-hash baseline**: SHA-256 content hashes for `@deepseek-ai/*` packages
  compared against a baseline to catch package-name forgery. Baseline storage supports multi-version
  coexistence (key = `name@version`), resource limits (1000 files / 50MB / 10s timeout) against DoS, and
  atomic writes against concurrent corruption. New `contentBaseline` config option (enabled by default).
- **Marketplace scan gate (vet-gate)**: new `runGate()` programmatic API plus a `vet-gate` CLI, callable
  from installer flows such as `dsh-plugin-hub`. Default `mode: report` (alarm-only), OSV off by default
  (second-level feedback), timeout scales with file count. New `bin` and `exports` fields.
- **Runtime network egress observation**: wraps http/https/net/http2/tls/dgram/fetch to observe
  plugin-initiated network requests. Sensitive hosts (webhook.site, requestbin.com, ngrok.io, etc.) → yellow;
  sensitive ports (4444, 5555, 6666, 7777, 1337, 31337) → red. dgram special-cased (instance-method
  wrapping). New `networkEgress` config option (enabled by default).
- **R10 transitive dependency graph**: new `transitiveDeps` config option (off by default) calling the
  upstream-radar CLI to scan the transitive dependency tree. Local installation probed via `createRequire`
  (no npx); OSV-T rule severity lowered to medium (transitive attack surface < direct); silent downgrade with
  a first-run warn when upstream-radar is not installed.

### Changed

- **Baseline hashes use relative paths**: `computePackageHash` uses `relative(packageRoot, fullPath)`
  instead of absolute paths so the same package installed at different paths hashes identically (cross-machine
  consistency).
- **Baseline hashes support binary files**: file contents read as Buffer to avoid utf8 corruption of binary
  data.
- **Byte-order sorting**: baseline files sorted with `<` / `>` instead of `localeCompare` for
  cross-platform consistency.
- **Red alarm on mismatch**: an official-package hash mismatch now records a red alarm via
  `status?.record()` so users know an official package may have been tampered with.

### Fixed

- **Symlink detection**: `computePackageHash` uses `lstatSync` instead of `statSync` to correctly detect
  and skip symlinks.
- **ESM compatibility**: `content-baseline.ts` imports `mkdirSync` directly instead of
  `require('node:fs')`; `engine.ts` uses `createRequire` instead of `require.resolve`.
- **dgram.send argument shapes**: both forms (`msg, port, address` and `msg, offset, length, port,
  address`) supported, extracting the target port/address correctly.
- **upstream-radar output validation**: `Array.isArray(radarResult.vulnerabilities)` guard added so
  unexpected output shapes don't crash the scan.
- **saveBaseline directory**: uses `dirname(baselinePath())` instead of a hardcoded path so the
  `DSH_PLUGIN_VET_BASELINE_DIR` env override keeps directories consistent.
- **Deep security-review fixes (true positives)**: `http.get`/`https.get` are standalone exports whose
  internal calls bypass `module.exports.request` patching — `'get'` added to the patched network ops;
  the OSV network phase is now bounded by a time budget derived from the host request timeout, with
  per-query timeouts narrowed dynamically (remaining / remaining targets), so scans always finish before the
  host kills the subprocess.
- **Alarm panel UI rework**: dismissed alarms moved out of the main shield panel to the bottom of the alarm
  panel — flex two-column layout with collapsible sections and a thin scrollbar; active alarms get more
  visual space.
- **Dependency upgrade**: `@deepseek-ai/*` dependencies rc.6 → rc.7.

## [0.1.10] - 2026-08-17

### Added

- **Crystal Edge borders**: top highlight line on all panels and cards, stronger glass feel
- **Mirror Sheen hover effect**: two-layer gloss (diffuse → focused) on hover
- **Minimal White style**: light mode uses white-on-black design with softer blue-tinted text
- **Alarm detail panel**: standalone alarm detail popup with expand/collapse and copy
- **Instant theme switching**: MutationObserver watches theme changes, no polling delay

### Changed

- **Translucent glass**: light mode at 20% opacity with a grey base for a clearer look
- **Unified card style**: all cards share the same gradient background and top highlight
- **Code review cleanup**: removed dead code (parseLuma/linearize), extracted constants to avoid duplication

### Fixed

- **Theme detection**: light mode no longer incorrectly renders as dark UI
- **isDark()**: now checks the `body[data-ds-dark-theme]` attribute, more accurate

## [0.1.9] - 2026-08-17

### Fixed

- **Session log rotation noise fix**: `isSessionLogFile` now also recognizes sharded session files (e.g. `session.jsonl.zstd.9a3`, `session.jsonl.zst.001`) under `~/.dsh/sessions/**`. An **unattributed** session-log deletion is downgraded from red `fs-destroy` to **yellow** (host self-maintenance cannot attack itself); the `sessionLog` hint still displays. An **attributed** deletion stays red (possible evidence destruction by a plugin).
- **Attribution-layered messaging**: Unattributed alerts now use independent suggest messages (e.g., "Check why there is an unattributed sensitive path deletion") instead of implying plugin responsibility. Session log rotation scenarios have dedicated hint messages.

## [0.1.8] - 2026-08-17

### Added

- **R13 network-exfil**: static detection of hardcoded exfiltration sinks in string literals — Discord/Telegram/Slack webhooks, cloud-metadata endpoints (169.254.169.254 / metadata.*.internal / 100.100.100.200) and .onion destinations. high/likely → suspicious.
- **R14 non-js-scripts**: deterministic text scan of shipped shell/PowerShell/batch files (.sh/.bash/.ps1/.cmd/.bat) for download-and-exec primitives (curl|sh, wget|sh, encoded PowerShell -enc/IEX, certutil/bitsadmin/mshta/regsvr32/rundll32). high (plugin) / info (generic); client source enumeration now includes script extensions.
- ENGINE_VERSION bumped to static-v8 (rule set change → cache invalidation).

### Fixed

- **R13/R14 case-insensitive matching (round-8.1)**: PowerShell/cmd commands are case-insensitive, but R14 patterns only matched lowercase (`IWR`/`iex`/`CERTUTIL -urlcache` leaked). R13 host patterns were also lowercase-only. All affected patterns now carry the `/i` flag, and rule regexes propagate their original flags into the runtime matcher (previously `new RegExp(source, 'g')` silently dropped them).
- **R14 `curl -o` download-only downgraded to medium**: writing a file to disk is not execution — it no longer flips the verdict to suspicious by itself. ENGINE_VERSION bumped to static-v9.

## [0.1.7] - 2026-08-17

### Fixed

- **DSH install tree false positive exemption**: `isSensitivePath` previously flagged
  `~/.dsh/profiles/<name>/node_modules/**` paths as sensitive because the `.dsh` segment triggered
  the sensitive match before the `node_modules` exemption break could execute. This caused false positives
  during plugin loading when `require.resolve` triggered `realpathSync` on package files (e.g.,
  `electron/install.js`, `dsh-traffic-light/package.json`). Now paths matching `/.dsh/profiles/<name>/node_modules/`
  are exempted entirely — these are platform-installed public dependencies, not credential probes. Real
  credential surfaces (`~/.dsh/.credentials.yaml`, `~/.dsh/sessions/**`) remain protected.
  Regression test assertions +4 (250 total cases).

## [0.1.6] - 2026-08-17

### Fixed

- **Improved YAML write robustness (object-based generation)**: v0.1.5 added validation to reject bad YAML
  before writing, but this left users with an error message and no clear path forward. v0.1.6 replaces the
  string-concatenation approach entirely with object-based generation: parse existing file → manipulate JS
  object → regenerate with `js-yaml.dump()`. Bad input files are auto-repaired (with user-visible message).
  Comments are lost but stability is guaranteed — users never need to manually fix broken config files.

## [0.1.5] - 2026-08-17

### Fixed

- **YAML write crash prevention (object-based generation)**: `writeRuntimeGuardConfig` previously composed
  `cordis.patch.yml` by string concatenation — if the user's existing file had unusual structure (e.g. `---`
  document separators, non-standard indentation), the composed output could be invalid YAML. DSH parses this
  file on every boot; invalid YAML crashes the process (`YAMLException: end of the stream or a document
  separator is expected`).
  
  Now uses `js-yaml.load()` to parse the existing file into a JS object, manipulates the object (add/remove
  vet entries), and regenerates with `js-yaml.dump()`. This guarantees valid YAML output regardless of the
  input file's structure. If the existing file is already corrupted (unparseable), it's auto-repaired with