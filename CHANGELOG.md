# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

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
  a user-visible message. Comments are lost but stability is guaranteed — users never need to manually fix
  broken config files.
  
  Added `js-yaml` as a runtime dependency for the object-based generation layer.
  
  Regression test +1 (250 total cases).

## [0.1.4]

### Fixed

- **round-7.2 (minified-bundle verification, 2 semantic false positives fixed)**:
  - R2: `new n.constructor(n.type, n)` (React event system cloning event objects) false-positived as high —
    checkNew's constructor branch now routes through isConstructorCapture: the base must be an arrow/function
    literal to count as true capture (object-clone/factory shapes no longer alarm; true capture
    `new (async()=>{}).constructor('return process')` stays critical).
  - R9: `outer: for(;;) { for(...) { break outer } }` false-positived as an exit-less loop — exitSignals now
    understands labeled-break exit semantics: a label bound to a labeled statement wrapping the current loop
    (an ancestor of the loop body) counts as an exit signal; a label bound inside the loop (`break inner`)
    does not, so true infinite loops still alarm.
  - ENGINE_VERSION static-v6 → static-v7 (rule change → old caches invalidate).
  - Regression tests +6 (249 total cases).
- **Windows test environment**: the sidecar singleton-lock integration test (D30) depends on /proc; on Windows
  that path is absent, so the first tick exits gracefully (exit 0) and the assertion always fails — now skipped
  per platform (`skipIf(win32)`); still runs as-is on Linux/CI.

### Docs

- All documentation translated to English for international users: README.md (Chinese original kept as
  README.zh.md), AUDIT_PROTOCOL.md, CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, docs/ARCHITECTURE.md.
  `README.zh.md` added to the npm `files` allowlist.
  - Restored Known Limitation 16 (platform support: Linux-first, graceful degradation) in the English README.md
    - the en rewrite dropped it while README.zh.md kept it; the two docs now stay in sync.

### Build / release

- `exports["./client"]` gains a `types` condition: build-client also emits a hand-written `lib/client.d.ts`
  (kept in sync with `inject`/`apply` in src/client/index.ts), so browser-half integrators get type hints.
- The `files` allowlist now includes `docs/ARCHITECTURE.md`: the architecture link in the npm package README no
  longer breaks (it was only reachable on GitHub before).
- Added GitHub Actions CI (.github/workflows/ci.yml): on push/PR runs typecheck + coverage-threshold tests +
  `npm pack --dry-run` artifact verification.

## [0.1.3]

- **round-7.1 (0.1.2 external verification, 5 feedback items)**:
  - R3 read-only member classification (P-1/P-2): `cwd`/`env`/`platform`/`pid`/`argv`/`execPath`/`stdout`/
    `nextTick`/`on` and other pure read-only / side-effect-free members downgrade to info capability surface in
    plugin mode (reading cwd/env/pid isn't an escape channel) — the 134 cwd/env/platform false positives on
    dsh-bridges-class no-bin MCP/tool plugins that depend on @deepseek-ai/* are gone; wechat-mp's cacheFile +
    pid + .tmp atomic-write temp names no longer get hurt. Side-effect members (`kill`/`abort`/`chdir`/`umask`/
    `setuid`/`dlopen`/`binding`, etc.) and unknown members stay high; `exit`/getBuiltinModule/mainModule/module/
    reallyExit stay critical — no loss of escape detection.
  - R4 prototype pollution no longer downgrades by targetKind (P-3): pollution semantics are unrelated to
    plugin/generic package (a generic package can also be installed into the host as a plugin); files mode is
    always high; core-js-class polyfill false-positive risk is limited (polyfills usually live in node_modules
    dependencies, outside the scan surface).
  - detectTargetKind self-exemption via realpath (P-3 security surface): vet's self-exemption used to compare
    names only — local file: installs have no registry validation, so a malicious tarball naming itself
    @jieai/dsh-plugin-vet could fool the generic downgrade (R3/R4 fully downgraded, deny passes). It now must
    realpath-verify that the target is the current vet instance; a same-name impostor is judged by the
    strictest plugin rules (identity impersonation = highest suspicion), together with R4 no longer
    downgrading, closing that attack surface.
  - P-4 re-verification: vet's self-scan 2 R9 medium self-hits (constructor-chain.js/dynamic-exec.js rule
    regexes) no longer trigger on the 0.1.2 engine (covered by the round-7 group-then-`?` fix); tarball
    verified with no R9 medium; static-v6 invalidates any old cache.
  - P-5 recorded: judging official @deepseek-ai/* packages as generic with capability-surface downgrade is part
    of official trust (same policy as the internal/plugin guard); a supply-chain attack on an official package
    would let static downgrade mask process access — recorded in README Known Limitations 8.
  - All with regression tests (+5, 243 total cases); ENGINE_VERSION static-v5 → static-v6.
  - Known Limitations 15 (evaluation feedback): keeping process.kill high is intentional (side-effect member);
    MCP/bridge-class plugins killing their own spawned children are ruled out manually by the agent during
    review — distinguishing kill(child.pid) from arbitrary pids needs dataflow analysis; high cost, low
    benefit; kept as-is.

## [0.1.2]

- **round-7 (second external evaluation round, all 4 feedback items generalized-fixed)**:
  - R2 `new (Function)('...')` parenthesized-callee bypass: a parenthesized callee (incl. the parenthesized
    base of `(async()=>{}).constructor`) was previously treated as a plain expression and fully bypassed
    (adversarial sample verdict=clean) — checkCall/checkNew/isConstructorCapture now uniformly strip parens
    (unwrapParens); `new (Function)('return process')` and friends hit critical.
  - R4 host-global prototype pollution: override assignments of prototype members on host builtins
    (Object/Array/String/Function/TextEncoder/URL/Buffer and 40+) were previously undetected — added the three
    forms (assignment / Object.defineProperty / whole-object replacement), code → critical / files plugin →
    high / generic (possible polyfill) → info.
  - P2 OSV range false positive: directDepsOf stripped `^`/`~` before isExactVersion, so `^2.4.2` was queried
    as an exact lower bound — false-known-vulnerability when the lower bound is affected but the upper bound is
    already fixed (actually installed 2.8.x), inflating the verdict. Ranges now always skip the query (matching
    the README claim); exact versions query as-is.
  - R9 `(https?:)?`-class false positive: group-then-`?` (at most one extra branch) is linear backtracking, not
    `(a+)+`-class exponential — only group-then-`*`/`+` is judged ReDoS (dsh-wechat-mp markdown.js verified
    fixed).
  - R3 app-type downgrade: packages whose package.json declares bin (CLI/TUI/server, where process is the
    product function) downgrade process access wholesale to info capability surface; bin entry files (CLI
    scripts that always run standalone) judge as generic code (R2/R3 downgraded, R9 dead loops → medium) —
    dsh-tui's 4065 and dsh-bridges' 2100 score deductions were all false positives.
  - R6 obfuscation combined evidence: charCodeAt/fromCharCode/atob appearing alone is normal terminal-protocol
    parsing / byte handling (dsh-tui's 42 were all false positives) — only when the same file has a dynamic
    execution signal (eval/new Function/vm, etc.) is the obfuscation hint emitted.
  - R9 bounded traversal recursion: for-of/for-in collection traversal and self-calls inside conditional loops
    (while(cond)/do/for(;cond;)) are no longer crudely judged "non-terminating recursion" (zeroLayoutRecursive
    tree-traversal false-positive fix); while(true)/for(;;) still judged.
  - Engine package-shape parsing: the engine reads package.json's bin field to produce cliFiles (bin entry
    basename set) + appShape (app-type), injected into the RuleContext; package.json content is already inside
    the cache hash, so shape changes invalidate naturally.
  - All with regression tests (+13, 238 total cases); ENGINE_VERSION static-v4 → static-v5 (rule changes must
    bump it).

## [0.1.1]

- **round-6 (second regression-test round) fixes**:
  - R1 new-form bypass: `new (globalThis.constructor.constructor)('return process')()` and `const c = ...; new c(...)`
    were fully bypassed — added a NewExpression branch; the callee supports property/bracket-access chains and
    const-alias binding tracking; all forms hit critical.
  - Cache-version poisoning: rule changes didn't bump ENGINE_VERSION (static-v3 unchanged) → the old disk cache
    was hit by the new engine and returned old-rule results (247 stale results in practice); bumped to
    static-v4, cache key and validReport validation invalidate together, added a regression test (old-version
    caches must invalidate).
  - R9 ReDoS disjoint-alternation judgment: `((?:[^']|'')*)` branches' first characters are disjoint (non-quote
    vs. double-quote) → linear, not reported; `(a|aa)+` branches overlap → still reported.
- **Install docs added (round-5 evaluation feedback)**: README install section adds a local tarball install
  example (`dsh plugin add` with a local tgz + file: protocol fallback note + manual unpack mount-entry
  example), and notes the first install into a large profile may take several minutes (pnpm full resolution /
  lockfile update / supply-chain validation — not vet's own overhead).
- **round-5 (external DSH evaluation) fixes**:
  - R1 bracket-access-form bypass: `x["constructor"]("return " + "process")` was previously fully bypassed
    (verdict=clean) — one of the most common malicious forms; now both dot-access and bracket-access forms plus
    concatenation/template/const-bound static arg evaluation all hit critical.
  - R3 signal-handling false positive: process.on/once('SIG*') registration and process.exit inside signal
    callbacks (graceful shutdown) are normal for resident MCP servers, downgraded to info (not into verdict);
    bare process.exit (error paths, etc.) stays critical.
  - R5 ctx.logger false positive: officially injected cordis services (heavily used by dsh-mcp-client, etc.)
    added to the allowlist, no longer reported as medium.
  - R9 ReDoS false-positive rewrite: the old regex treated a leading `?` modifier on a group `(?:x)?` as a
    quantifier, misreporting all single-optional groups as medium — switched to a functional judgment (top-level
    quantifier inside the group + quantifier after the group both count); real `(a+)+` ReDoS still reported.
  - All with regression tests (+7, 225 total cases).
- **Build hygiene: stale lib/ residue cleanup**:
  - Added a clean step before build (rm -rf lib, then compile) — previously, compiled artifacts of deleted
    sources lingered in lib/ and shipped in the tgz (session-events.js, tools/audit-plugin.js, 6 abandoned
    modules under audit/ as js + matching d.ts, old LLM-audit-tool compat shells); after the cleanup the
    tarball dropped from 83 to 66 files, and vitest.config.ts removed two coverage excludes pointing at the
    abandoned files.
- **round-4 review fixes (open-source prep)**:
  - R12 nodeMajorBelow22 single-digit-major bypass: the old implementation assumed a two-digit major
    (two=s[0]+s[1]), so 4.0.0 / 8.17.0 / 2.0.0 / 6.0.0 / 9.0.0 / 3.x / 5.5.0 all missed the hint — now parses
    the numeric-prefix major and compares to 22, and supports a `v` prefix (v18.0.0).
  - R12 pickEntry adds two legal forms: the exports string form (legal in Node) was previously skipped → no
    main + no root index.js produced a medium false positive; the exports conditional object now includes the
    `node` condition (DSH runs on Node; the node condition is the most common) — the old list only had
    import/require/default/types.
  - P2-2 fix gap: nearestPackageRoot's existsSync probe wasn't wrapped in withVetSelfIo — scanning
    non-node_modules files under ~/.dsh produced unowned fs-probe self-alarms; now wrapped straight through
    (aligned with detectTargetKind/listSourceFiles/readPackageVersion).
  - budgetMs removed the DSH_PLUGIN_VET_SCAN_BUDGET_MS env override: a large value bypasses host-timeout
    alignment and makes R8-skip unreachable again (subprocess killed → deny fail-closed false block); tests
    control the budget via a timeoutMs parameter.
  - Lockfile switched to the official npmjs source: all package-lock.json resolved URLs regenerated from
    registry.npmmirror.com to registry.npmjs.org (with full integrity), npm ci smoke-verified clean install of
    137 packages.
- **Pre-open-source self-check (dogfood, verified)**:
  - Honeypot-lure R7 self-hit fix: lure prefixes (sk-/AKIA) switched to constant concatenation, so template
    concatenation text is no longer judged high by its own R7 — the shipped artifact self-scans clean (was
    suspicious); reinstalling vet in deny mode no longer locks itself; regression test added.
  - esbuild declared as a direct devDependency (previously a fragile transitive of vitest).
  - README numbers/wording synced: case count 189→214; Known Limitations #8 rewritten to the OSV status quo
    (exact-version queries, silent network-failure downgrade, can be disabled).
  - Removed 19 references to a PLAN.md that no longer exists in the repo; .gitignore gains *.tgz (npm pack
    output).
- **Three-round review fixes + audit-protocol extension (P-2 plan items landed)**:
  - P2-1 scan budget vs host timeout mismatch: the engine budget used to be unbounded files×2s, so 15+/31+ file
    packages in deny/report got killed by the host before R8-skip triggered → false scan-fail (deny fail-closed
    would block legitimate large packages). The request now carries the host's planned timeout
    (protocol.timeoutMs); engine budget = min(files×2s, timeout-1.5s) — R8-skip always precedes the kill, so
    graceful degradation is structurally reachable; scan_plugin's tool timeout uses the same formula as
    internal/plugin (scaled by file count, capped at 60s).
  - P2-2 vet self-check IO not covered by vetSelfIo: archive.hasAuditRecord's readdir of ~/.dsh and
    scan_plugin's listSourceFiles/detectTargetKind reading user paths produced unowned fs-probe self-alarms
    under the .dsh sensitive segment — all pass through withVetSelfIo (same as the shield polling).
  - P2-3 cross-module duplicate install + 5s respawn-window race silently killed monitoring: the exit handler
    now logs a warn + yellow t1:sentinel-taken-over when decideRespawn=false and env points at a live pid —
    handover is observable, not silent.
  - P3-1/P3-3 OSV exact-version only: `*`, `>=`, `^` and version-less main packages skip the query
    (isExactVersion character judgment), eliminating stale range/full-history false positives.
  - P3-2 lastScan gains a TTL (24h, reuses alarmTtlMs): one suspicious scan no longer turns the shield
    permanently yellow; sustained scanning renews naturally.
  - P3-4 file target-identity: when the parent directory has a package.json, detectTargetKind runs (plugin-file
    escape judgment is no longer always generic).
  - P-1 record exact-version binding: the requireAudit gate matches records against the installed version
    (internal/plugin resolves the root package version early) — after a plugin upgrade the old record no longer
    authorizes the new version; re-audit required.
  - New rule R12 (Cordis/DSH bundle contract): missing declared dsh.bundle.patch / missing entry file → high
    (suspicious); no entry (no main/exports and no index.js) → medium; plugin-intent package missing name →
    medium; engines.node major < 22 → info. Deterministic manifest checks; non-plugin-intent packages aren't
    judged.
  - scan_plugin output adds pluginVersion (for record/version checks); AUDIT_PROTOCOL adds step 4.5 "contract
    & code-quality audit" (error handling/synchronous blocking/resource leaks/async correctness/lifecycle
    hygiene and hot-reload idempotence) + a quality section in the record template + the conclusion matrix gains
    the quality dimension (statically clean but host-dragging defects → review).
  - P3-5 recorded (not a problem): readHostMetrics fully scans /proc children every 5s poll — overhead scales
    linearly with the number of children; acceptable at current magnitudes, left for later on-demand
    caching/de-bursting.
  - False-positive fix (shield-tested): atomic-write protocol-lock (`<file>.lock`) delete/write exemption —
    DSH writes `~/.dsh/.credentials.yaml` via dsh-atomic-write (wx-creates a sibling lock file holding only the
    PID, finally deletes the lock after writing), so every credential save triggered an unowned fs-destroy red
    false positive; the lock file isn't the credential itself, so single-path write/delete is no longer
    sensitive (credential body and cp/rename dual-path semantics unchanged).
- **Second-round review fixes (all 14 items verified and handled)**:
  - P1-1 `guardDisabled` asymmetric reset: off→watch transition never started the sentinel — the watch branch
    now resets it at the start (the fresh-spawn branch used to return directly after the check, with no log).
  - P1-2 T1 reuse-mode alarm loss: reusing the old sentinel = the new instance had no stdout pipe, so all T1
    alarms went into the abandoned VetStatus — now clears env + terminates the old sentinel + spawns fresh (new
    pipe, new listeners).
  - P1-3 `rootIndexing` flag leak: when attribution construction (loader.entries()/ctx.baseUrl) threw, the flag
    stuck forever → all T2 alarms silently bypassed — the whole construction is now in try/finally, and the
    wrapper try/catches attribution failures (alarms stay, unowned; fs calls never interrupted).
  - P2-4 ring-buffer replace semantics: an out-of-window resend of the same id first removes the old copy then
    enqueues — sustained alarms no longer fill all 20 slots (inflated alarmCount, crowding out other alarms).
  - P2-5 M5 half-implementation: clean results no longer get a `\n\n` prefix (previously polluted
    machine-readable output even with empty notes).
  - P2-6 `~/.dsh` sensitive segment: config-root reconnaissance (readdir/stat/config reads) was fully
    invisible — added to the sensitive segment; paired with full-class official-attribution noise reduction
    (platform-body high-frequency IO doesn't spam) + vet self-IO pass-through (withVetSelfIo, shield polling
    doesn't self-alarm).
  - P2-7 deny synchronous freeze: OSV network query removed from the synchronous path + timeout capped at 30s
    (previously scaled by file count to 60s + OSV 4s; timeout still fails closed against scan-avoidance).
  - P2-8 vet entry-match rule unified: strip/extract/read used inconsistent trim vs. top-level alignment —
    indented nested entries were misread / not stripped; now only top-level matches.
  - P3-9 enable-branch indentation reuse: writing runtimeGuard no longer hardcodes 4 spaces; reuses the
    original config indentation (non-4-space configs no longer produce corrupt YAML).
  - P3-10 OSV dependency tree: check surface extended from the plugin itself to direct dependencies (cap 8,
    official packages skipped, independent timeout, silent downgrade).
  - P3-11 README sync: cordis_run carries no code payload, so the guard slot is dormant (kept as a placeholder
    slot); the interception claim was removed; M5 behavior synced.
  - P3-12 auth boundary recorded: dismiss/restore do same-origin validation (alarm-only display layer; recorded
    in the README).
  - P3-13 judgment: keep deny scan-failure fail-closed (M9 scan-avoidance), OSV moved off the deny synchronous
    path (network jitter no longer affects it); trade-off recorded in README/CHANGELOG.
  - P3-14 cleanup: osv.ts stale comments synced, data/code-index.sock working residue deleted, render.ts
    trailing newline added.
- **Lifecycle gap-fill (Cordis convention)**: T2 hooks and the T1 sentinel are global resources (fs/
  child_process monkey patches + sentinel subprocess) that were only cleaned up on re-apply — fully removing the
  entry leaked them until process exit. apply now registers a disposer via `ctx.effect` (runs on cordis fiber
  unmount; verification found `ctx.on('dispose')` isn't in cordis's typed event surface and failed to compile,
  so effect mounting is used); the disposer is idempotent (belt-and-braces with prevGuardDisposer).
- Open-source release prep: MIT license, CONTRIBUTING/SECURITY/CODE_OF_CONDUCT, public architecture document,
  npm metadata.
- False-positive fixes (two, empirically verified):
  - T2 fs-destroy: toolchain temp-artifact exemption — tsc incremental compilation builds `<src>.<pid>.<uuid>.tmpdir`
    next to sources (`*.tmp`/`*.temp`/`*.swp`, etc.) and deletes them as it goes; the secrets in their names are
    just source filenames being compiled; the trailing temp suffix doesn't participate in sensitive-word
    judgment, parent segments still judged (`~/.ssh/config.bak` still alarms).
  - T1 growth: the measurement span must cover the full window — an early-window transient spike (274MB in the
    first 20s) is no longer labeled "10-minute sustained growth, suspected leak".
- New feature: per-alarm dismiss/restore — each alarm in the panel can be "dismissed" (no longer counts toward
  shield level or count; the record stays and can be "restored"; a dismissed alarm auto-expires once the alarm
  stops, so a recurrence is visible again; shares the alarm store's lifecycle, resets on restart).
- **R31 crash fix (watch-mode crash, actually recursive stack overflow)**: T2 alarm attribution (rootIndex
  traversing 100+ plugin roots) ran its own fs probes through the wrapped fs → sensitive package names
  (dsh-credentials / dsh-token-meter, etc., 4041 recursion levels in practice) alarmed again → attribution →
  infinite recursion → per-level regex rebuild → V8 RegExpCompiler stack exhaustion, a false OOM process crash.
  Fix: set a pass-through flag during attribution; the wrapper passes through the original fs to break the
  recursion; segmentHasKeyword regexes cached per keyword. The guard flag is module-private (hanging it on
  globalThis would hand a malicious plugin the key to blind all of vet).
- **A9 self-harm fix (user-reported)**: both root causes of T2 mis-attributing vet itself as the alarm source:
  - Attribution excludes vet: the wrapper frame (runtime-hooks.js) is always the top of the alarm stack, so when
    vet's root was in the attribution map, every host/unowned alarm got pinned on @jieai/dsh-plugin-vet
    (in practice: fs-probe realpathSync(...@deepseek-ai/dsh-credentials-local/package.json) attributed to
    @jieai/dsh-plugin-vet). Now the attribution map excludes vet — alarms still fire but attribute to the real
    caller (official package / unowned).
  - node_modules package-directory exemption: package names/inner files are public artifacts; names containing
    credential/secret words are normal ecosystem (12 installed in practice: @aws-sdk/credential-provider-*,
    @deepseek-ai/dsh-credentials(-local), etc.) — host module resolution (require.resolve's internal
    realpathSync/stat of inner package.json) and vet's own scan reads both touch them at high frequency, and
    they all previously false-positived as fs-probe. Path segments after node_modules no longer do sensitive
    matching; segments before node_modules still judged (~/.ssh/node_modules/x still hits); under mutate,
    system-root prefixes (/usr, etc.) still apply.
  - rootIndex attribution map built once and cached: previously rebuilt per classified fs call (N×require.resolve),
    amplifying to CPU spin during alarm storms.
- Installability verified and corrected against the DSH official bundle contract:
  - peerDependencies aligned to the DSH 0.1.0-rc.6 version family (the old `^0.0.1-rc.1` didn't match the
    actually installed versions — pure luck that it worked).
  - Added `prepublishOnly`: forces a build before publish, so lib/ (incl. the client bundle) can't be missing
    or stale.
  - Cleaned internal comments in cordis.patch.yml pointing at the deleted PLAN.md.
  - End-to-end simulated a fresh-user install through the full chain: `dsh plugin --profile <name> add <tarball>`
    → reconcilePlugins recognizes `dsh.bundle` → loadProfile resolves the bundle layer → composeEntries mounts
    the vet entry → client-registry conditions (`dsh.client`/exports["./client"]/inject edges) all satisfied.

## [0.1.0] - 2026-08-16

First releasable version.

### Added

- Static scan engine (scanner-bin): R1-R11 rule set, deterministic verdict, scoring model, content-hash cache,
  OSV known-vulnerability check (version-filtered).
- Target-identity grading (targetKind): DSH plugin packages judged strictly; ordinary npm packages downgraded to
  capability surface — 195 official packages, zero false positives.
- `scan_plugin` tool: dynamic-code / package / file scan targets; the verdict comes only from the static layer.
- `vet-audit-protocol` skill: agent-guided plugin review protocol (AUDIT_PROTOCOL.md), health-record on-disk
  convention.
- `requireAudit` audit gate: loading a third-party plugin without a record → report alarms / deny blocks
  (record-prefix anti-forgery).
- `tools/execute` guard: pre-execution code scan of cordis_define / cordis_run / run_code / workflow.
- Runtime guard (`runtimeGuard: watch`, alarm-only):
  - T1 sentinel: sidecar /proc monitor (memory/children/fd/growth window), singleton lock against hot-reload
    stacking, auto-restart on unexpected exit.
  - T2 hooks: wrap fs / fs.promises / child_process; sensitive-path operations/reconnaissance/destructive
    commands/honeypot touches alarm; stack attribution to the plugin package name.
  - Honeypot lures: fake keys in an unobtrusive location, anti-honeypot design (no keywords), 0700/0600
    permissions, idempotent self-heal.
- GUI shield: session-header status light (green/yellow/red + count badge), alarm panel, live metrics,
  one-click guard toggle (takes effect on restart), Morandi dual theme.
- Alarm aggregation: ring buffer + per-id dedup + TTL expiry (24h) — one false positive never turns the shield
  permanently yellow/red.

### Fixed

- Sentinel respawn dead code (env was deleted before the comparison, always false) — monitoring now recovers
  after a crash.
- Report-mode scan synchronously blocked the event loop — switched to an async subprocess; large packages no
  longer freeze the host.
- T2 alarm id lacked pluginHint, letting alarms across plugins swallow each other.
- fs.open treated the first-arg path as flags (open('auth.txt','r') false-positived as a write).
- exec destructive commands (rm -rf ~/.ssh, etc.) and sensitive-path redirection missed.
- Scan cache key lacked targetKind/runtime, cross-context contamination.
- OSV query without a version false-positived already-fixed versions.
- R7 hardcoded-secret whole-segment placeholder false kill (real key mixed with example missed).
- R11 fsBase used startsWith('fs'), hurting custom objects like fsmap.
- R2 eval/Function lacked a shadowing check; factory-injected require in nested functions false-positived.
- Honeypot file permission 0644 readable on the same machine (tightened to 0600/0700).

### Security

- Scanner is a separate subprocess; AST read-only, never eval'd; malicious input can't affect the host.
- Scan failure in deny mode fails closed (block + alarm, no silent pass).
- Cache strict-shape validation against local forgery.
- Strict record-naming regex against prefix forgery.