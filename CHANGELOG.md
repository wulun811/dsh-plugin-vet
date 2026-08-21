# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [0.2.4] - 2026-08-21

User-reported regression fixes (@dsh-traffic-light scan-fail alarm):

### Fixed
- **Restore `typescript` runtime dep (0.2.3 regression)**: the round-3 "zombie dep" call missed scanner-bin/** (14 files import it); prod-only installs crashed the scanner at startup → scan-fail on every plugin. Reproduced on a clean install; fix verified the same way. Bumped to 0.2.4.
- **Readable scanner-crash diagnostics**: name the missing dependency from stderr instead of a bare JSON parse error; async + spawnSync paths.

### Added
- **Bare-import closure gate**: shipped lib/** may only import declared deps or node builtins (react/react-dom exempt: host-provided). Would have blocked the 0.2.3 release; gated in vitest + prepublishOnly.

## [0.2.3] - 2026-08-21

Output of the full round-3 review (each fix has a regression test):

### Fixed (user feedback: host housekeeping denoise)
- **Denoise unattributed alarms on DSH web temp artifacts**: atomic-save housekeeping (`.name.json.<pid>.<uuid>.tmpdir` lstat+rmdir) flooded red/yellow alarms. Now exempt when unattributed + untampered; plugin-attributed, sensitive, non-temp, honeypot/integrity and credentials/sessions surfaces still alarm.

### Fixed (round-5 review additions)
- **Pack-integrity closure check was silently idle**: `\\.{1,2}` in a regex literal matches a literal backslash, not an escaped dot → zero matches, check printed "✓ all closed". Fixed regex + added a self-check probe + vitest gate.

### Fixed (round-4 review additions)
- **vet_label could crash on malformed capability records**: missing fields became undefined after JSON round-trip, piercing the `=== null` guard (same family as the DSH.SO bug). Now null/undefined both checked, sections render empty on non-arrays; latest/note tightened too.
- **Tarball member pre-check missed backslash members**: '..\\..' is inert in GNU tar but Windows bsdtar treats backslashes as separators. Pre-check now rejects them (npm pack normalizes, zero false-positive risk).

### Fixed
- **Scanner concurrency cap ineffective**: the queue path never updated activeScans, so pump drained the whole queue at once (measured peak 7 vs cap 2). Queued tasks now account and pump.
- **upstream-radar resolvable from the scanned package tree (isolation break)**: a planted fake could be exec'd inside the scanner. Resolution now stays inside vet's own tree, with defense-in-depth rejection.
- **Tarball reconciliation hardening**: `-tzf` member pre-check before unpack (no absolute/`..`/drive paths); dist.tarball host pinned to the registry origin.
- **vet_label / vet_diff crash on single-version records (DSH.SO bug)**: null fields were dropped by execute and came back as undefined past the `!== null` guard. Both render guards now check null/undefined.

### Changed
- **Removed unused runtime dep `typescript`** (build-time tsc only). [Reverted in 0.2.4 — the grep missed scanner-bin/**]

## [0.2.2] - 2026-08-21

### Fixed
- **npm files whitelist missed loose dirs (release blocker)**: lib/tools, lib/audit, lib/guards, pkg-root.js, invariant.js etc. weren't shipped → ERR_MODULE_NOT_FOUND on load. files now ships all of lib; relative imports closed everywhere.
- **fetch(Request) body blind spot (round-2 #1/#6)**: body inside Request bypassed all three observation channels. Request is cloned and observed async now; string and Request bodies share the same scans.
- **Hot-path sync disk IO (round-2 #2)**: dismissal persistence read the file on every record(). Now an O(1) in-memory cache.
- **saveDismissed hardcoded dir (round-2 #3)**: now derived from dirname(DISMISSED_FILE).
- **fetch wrapper lacked C4 tamper detection (round-2 #5)**: tamper + sensitive egress now raises attribution-tampered red like other modules.
- **Forensics files grew unbounded (round-2 #10)**: filenames now rotate per session (<plugin>-<ts>.jsonl).

### Changed
- **Peer ranges to ^0.1.1-rc.1 (DSH 0.1.1 compat)**: semver prerelease rules made ^0.1.0-rc.8 unsatisfied; API verified identical.
- **Cached wildcard regexes (round-2 #4)**: patternMatchPath no longer compiles per call.
- **Pack-integrity checks expanded**: relative-import closure in lib/**, bin/exports reachability, ship-set boundary (no src/scripts/test/scanner-bin/*.ts), hard error on missing files entries. Enforced in prepublishOnly.

## [0.2.1] - 2026-08-21

### Added
- **N3 key-exfil attribution grading**: unattributed hits downgraded to yellow "needs human triage" (drop "100% confirmed"); attributed stays red; canary hits unaffected.
- **Capability extraction denoise**: hosts shape validation; bare-literal fsPaths tightened; hasExec gating; Function("return this") exempt.
- **baseline-mismatch reworked**: async npm registry reconciliation — byte-equal = stale baseline (auto-refresh, yellow); different = red confirmed; unreachable = fail-closed red. New `acknowledged-package-hashes` config for legitimate local edits (one-time yellow, transparent).

### Fixed
- N3 unattributed false positives: secret-shaped text in host docs/sessions is normal; shape hit ≠ exfiltration proof.
- Capability extractor noise: bundled helpers (fork/exec) tripped upgrade-cold; comments/error text/relative refs leaked into fsPaths; template fragments into hosts.
- baseline-mismatch misdirection: reinstall/local patches looked like tampering. Registry reconciliation + hash registration fix both.

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

- **M1 contract wired into runtime T2 sink / N1 diff (P0-5, plan-A record stage)**: with config
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

- **Self-scan trust annotation — vet scanning vet**: scanning vet itself (realpath-based) returns a `selfScan` block + Trusted scorecard instead of a raw Critical radar; findings stay visible.
  - (1) Declared-capability downgrade: undeclared dangerous tokens keep severity; rule data/decoys/fixtures exempt only on pinned-match.
  - (2) Per-version pinning: `vet-self-pins.json` maps version → scan-set sha256; byte mismatch voids exemptions.
  - (3) `scan_plugin` returns selfScan (isTrustLayer/version/pin/verdict/staticScore/annotation); dsh.so shows the Trusted card.
  - (4) Release gate `scripts/check-self-contract.mjs` on prepublishOnly: unpinned/mismatched/undeclared-decisive → publish refused.
  Tests: self-scan (27) + self-pin (6); end-to-end: pinned-match clean, 325 findings all classified (declared 128 / datasetRef 11 / devFixtures 186 / retained 0).

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

### dsh.so static-registry integration prep (scanner-only)

- **R3 test/CI downgrade**: `process` access in coverage.*/test/spec/etc. files → info (capability touch), like bin/appShape; `process.exit` in real source stays critical.
- **R12 `scanBasis`**: `'git' | 'npm'` — git: missing entries downgrade to info; npm: stays high. Joins the cache key.
- **`scan_plugin` exposes `capabilities`** (N1 manifest) for portal/audit indexing.

### Fixed: package-root resolution regression in bundle form (C1 fallout)

- **Symptom**: fixed two-level root walk overshot the package root after bundling → ENOENT on AUDIT_PROTOCOL.md, DSH failed to boot; the same pattern lurked in SELF_ROOT, SCANNER_BIN and the T1 sidecar path.
- **Fix**: `src/pkg-root.ts` — resolvePkgRoot walks up to package.json; resolveVetFile probes candidate dirs; all 4 call sites migrated.
- **Tests**: test/pkg-root.test.ts (bundle form, per-file form, fallback).

### Fixed: 17 verified code-review findings (0.1.16 batch)

- **#1-3 stale docs**: "alarm-only / never intercepts" → N7 blocks families 1/2 by default; reworded.
- **#4 fetch(Request) egress blind spot**: Request instances now extracted onto the observation surface.
- **#5 scripts/ whitelist too broad**: process.exit in scripts/ no longer downgrades.
- **#6 cache key hashed huge files**: stat-first now; oversized files join the key by size marker.
- **#7 dgram.send byte count**: sliced by length.
- **#8 OSV ↔ upstream-radar dedup**: shared dedup set; radarImpl injection point added.
- **#9/#12 regexes hoisted to module constants** (hot paths).
- **#10 credentialFiles memoized** (per HOME).
- **#11 README_ASSIGNED renamed** to isReadDataOp.
- **#13 KEYWORD_REGEX_CACHE bounded** (≤512).
- **#14 generateYamlFromObject parses once**.
- **#15 resetUpstreamRadarWarned() exported** (test isolation).
- **#16 allocFinding NaN guard**.
- **#17 open flags composites**: wx+/ax+/as+/rs+/rs recognized.
- **Regression tests**: #4/#5/#6/#8/#17.

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
  both fail) as **info/heuristic**: "network target dynamically constructed — not statically auditable (N5)". The N1 manifest cannot name
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