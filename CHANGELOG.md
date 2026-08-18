# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

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

- **Session log rotation false positive reduction**: fs-destroy red alerts now recognize compressed/log files (.zst/.zstd/.jsonl/.log) under `~/.dsh/sessions/**`, but rotation hints only display when unattributed (pluginHint is undefined) to avoid misleading users. Attributed session log deletions still treated as plugin malicious actions (real evidence destruction).
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