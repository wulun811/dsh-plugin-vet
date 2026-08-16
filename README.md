# @jieai/dsh-plugin-vet — Trust pipeline for DSH plugins

English | [中文](README.zh.md)

[![npm version](https://img.shields.io/npm/v/@jieai/dsh-plugin-vet)](https://www.npmjs.com/package/@jieai/dsh-plugin-vet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D22.19-339933)](package.json)
[![dsh.so security](https://www.dsh.so/badges/dsh-plugin-vet.svg)](https://www.dsh.so/artifact/dsh-plugin-vet/)

> Before installing any plugin, run it through dsh-plugin-vet: static rules produce a verdict (deterministic,
> unforgeable), the agent investigates sensitive points and quality issues following the `vet-audit-protocol`
> skill (no one can substitute for that), and a final scorecard is handed to a human/model to decide.
>
> **Positioning: a monitoring alarm, not an enforcer.** vet only does "check → alarm → advise": checks at
> write time (static scan), watches at run time (runtime guard), and surfaces alarms (scorecard + GUI shield
> status light). **vet never acts on your behalf** — it never auto-uninstalls, never kills processes, never
> rewrites configs; deny mode is an explicit opt-in by the deployer and is not part of the product identity.
> The final disposition is always decided by the user on their own DSH.

@jieai/dsh-plugin-vet is the **trust-layer plugin** in the deepseek-harness ecosystem: it occupies the whole
**download → scan → audit → score → decide → runtime watch** trust pipeline. The runtime watch ships built-in
**honeypot lures**: anyone quietly rifling through key files gets caught red-handed (opt-in, `honeypot.enabled`).
It does **not** provide a plugin marketplace itself (catalog/distribution).

- 📚 Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 🧾 Audit protocol: [AUDIT_PROTOCOL.md](AUDIT_PROTOCOL.md)
- 🛡️ Security policy: [SECURITY.md](SECURITY.md)
- 🤝 Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Installation

```sh
dsh plugin --profile <profile> add @jieai/dsh-plugin-vet
```

Install-and-activate chain: pnpm install → `reconcilePlugins` reads `dsh.bundle` → on next start `loadProfile`
resolves the bundle and mounts the plugin. Default configuration is in the Config section below
(fail-open: reports only, never blocks).

**Local tarball install** (offline or verify-before-release scenario):

```sh
dsh plugin --profile <profile> add ./jieai-dsh-plugin-vet-0.1.4.tgz
# or unpack directly into the profile's node_modules:
# tar -xzf jieai-dsh-plugin-vet-0.1.4.tgz -C ~/.dsh/profiles/<profile>/node_modules/@jieai/
// and add an insert mount entry in the profile's cordis.patch.yml:
//   - insert:
//       - id: plugin-vet
//         name: '@jieai/dsh-plugin-vet'
//         config:
//           mode: report
//           autoScan: true
```

> Paths / relative paths / URLs all work (`dsh plugin add` falls back to pnpm's `file:` protocol; a local tgz is
> resolved directly).
>
> **First-install time note**: the first `dsh plugin add` into a large profile can take several minutes — during
> that time pnpm does a full dependency resolution, updates the lockfile for 500+ packages and runs supply-chain
> policy validation over the whole dependency tree (vet itself carries only 2 runtime dependencies; the bulk of
> the time is parsing/validating the profile's existing tree, not vet). Subsequent installs/updates take seconds
> (validation results are reused).

> **Compatibility**: vet targets DSH 0.1.0-rc.6+ (peer range `^0.1.0-rc.6`). pnpm may warn about unmet peer
> dependencies — this is expected: profile templates set `autoInstallPeers: false`, and at runtime the packages
> resolve from the DSH install closure (`$DSH_HOME/profiles/node_modules` fallback layer); you neither need nor
> should install another copy of the cordis family in the profile.

> **Watch scope = the profile vet is installed into.** vet's guards are in-process events
> (`internal/plugin`) — whichever profile vet is installed into is the one whose loaded plugins it guards.
> For multi-profile deployments, install vet into every profile you want guarded
> (`dsh plugin --profile <name> add @jieai/dsh-plugin-vet`) and point `requireAudit` at the matching profile's
> cordis.patch.yml.

## Config (cordis.yml)

| Key | Default | Description |
|---|---|---|
| `mode` | `report` | `report` reports only, never blocks; `deny` explicitly enables blocking |
| `autoScan` | `true` | Automatically static-scan new plugins (`internal/plugin`) |
| `scannerTimeoutMs` | `15000` | Static-scan subprocess timeout |
| `requireAudit` | `false` | Audit gate (opt-in): when enabled, loading a new plugin checks `~/.dsh/vet/audits/` for a health record — without one, `report` mode logs a yellow `audit-required` alarm, `deny` mode blocks. Records are written to disk by hand by the agent following the `vet-audit-protocol` skill |
| `rules` | `{}` (all on) | Per-rule switches (R1-R12) |
| `denyOn` | `critical` | Blocking threshold in `mode: deny` |
| `allowlist` | `[]` | Package/plugin-id allowlist (skip scanning) |
| `runtimeGuard` | `off` | Runtime guard (performance/stability cost, opt-in): `off` = disabled; `watch` enables the T1 sentinel + T2 hooks, **alarm-only** |
| `runtimeIntervalMs` | `2000` | T1 sentinel /proc sampling interval |
| `runtimeMemLimitMb` | `2048` | T1 memory alarm threshold (host VmRSS, over limit → red) |
| `runtimeForkBurstN` | `5` | T1 child-process burst alarm threshold (single-round delta → red) |
| `runtimeFdLimit` | `512` | T1 file-descriptor alarm threshold (→ yellow) |
| `runtimeGrowthMb` | `256` | T1 sustained memory-growth alarm threshold (**net RSS growth over the full window** → yellow, suspected leak; an early-window spike does not count as window-level sustained growth, so no false positive) |
| `runtimeGrowthWindowMs` | `600000` | Growth-detection window (default 10 minutes) |
| `honeypot.enabled` | `false` | Honeypot lures (needs `runtimeGuard: watch`): plants fake key lures in `honeypot.dir`; T2 reports touches (read/write/delete) of lure paths as a separate `honeypot` alarm class. Directory/file names and contents carry no honeypot keywords (anti-honeypot), default location `~/.dsh/.local`, lure values are well-formed but invalid fake credentials |
| `honeypot.dir` | `''` | Lure directory; empty = `$HOME/.dsh/.local` |
| `osvCheck` | `true` | Query Google OSV for known vulnerabilities when scanning package.json (**exact-version queries only**: ranges (`*`/`>=`/`^`/`~`) and version-less main packages are skipped, P3-1/P3-3 — avoids stale full-history false positives; since round-7 ranges are no longer stripped to query as exact lower bounds). Verified targets = the plugin itself + direct dependencies (cap 8, official `@deepseek-ai/*` packages skipped, P3-10); transitive trees exceed the OSV v1 scope and the scan budget. Default on sends package names to api.osv.dev; network failure degrades silently. Set false if privacy-sensitive |

Official `@deepseek-ai/*` packages are exempt by default (built-in trust).

## Tools

- **`scan_plugin`** — deterministic static scan: `target` = `dynamic-code` (source string) / `package` (package
  directory) / `file` (single file). Returns a scorecard (verdict + staticScore + findings). The verdict is
  produced only by static rules.
- **`vet-audit-protocol` (skill)** — audit-process protocol (`AUDIT_PROTOCOL.md`): the agent audits a new plugin
  in preset steps — scan_plugin static criteria (incl. R12 Cordis/DSH contract) → read manifest/source →
  verify each finding → proactively dig deeper (network/files/processes/credentials/library semantics) →
  **contract & code-quality audit** (step 4.5: entry/Config-schema consistency, error handling/synchronous
  blocking/resource leaks/async correctness and other "badly written" issues — statically clean ≠ worth
  installing) → hand-write a health record to `~/.dsh/vet/audits/<plugin>-<version>-<ts>.md` using the system
  write capability. vet ships no audit tooling and does not investigate for the agent — it only provides the
  criteria and the on-disk convention.

## Automatic behavior

- **`internal/plugin` auto-scan** (`autoScan: true`): newly installed third-party npm packages are
  static-scanned on load; `deny` mode + verdict ≥ `denyOn` → load rolled back.
- **Audit gate** (`requireAudit: true`): loading a third-party plugin without a health record — `report` mode
  logs a yellow `audit-required` alarm (enters the /vet/status.json alarm list, plugin loads normally); `deny`
  mode rolls back the load (references `vet-audit-protocol` as a prompt to audit first). **Records match by
  exact version** (P-1): after a plugin upgrade the old version's record no longer authorizes the new version —
  re-audit is required to clear the alarm/block.
- **`tools/execute` interception**: `cordis_define` / `run_code` / `workflow` are scanned before execution
  (`cordis_run`'s real schema carries no code payload, so the guard slot stays dormant — P3-11 synced);
  `report` mode prefixes non-clean results with `VET:` (clean executions don't pollute machine-readable
  output), `deny` mode blocks outright (isError).
- **Runtime guard (`runtimeGuard: watch`)** — alarm-only:
  - **T1 sentinel**: a sidecar subprocess reads the host /proc every `runtimeIntervalMs`
    (VmRSS / child-process count / fd count) and streams alarm JSON lines back to the host → shield turns
    yellow/red.
  - **T2 hooks**: in-process wrappers around fs / child_process (incl. fs.promises); dangerous operations
    (sensitive-path writes/deletes, key-file reads, subprocesses with shell/download/exfiltration keywords,
    honeypot-lure touches, `~/.dsh` config-root reconnaissance) are attributed via the stack to the plugin
    package name before alarming; official packages get full-class noise reduction via attribution (capability
    grant — official packages are the platform itself; their high-frequency `~/.dsh` session/config/storage
    reads don't spam; third parties can't forge attribution). **Never blocks a call.** Self-harm exemptions
    (fixed after real-world false positives):
    - **node_modules package-directory exemption**: package names/inner files are public artifacts — package
      names containing credential/secret words are normal ecosystem (`@aws-sdk/credential-provider-*`,
      `@deepseek-ai/dsh-credentials-local`, etc.), and both host module resolution (require.resolve's internal
      realpathSync/stat of inner package.json) and vet's own scan reads touch them at high frequency, so they
      no longer false-positive as fs-probe; path segments before node_modules still judged normally
      (`~/.ssh/node_modules/x` still hits .ssh), and write/delete of system roots (/usr etc.) still alarms.
    - **Attribution excludes vet itself**: the wrapper frame is always the top of the alarm stack, and the vet
      root never participates in attribution mapping — host/unowned alarms are no longer pinned on vet (the
      alarm still fires, attributed to the real caller).
    - Toolchain temp artifacts (tsc `<src>.<pid>.<uuid>.tmpdir`, `*.tmp`, `*.temp`, `*.swp`, etc.) are
      auto-exempt — the secrets/credentials in their names are just source filenames being compiled; deleting
      them is cleanup, not destruction; parent segments still judged normally (`~/.ssh/config.bak` still
      alarms).
- **GUI shield**: a browser half registers into `conversation.session.header.actions` and polls
  /vet/status.json to show a green/yellow/red light + alarm count. Activation requires a `dsh web` restart
  (client-modules only scans the `dsh.client` declaration at startup).
  - Interaction: **clickable** — clicking expands the alarm panel (**live metrics**: memory/CPU/I-O/
    child-process/fd; **guard status**: when off, one click writes a `runtimeGuard: watch` config (takes
    effect on restart); **alarm list** with severity/attribution/**per-item advice**; recent-scan echo,
    refresh, updated time), outside clicks close it; when alarms exist a count badge appears next to the
    shield (green/yellow/red theme color, light/dark adaptive).
  - **Per-item dismiss**: each alarm can be "dismissed" — display-only (no longer counts toward shield level
    or count), the record is kept and can be "restored"; a dismissed alarm auto-expires once the alarm stops,
    so a recurrence is visible again (and can be dismissed again). Dismiss state shares the alarm store's
    lifecycle (resets on restart). Auth boundary (P3-12 recorded): dismiss/restore only do same-origin
    validation (alarm-only display-layer risk — a same-origin page script could hide alarms, but records
    aren't deleted and nothing else is affected; acceptable within the system).
  - **Display caps**: the panel shows the latest 8 alarms; the store is a ring buffer capped at 20, deduped
    per id within 60s, 24h TTL (sustained triggers naturally renew) — 100 alarms are not displayed in full,
    and needn't be (new alarms push out the oldest). Recent-scan echo (suspicious → yellow) also expires on
    the 24h TTL (P3-2: one suspicious scan no longer turns the shield permanently yellow; sustained scanning
    renews naturally).

## Static rule table (R1-R12)

| ID | Name | Default level | Scope | Determinism |
|---|---|---|---|---|
| R1 | constructor-chain escape | critical | code + files | certain/likely |
| R2 | Dynamic execution (eval/Function/import/require) | high (files) / medium (code; bin entries drop to medium) | both | certain/likely |
| R3 | Direct process access (runtime-graded; read-only members/generic/bin entries/app-type packages → info) | critical (host) / high (sandbox) | both | certain |
| R4 | Host closure capture (agent/TextEncoder…) + host-global prototype pollution | critical (code) / high (files, independent of targetKind) | both | certain/likely |
| R5 | ctx-escape attempt signal (withheld members/undeclared services; `ctx.logger` and other officially injected services are allowlisted) | medium | code only | likely |
| R6 | String coarse-scan fallback (obfuscation signals need combined evidence with dynamic execution) | info | both | heuristic |
| R7 | Hardcoded secrets | high | both | likely |
| R9 | Resource safety (unbounded allocation / exit-less synchronous loops / spawn-in-loop / ReDoS / non-terminating recursion / growth patterns in loops) | high (allocation/dead-loop/fork) / medium (ReDoS/recursion/Map.set) / info (resident loops/+=/Promise.all) | both | certain/likely/heuristic |
| R10 | Supply chain (package.json install hooks / dependency manifest) | high (install hooks) / info (dependency manifest) | files | likely/heuristic |
| R11 | Destructive file operations (fs deletes / sensitive-path reads-writes) | high (sensitive paths) / medium (deletes) | both | likely |
| R12 | Cordis/DSH contract (entry file / bundle-patch declaration / name / engines.node) | high (missing patch / missing entry) / medium (no entry / missing name) / info (low node version) | files | certain/likely |

## Scoring model

`staticScore = max(0, 100 - Σ(severity weight × hits × confidence coefficient))`

verdict (the single authoritative judgment; heuristics never upgrade): critical ≥ 1 → `critical`; otherwise
high ≥ 1 → `suspicious`; otherwise → `clean`. **The verdict is produced only by the static layer**: staticScore
and verdict are shown separately and never merged into a single total.

## Capability boundary (honest list)

> Static scanning is a "speed bump + forensics layer", not a security boundary. The following is split by
> **impact on the verdict**, and the forms it **explicitly does not detect** are listed truthfully (all
> empirically verified).

### Detected — verdict-level (changes the verdict)

| Rule | Problem class | Hit → verdict | Verified |
|---|---|---|---|
| R1 | Constructor-chain escape: `x.constructor("return process")` / `x["constructor"]("return " + "process")` / `new (globalThis.constructor.constructor)("return process")()` (dot/bracket-access + new forms; string args statically evaluable: literals/templates/concatenation/const bindings; new supports const-alias tracking) | critical | matrix + multi-file ✓ |
| R2 | Dynamic execution: `eval()` / `Function()` / `new Function` / `new AsyncFunction` (incl. parenthesized `new (Function)(...)`; escape-string args → critical) / `(async)=>{}.constructor` capture (round-7.2: `new X.constructor` reported only when the base is a function literal — `new n.constructor(n.type, n)` object-clone no longer false-positives) / `vm.runInContext`/`runInNewContext` / dynamic `import()` / `require()` | high (files) / medium (code, escape-string → critical); bin entries judged as generic code, drop to medium | matrix + round-7/7.2 regression ✓ |
| R3 | Direct process access: `getBuiltinModule`/`mainModule`/`module`/`exit` (incl. `reallyExit`) → critical; side-effect members (`kill`/`abort`/`chdir`/`umask`/`setuid`/`dlopen`/`binding`, etc.) and unknown members → high; **read-only members (round-7.1)**: `env`/`cwd`/`platform`/`pid`/`argv`/`execPath`/`stdin`/`stdout`/`stderr`/`nextTick`/`on`, etc. → info capability surface (reading cwd/env/pid isn't an escape channel; no-bin MCP/tool plugins like bridges no longer get hurt); `runtime='sandbox'` caps at high; shape degradation: generic packages / bin entry files / app-type packages → info | critical / high / info | matrix + round-7.1 regression ✓ |
| R4 | Host-closure capture: reading `.constructor` of agent/parallel/pipeline/phase/log/TextEncoder/TextDecoder/btoa/atob or feeding `Object.getPrototypeOf` (code scenario); host-global prototype pollution: `<builtin>.prototype.<member> = ...` override assignments and `Object.defineProperty(<builtin>.prototype, ...)` (Object/Array/String/Function/TextEncoder/URL/Buffer and 40+ builtins, round-7) | critical (code) / high (files, since round-7.1 independent of targetKind — pollution semantics don't distinguish plugins from generic packages, generic no longer drops to info) | matrix + round-7 regression ✓ |
| R7 | Hardcoded secrets: `sk-` / `AKIA` / `AIza` / `gh[pousr]_` / `xox[baprs]-` / env-var assignment / URL-embedded keys (placeholders excluded) | high → suspicious | matrix ✓ |
| R9 | Resource safety: `new Array(2**31)` / `Buffer.alloc(1GB)` unbounded allocation (≥1e8), `while(true)`/`for(;;)` exit-less **synchronous** loops (freezes the host; round-7.2: a labeled break whose label wraps the loop — `outer: for(;;){ ... break outer }` — counts as an exit signal), `spawn`/`exec`/`fork`/`new Worker` in exit-less loops (fork bomb) | high → suspicious; ReDoS nested quantifiers `(a+)+`-class and overlapping alternation branches `(a|aa)+` → medium (first-char-disjoint branches like `(?:[^']|'')*` and group-then-`?` like `(https?:)?` are linear and not reported, round-7), non-terminating recursion (for-of/for-in collection traversal and self-calls inside conditional loops not reported, round-7), `Map.set` in loops → medium (not into verdict); resident `await` loops only info (§14.1 doesn't shortcut review) | matrix + round-7/7.2 regression ✓ |
| R10 | Supply chain: `preinstall`/`install`/`postinstall`/`uninstall` hooks in package.json scripts (arbitrary code execution at install time) → high; dependency manifest → info (known-vulnerability check: OSV exact-version query, osvCheck can be disabled) | high → suspicious (install hooks) | matrix ✓ |
| R11 | Destructive file operations: `fs.unlink/rm/rmdir(+Sync)` deleting sensitive paths (/etc/root/.ssh etc.) → high, plain deletes → medium; `fs.writeFile` etc. writing sensitive paths → high; `fs.readdir` traversing sensitive directories → medium | high → suspicious (sensitive paths); medium not into verdict | matrix ✓ |
| R12 | Cordis/DSH contract: missing declared `dsh.bundle.patch` file → high; no entry (no main/exports["."] and no root index.js) → medium; declared entry file missing → high; plugin-intent package missing name → medium; `engines.node` major < 22 → info | high → suspicious (declared mount point/entry missing means guaranteed failure); medium/info not into verdict | matrix ✓ |

### Detected — advisory level (downgrades score only, never changes the verdict)

| Rule | Problem class | Note |
|---|---|---|
| R5 | ctx-escape attempt signal: accessing sandbox-withheld framework members / undeclared services (`ctx.plugin`, etc.) | code scenario only; medium |
| R6 | String coarse scan: concatenated escape features, `getBuiltinModule`/`child_process`/dangerous-require module references, obfuscation features (`String.fromCharCode`/`Buffer.from(base64)`/`atob(`/`charCodeAt` — since round-7 reported only when combined with an in-file dynamic-execution signal (eval/new Function/vm etc.); routine byte handling for terminal protocols/encoding no longer false-positives) | info/heuristic |
| R8 | Scan timeout / file-too-large skip | info meta-rule |

### Runtime monitoring (when `runtimeGuard: watch`) — alarm only

| Layer | Mechanism | Catches | Limits |
|---|---|---|---|
| T1 sentinel | Subprocess polling host /proc | Memory bomb (>memLimit), **sustained memory growth (leak; net window growth alarms by multiple)**, fork bomb (child-process burst), fd surge | Granularity = host-global (plugins share the process; can't attribute to a plugin) |
| T2 hooks | In-process wrapping of fs/child_process (incl. fs.promises) | Sensitive-path writes/deletes (/etc, ~/.ssh, .env…), key-file reads, spawn with shell/download-exfiltration keywords | Stack attribution best-effort; per-call wrapper overhead (I/O-heavy <5%, hot paths 10-20% range) |
| Shield | Browser `conversation.session.header.actions` + /vet/status.json | Green/yellow/red light + alarm count | Requires `dsh web` restart to activate |

### Explicitly not detected (empirically verified)

| Form | Empirical result |
|---|---|
| Indirect references: alias function `const f = Function; f(...)`, `process["getBuiltinModule"]`, `globalThis.process`, indirect eval `(0, eval)` | R6 info or zero findings, verdict=clean |
| Runtime/externally constructed payloads: base64 strings, hex/charCode assembly, reading code from network/env/args, self-modifying code | base64 constructor string tested → **zero findings** |
| Non-source files: `.jsx`/`.tsx`/`.vue`/`.json`/binaries/wasm/shell scripts | Not in the scan surface (only .js/.ts/.mjs/.cjs) |
| Dependency chain/supply chain: import/require graph, dependency-version vulnerabilities, package.json scripts/install hooks, licenses, author reputation | Not parsed |
| Runtime behavior: network exfiltration, dynamic prototype-pollution chains, dead loops/resource exhaustion, timing, permission abuse | No dataflow/behavior analysis; static `<builtin>.prototype` override assignments are caught by R4 (round-7) |
| Semantic knowledge: the actual services a plugin injects, `process` in bundler polyfills, shadowing boundary | R5 only recognizes 4 variable names; shadowing check is a v1 heuristic (undercounts) |
| Legitimate `process` use by host tool packages (`process.env` config reads, `process.stdin/stdout` protocol, `process.execPath` spawn) | Resolved: targetKind grading — non-DSH plugin packages/official packages (generic) downgrade R3/R2/R10/R9 dead-loop to capability-surface/advice (info/medium), not into verdict; DSH plugin packages stay strict. round-7 adds shape downgrades: app-type packages (package.json declares bin) and bin entry files are likewise downgraded to capability surface; round-7.1 read-only member classification: pure read-only members (`cwd`/`env`/`platform`/`pid`, etc.) drop to info even in plugin mode (no-bin MCP/tool plugins like bridges no longer hurt); side-effect/escape members (`kill`/`exit`, etc.) stay high/critical. 195 official packages tested all clean |

## Trust boundaries

1. **The verdict is produced only by the deterministic static layer** — rules are regex/AST judgments, not
   spoofable by prompt injection.
2. **The static layer is physically isolated from plugin code** — the scanner is a separate process; the AST is
   read-only and never eval'd.
3. **Review goes through the agent protocol** — the agent follows the vet-audit-protocol skill steps (static
   criteria first, sensitive points dug into one by one); the verdict is unaffected by the review step.
4. **No single merged score** — merging the verdict with subjective assessment is forbidden, to avoid polluting
   the verdict boundary.
5. **This product is not a security boundary** — positioned as a "speed bump + forensics layer" (bypassable
   forms in Known Limitations 1 below, aligned with DSH's official stance).
6. **Fail-open by default** — default `mode: report`; `deny` is explicitly enabled by the deployer.
7. **Alarm-only** — the runtime guard only watches, never kills; vet's automatic behavior (deny interception)
   exists only in the explicitly enabled opt-in mode. Alarms only carry advice; disposition is always left to
   the user on their DSH.

## Known Limitations

1. **Static scanning is not a security boundary**: obfuscated/encoded/dynamically generated code can bypass the
   AST rules; R6 only provides a "suspicious" signal.
1b. **Source enumeration limits**: `internal/plugin` auto-scan only recursively collects ≤6 levels deep,
   non-hidden (non-dot-prefixed) .js/.ts/.mjs/.cjs files — deep or hidden directories are silently unscanned
   (no warning); use scan_plugin(target=package) manually for a full directory scan.
2. **Agent review can be prompt-injected**: the verdict never comes from the review step, but the agent may
   miss things — the confidence field lets users know.
3. **`internal/plugin` guard doesn't cover runtime dynamic-mount escapes**: the vm path is intercepted at the
   call layer by the `tools/execute` guard.
4. **R5 is code-only**: ctx access in files scenarios isn't reported by default (high false-positive rate).
5. **Scan duration**: large plugin packages may time out and skip (R8 info); agent review proceeds per the
   vet-audit-protocol steps.
6. **The verdict is the static layer's deterministic judgment**; the agent's subjective assessment is recorded
   in the health record and doesn't constitute a security guarantee.
7. **/vet/status.json has no auth**: the shield's polling needs anonymous GET, and the route itself isn't
   authenticated — if dsh web binds to a non-loopback address, LAN clients can read scan conclusions/alarm
   targets. vet is an alarm-only observer and won't overreach into access control; if you care, keep loopback
   binding or trust your network (the POST guard toggle already has same-origin validation; no-Origin requests
   are rejected).
8. **`@deepseek-ai/*` is trusted by default**: if the official ecosystem is ever compromised, tighten this
   (v1 keeps the switch). scan_plugin judges official packages as generic (capability-surface downgrade) —
   an official-package supply-chain attack would let static downgrade mask process access (recorded, P-5;
   official packages are the platform itself, same policy as the internal/plugin official exemption). vet's own
   exemption is likewise narrowed (P-3): it now matches by name AND verifies via realpath that the target is
   the current vet instance — a same-name impostor package (file: install has no registry validation) is judged
   by the strictest plugin rules.
9. **R10's known-vulnerability check depends on an OSV network query**: on by default, sending "package
   name + exact version" to api.osv.dev (disclosed in the README config section; set `osvCheck: false` if you
   care); network failure/timeout degrades silently to skip (never false-blocks); only exact versions are
   queried — `*`/`>=`/`^`/`~` ranges and version-less main packages are skipped (P3-1/P3-3; round-7 fix:
   `^`/`~` no longer strip their prefix to query as exact lower bounds — the lower bound being affected while
   the actually installed version is already fixed would false-positive). Indirect transitive dependencies are
   not in the check surface.
10. **R11 only recognizes `fs.*` forms**: destructured/aliased calls (`const { unlinkSync } = require('fs')`)
    and runtime paths are missed (empirically recorded; a static boundary).
11. **T1/T2 are "security cameras", not "vaults"**: they catch obvious mischief (memory/fork bombs,
    sensitive-path operations, third-party spawn) but not worker threads/native plugins/low-traffic slow
    exfiltration; T2 doesn't cover ESM named-import snapshots, `process.binding`, and other side channels.
12. **T2 attribution & noise reduction**: stack attribution is best-effort (shared services/timers across
    plugins can mis-attribute); official-package spawn is not alarmed by default (capability grant).
13. **Shield activation requires a `dsh web` restart**: client-modules scans the `dsh.client` declaration at
    startup; the browser won't load the shield before the restart, but the /vet/status.json endpoint and the
    runtime guard (host side) take effect on restart.
14. **Runtime guard is off by default** (`runtimeGuard: 'off'`): wrapping fs/child_process carries performance
    and stability costs; opt-in.
15. **`process.kill` stays high (intentional, round-7.1)**: kill is a side-effect member and doesn't degrade
    with the read-only members — but a plugin killing its own spawned child (MCP/bridge-style) is a normal
    capability surface (dsh-bridges tested: 98/134 cleared; the remaining highs are all process.kill in
    run.js/util.js). Statically distinguishing `process.kill(child.pid)` (pid from this package's own spawn
    return) from arbitrary pids needs dataflow analysis — high cost, low benefit; kept as-is, to be ruled out
    manually by the agent during vet-audit-protocol review (conclusion recorded in the health record).
16. **Platform support (Linux-first, graceful degradation elsewhere)**: the static scan layer (scanner-bin /
    scan_plugin / R1-R12 / OSV), T2 runtime hooks, honeypot, GUI shield and audit protocol are all pure JS and
    run cross-platform (macOS/Windows). **The T1 sentinel is Linux-only**: it depends on /proc for
    VmRSS/children/fd; on non-Linux the sentinel exits gracefully and the metrics panel falls back to -1/0 (no
    errors, no log spam, by design). T2 sensitive paths match by path-segment name (backslashes are normalized,
    so `.ssh`/`.env`/`credentials` etc. hit on Windows too), but the "system-root prefix" (/etc /usr /var) is
    POSIX-shaped: on Windows, write/delete of `C:\Windows\System32`-style paths bypasses the system-root
    judgment (segment-name/keyword checks still apply); macOS has /etc /usr /var, so T2 is fully functional.
    Consistent with DSH current Linux-first adaptation state.

## Development

```sh
npm run build       # scanner-bin + src compiled to lib/ + client bundle
npm run typecheck   # full tsc --noEmit
npm test            # build + vitest (249 cases, incl. coverage thresholds)
npx vitest run --coverage   # coverage report (lines/functions >= 70%, branches >= 50%)
```

Layout: `scanner-bin/` static engine (separate process); `src/` plugin body (tools/guards/audit/report/guard);
`src/client/` GUI shield; `test/` fixtures + unit tests + adversarial matrix. Architecture in
`docs/ARCHITECTURE.md`.

## License

[MIT](LICENSE).