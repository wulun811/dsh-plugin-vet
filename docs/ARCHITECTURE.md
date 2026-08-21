# Architecture

> Public architecture document (distilled from the internal development plan, 2026-08). Describes the current
> implementation; internal process numbering is omitted. The component list is authoritative against the actual
> code in `src/` and `scanner-bin/`.

## 1. System overview

`@jieai/dsh-plugin-vet` (vet, for short) is the **trust-layer plugin** for deepseek-harness (DSH): it occupies
the whole **download → scan → audit → score → decide → runtime watch** trust pipeline.

**Product positioning: a monitoring alarm, not an enforcer.** vet only does "check → alarm → advise":
checks at write time (static scan), watches at run time (runtime guard), and surfaces alarms (scorecard + GUI
shield status light). vet **never acts on your behalf** — it never auto-uninstalls, never kills processes, never
rewrites configs; `deny` mode is an explicit deployer opt-in and is not part of the product identity. The final
disposition is always decided by the user on their own DSH.

```
DSH host process:
  tools/execute guard ── intercepts cordis_define/cordis_run/run_code/workflow
  internal/plugin guard ── auto static-scan of newly installed third-party npm packages + requireAudit gate
  T1 sentinel ── sidecar subprocess polling host /proc (memory/children/fd) → alarm JSON lines back
  T2 hooks ── in-process wrappers over fs/child_process (incl. fs.promises) → dangerous-operation alarms
  N1 capability diff ── declared capability manifest (scanner) vs observed runtime actions (T2) → hidden-capability red
  N3 exfil/destruction ledger ── per-plugin byte counters + 10s destruction signature windows + sequence signatures → yellow/red
  N4 canary watermark ── high-entropy canaries embedded in honeypot values; outbound URL/body/spawn match → 100% exfil red
  integrity canaries ── marker files under ~/.dsh; write/delete → red (ransom early trigger)
  honeypot ── fake key lures in an unobtrusive location; touching them is a high-confidence key-hunt signal
  webServer /vet/* ── GET status.json (shield polling), POST runtime-guard toggle
        │
        ▼  spawn separate process (request-response, exits after the scan)
scanner-bin:
  read stdin JSON → AST parse (TypeScript compiler API, read-only) → run rules
  → score/verdict → write stdout JSON (single line)
  cache: content hash + engine version + rule set + targetKind/runtime → report
  OSV: when package.json has a name, query known vulnerabilities by installed version (network failure degrades silently)
```

## 2. Trust boundaries (the most important design constraint)

1. **The verdict is produced only by the deterministic static layer.** Rules are regex/AST judgments, not
   spoofable by prompt injection. The agent's review output is always a recommendation/record and never
   participates in the `critical/suspicious/clean` judgment.
2. **The static layer is physically isolated from plugin code.** The scanner is a separate subprocess; the AST
   is read-only and never eval'd. Even if the host is tampered with by escaped code, scan results still come
   from a clean process; a scanner crash doesn't affect the host.
3. **No single merged score.** `staticScore` (deterministic) and the verdict are shown separately; merging them
   into a single number is forbidden, to prevent subjective judgment from polluting the verdict boundary.
4. **Fail-open by default.** Default `mode: report` (report only); `deny` (blocking) is explicitly enabled by
   the deployer.
5. **Alarm-only.** The runtime guard only watches, never kills; vet's automatic behavior (deny interception)
   exists only in the explicitly enabled opt-in mode.

## 3. Process model

- **scanner-bin**: `spawn(process.execPath, [scannerBinPath], { stdio: ['pipe','pipe','pipe'] })`, one scan per
  call (request-response, exits when done). Malicious input only affects the subprocess itself.
  `scannerBinPath` and the T1 sidecar path are resolved form-agnostically via `resolveVetFile`
  (`src/pkg-root.ts`) — safe under both the bundle (`lib/index.bundle.js`) and per-file (`lib/**`) layouts.
- **Runtime guard T1 sentinel**: a sidecar subprocess reads host /proc every `runtimeIntervalMs`
  (VmRSS / child-process count / fd count / memory-growth window) and streams alarm JSON lines back to the host.
  Singleton lock: env registry `DSH_VET_SIDECAR_PID` + same-PPID sibling scan, so config hot-reload doesn't stack
  sentinels. Unexpected exits auto-restart (max 5, with 5s backoff); off/uninstall scenarios don't resurrect it.
- **Crash/timeout**: scanner subprocess killed on timeout, returned as "scan failed" — a verdict is never
  forged; in deny mode a failed scan fails closed (block + alarm).

## 4. Static scan engine (scanner-bin)

### 4.1 Process protocol

stdin/stdout are single-line JSON:

```jsonc
// request
{ "kind": "code" | "files", "code"?, "language"?, "files"?, "rules"?, "targetKind"?, "runtime"?, "osv"? }
// response
{ "ok": true, "report": { "engine", "sourceCount", "findings", "staticScore", "verdict", "capabilities" } }
// capabilities (files mode, N1): { hosts[], fsPaths[], spawnCmds[], imports[], hasNetwork, hasExec }
```

### 4.2 AST parsing

The TypeScript compiler API (`createSourceFile`) read-only parses .js/.ts/.mjs/.cjs.
Helpers: static string/number evaluation (literals/templates/concatenation/const bindings), lexical shadowing
check.

### 4.3 Rule set (R1-R12)

| ID | Name | Default level | Determinism |
|---|---|---|---|
| R1 | constructor-chain escape | critical | certain/likely |
| R2 | Dynamic execution (eval/Function/import/require, incl. shadowing check; `new X.constructor` capture reported only when the base is a function literal — object-clone forms (`new n.constructor(...)`) excluded, round-7.2) | high (files) / medium (code) | certain/likely |
| R3 | Direct process access (runtime-graded; round-7.1: read-only members → info, side-effect members → high, escape members → critical) | critical (host) / high (sandbox) | certain |
| R4 | Host-closure capture (agent/TextEncoder…) + host-global prototype pollution (round-7; round-7.1: files always high, independent of targetKind) | critical (code) / high (files) | certain/likely |
| R5 | ctx-escape attempt signal | medium | code only |
| R6 | String coarse-scan fallback (obfuscation signals need combined evidence with dynamic execution, round-7) | info | heuristic |
| R7 | Hardcoded secrets (placeholders excluded by segment) | high | likely |
| R9 | Resource safety (unbounded allocation / dead loops / spawn-in-loop / ReDoS / recursion; round-7: group-then-`?` not ReDoS, bounded traversal recursion not non-termination; round-7.2: labeled break to a label wrapping the loop counts as an exit signal) | high/medium/info | certain/likely/heuristic |
| R10 | Supply chain (install hooks / dependency manifest) | high/info | likely/heuristic |
| R11 | Destructive file operations (fs deletes / sensitive-path reads-writes) | high/medium | likely |
| R12 | Cordis/DSH bundle contract (entry file / bundle-patch declaration / name / engines.node) | high/medium/info | certain/likely |

Per-rule switch: `rules: { "R7": false }` disables a single rule.

### 4.4 Scoring model

`staticScore = max(0, 100 - Σ(severity weight × hits × confidence coefficient))`

verdict (the single authoritative judgment): `critical ≥ 1 → critical`; otherwise `high ≥ 1 → suspicious`;
otherwise → clean. **Heuristic confidence never upgrades the verdict** (R6 advises only, never judges).

### 4.5 Target-identity grading (targetKind)

- `plugin` (DSH plugin package: depends on @deepseek-ai/cordis, etc.): strict — process access and dangerous
  requires are judged as escape surface.
- `generic` (ordinary npm package / official runtime): capability-surface downgrade (info/medium), not into the
  verdict.
- Auto-scan runs with plugin semantics (strict); `scan_plugin` judges by the package.json dependencies.
- **Self-exemption via realpath (round-7.1 P-3)**: vet itself (name match) must verify via realpath that the
  target is the current vet instance before being judged generic — local file: installs have no registry
  validation, and a name-only match can be impersonated (a malicious tarball posing as @jieai/dsh-plugin-vet to
  get the downgrade); a same-name impostor is judged by the strictest plugin rules.
- **Package-shape downgrade (round-7)**: the engine reads package.json's `bin` field into the RuleContext —
  app-type packages (`appShape`: CLI/TUI/server declaring bin, where process is the product function) drop R3
  to info as a whole; bin entry files (`cliFiles`, CLI scripts that always run standalone) judge R2/R3 as
  generic code and drop R9 dead loops to medium. package.json content is in the cache hash, so shape changes
  invalidate caches naturally.

### 4.6 Cache

Content hash + engine version + rule set + **targetKind/runtime** → report file (0700 dir / 0600 file, strict
shape validation against forgery). Different contexts don't cross-contaminate.

### 4.7 OSV known-vulnerability check

When package.json has a name, query Google OSV (`api.osv.dev/v1/query`) by **installed version (exact versions
only)**; the server filters by affected ranges; hits append a high finding and recompute the verdict. Network
failure degrades silently. `osvCheck: false` disables it (on by default, which sends package names out — turn
off if privacy-sensitive).
Check surface = the plugin itself + direct dependencies (cap 8, official `@deepseek-ai/*` packages skipped);
`*`/`>=`/`^`/`~` ranges and version-less main packages skip the query (P3-1/P3-3, avoiding stale full-history
false positives; round-7 fix: ranges no longer strip their prefix to query as exact lower bounds — the lower
bound being affected while the actually installed version is already fixed would false-positive).

### 4.8 Capability manifest & cross-layer diff (N1)

When scanning a package (files mode), the engine additionally produces a structured **capability manifest**
(`ScanReport.capabilities`, N1 declaration side):

```typescript
interface CapabilityManifest {
  hosts: string[]       // network hosts parsed from URL-looking literals
  fsPaths: string[]     // fs-call string args + path-like literals (incl. sensitive segments)
  spawnCmds: string[]   // child_process first-args + shell/download command words
  imports: string[]     // third-party require/import package names
  hasNetwork: boolean   // references http/https/net/fetch/dgram …
  hasExec: boolean      // references eval/Function/child_process …
  ghostDeps?: string[]  // R16: imported but undeclared (ghost dependency)
  zombieDeps?: string[] // R16: declared but not installed (zombie dependency)
}
```

- Modules bound to fs/child_process via import/require (incl. destructuring) are tracked so all call shapes
  (fs.readFileSync / require(「fs」).readFileSync / bare readFileSync) contribute their arg strings; the
  extraction is deliberately over-collecting (never a verdict; only facts).
- `internal/plugin` auto-scan registers the manifest against the plugin name (`capabilityDiff.registerStatic`)
  at load time; the T2 sink then diffs every sensitive runtime observation (net-egress/spawn/fs-read/fs-write/
  fs-destroy/fs-probe) against the manifest:
  | observed action with **zero** static footprint (hosts/fsPaths/spawnCmds empty, !hasNetwork, !hasExec,
  imports empty) | red `n1-hidden` (confidence certain — hidden capability executed) |
  | any third-party import present | conservatively covers any action (capability unknown, never false-alarm) |
  | static capability, runtime never triggered | dormant — recorded in the observation store, surfaced by the
  nutrition label (M2 — `vet_label`, 0.1.21) |
- Alarm-only: the diff never blocks; detection signals never trigger interception (N7 is the only interceptor,
  and only for destructive classes).

### 4.9 Literal decode preprocessor (N2)

Before running rules, the engine collects statically decodable string expressions from each source file
(`collectDecodedLiterals`, scanner-bin/decode.ts):

- Supported forms: `atob(...)`, `Buffer.from(s, 「hex」|「base64」|「base64url」)`, `String.fromCharCode(...)`,
  constant concatenation (`「a」 + 「b」`, static templates) via the existing static evaluator.
- Hard limits (anti-DoS): decoded result ≤ 4KB, nested decoding ≤ 2 call layers (`atob(atob(x))`), ≤ 200
  decoded literals per file; engine per-file size cap (8MB) applies before this pass.
- Only all-literal arguments are decoded; any dynamic argument yields undefined (never guesses, never executes).
- The decoded corpus is fed back into R13 (exfiltration endpoints), R7 (hardcoded secrets) and R11 (sensitive
  paths) matching with unchanged rule predicates; hits carry `decodedFrom` (base64/hex/charCode/template) and
  the original expression line for audit trail.

### 4.10 Dynamic-string provenance (R15, N5)

"Deliberately built so the static layer cannot see the target" is itself a signal (G1 complement to N2).
R15 (scanner-bin/rules/dynamic-targets.ts) scans network sinks — fetch / new WebSocket /
http(s).request|get (incl. the require('http').request form) / net.connect|createConnection — and
checks whether the target argument is statically resolvable to a string:

- Resolvable (literal / constant concatenation / static template / N2-decodable atob / Buffer.from /
  String.fromCharCode, or an identifier whose initializer resolves via the static evaluator) → the target
  is *declared* → **not flagged** (N2 already re-feeds the text into R13/R7/R11).
- Unresolvable (runtime data, env reads, function results, templates with unknown substitutions) → **info,
  heuristic**: "网络目标动态构造，静态不可审计（N5）" — the N1 manifest cannot name this host, so runtime
  observation is the only evidence (N1's hidden-capability red alarm is the escalation path; this finding is
  its static-side context note, per the v2 "info/low, escalate only when stacked" policy).
- Noise controls: http(s).request/get options-object form ({ hostname, path }) and unresolved plain
  identifiers there (ambiguous: could be an options object) are skipped; fetch/WebSocket first args and
  net host args are URL/string by contract so unresolved identifiers are flagged; one finding per call site;
  missing argument → skipped. ENGINE_VERSION bumped static-v10 → static-v11 (old caches invalidate).


### 4.11 Dependency consistency audit (R16, P0-2 #9)

Three-way reconciliation of *declared* (package.json) vs *referenced* (code imports) vs *installed*
(node_modules): deterministic, zero network, advisory-only.

- **Ghost dependency (幽灵)**: a third-party package imported by code but not declared in any of
  dependencies / devDependencies / peerDependencies / optionalDependencies — it resolves only because npm
  hoists it as a transitive dep; an upgrade can silently drop or replace it. `@deepseek-ai/*` (host trust
  boundary, same skip rule as the OSV direct-dep check) is never flagged.
- **Zombie dependency (僵尸)**: a package declared in package.json but absent from `node_modules` (bounded
  8-level upward walk for monorepo hoisting) — stale/forged declaration that fails at runtime.

Wired into scanner-bin (files mode, package.json present): emitted as `R16` findings at info/heuristic
(no score, never changes the verdict) and recorded into the N1 manifest as `ghostDeps`/`zombieDeps`
(optional arrays), so `vet_label` (M2) prints them and N6's version diff surfaces their changes
(displayed, not alarm-escalating — `imports` already carries the "new dep" signal).
The node_modules/declared state feeds the scanner cache key (`deps` fingerprint) so results never go stale.
Rule gate `rules: { R16: false }`; `engine` bumped static-v12 → static-v13.

## 5. Runtime guard (T1 + T2 + honeypot, alarm-only)

### 5.1 T1 sentinel (sidecar monitor)

- Every `runtimeIntervalMs` (default 2s) reads host /proc: VmRSS, child-process count, fd count, in-window
  memory growth.
- Over-limit → alarm JSON line back to host: memory over-limit red, fork burst red, fd over-limit yellow,
  growth yellow.
- Granularity = host-global (plugins share the process; can't attribute to a plugin).
- Platform gate (0.1.21, P0-6): the sidecar is only spawned on Linux. /proc is required for the singleton
  lock, host-liveness watchdog and PID identity check, so on macOS/Windows the sentinel is skipped entirely —
  no spawn, no respawn noise, no `sentinel-down` alarm; T2 hooks (in-process) are unaffected.

### 5.2 T2 hooks (in-process wrapping)

Wraps the built-in exports of `fs`, `fs.promises`, `child_process` (property-level wrapping; ESM named-import
snapshots are a known side channel):

- Dangerous operation → capture stack → attribute to the plugin package name (stack-frame path ↔ plugin root
  longest-prefix match) → alarm.
- Coverage: sensitive-path writes/deletes, key-file reads, subprocesses with shell/download-exfiltration
  keywords, destructive commands (rm/mv/dd/mkfs…) hitting sensitive paths, shell redirection to sensitive
  paths, reconnaissance primitives (readdir/stat/access on sensitive paths), honeypot-lure touches.
- **Never blocks a call**; officially attributed spawn gets noise reduction.
- **Hook integrity heartbeat (0.1.21, P0-2 #2)**: every wrapper is branded (`brandVetHook`) with a
  module-closure-private `Symbol` — an extractable, non-spoofable marker (a copied `toString()` can't forge
  it). `hookHeartbeat()` re-checks the registered targets' current exports. In `watch` mode a periodic timer
  (runtimeIntervalMs×4, min 5s, unref) raises a yellow `t2:hook-heartbeat` alarm listing any stripped/replaced
  op — the one in-process way to bypass T2 is to rewrite the module exports, and this makes that deterministic.
- **N1 cross-layer diff (0.1.13)**: every sensitive T2 alarm (net-egress/spawn/fs-read/fs-write/fs-destroy/
  fs-probe) is diffed against the scanned capability manifest of the attributed plugin — a sensitive action with
  zero static footprint (including imports) is a hidden capability → red `n1-hidden` alarm (certain). The diff
  store also records observed sets for the M2 nutrition label (dormant capabilities), surfaced by the
  `vet_label` tool (0.1.21), which prints the *declared* (static) capability manifest from the N6 history as a
  human-readable "nutrition label"; runtime observed/dormant capabilities live in the in-process diff store.
- **File layout (0.1.21, P0-4 structure refactor — zero behavior change)**: `src/guard/runtime-hooks.ts` (1011
  lines) is now a public-API re-export barrel over 8 focused submodules: `runtime-ops` (op tables & types),
  `runtime-count` (stream byte counters), `runtime-heartbeat` (hook brand + heartbeat), `runtime-denoise` (path
  sensitivity / lock-sibling / session-log / stack-tamper / vet-self-io & root-indexing passthrough),
  `runtime-classify` (classifyOp), `runtime-attrib` (pluginFromStack / isOfficial), `runtime-net` (network
  classification) and `runtime-patch` (patchModule / patchNetworkModule). `src/guard/runtime-guard.ts`
  (762 → 492 lines) keeps the `installRuntimeGuard` assembly; the T1 sentinel lifecycle moved to
  `runtime-sidecar.ts`, and the T2 alarm/ledger/canary/key-leak/forensics pipeline to `runtime-sink.ts`
  (`createT2Sink(status)`). All previously-public symbols are re-exported from the same module paths, so no
  import site changes; `rootIndexing`/`vetSelfIo` stay module-private and the sidecar flags write via setters.

### 5.3 Honeypot lures

- Default location `~/.dsh/.local`: directory/file names and contents carry no honeypot keywords
  (anti-honeypot).
- Lure values are well-formed but invalid fake credentials (real AWS/OpenAI/npm prefixes, random key bodies;
  id_rsa is a real-format one-shot RSA key pair, never used anywhere).
- Idempotent: existing lures aren't rewritten; deleted lures are rebuilt. Permissions 0700/0600.

### 5.4 Exfiltration & destruction ledger (N3, 0.1.14)

A per-plugin ledger (src/guard/exfil-ledger.ts) fed by the same T2 wrappers via an optional observe channel
(patchModule/patchNetworkModule gain an optional observer; runtime-guard wires it to the exfilLedger
singleton; no observer = zero overhead). It never inspects session/chat content — only fs byte counts,
outbound byte counts and operation shapes:

- **Byte counters (lifecycle cumulative)**: reads from sensitive paths (sensitiveReadBytes, actual result /
  chunk lengths, not stat.size) and writes to non-allowlisted hosts (netWriteBytes, counted on the returned
  request object write/end, incl. streams). Both > 0 → yellow n3-exfil; magnitudes within [0.4×, 3×] (and
  ≥ 512B) → red n3-exfil-match (whole-package exfil).
- **Sequence signatures (30s window)**: READ_SECRET → SPAWN(curl|wget|nc), READ_SECRET → NET_WRITE → red
  (n3-seq-read-spawn / n3-seq-read-net). Compares the read→action interval, not recency.
- **Destruction signature family (10s sliding window, all paths)**: MASS_DELETE (delete rate), MASS_RENAME_EXT
  (rename to .encrypted/.locked/.crypt/random-hex), IN_PLACE_OVERWRITE (read-then-write-same-path pairs),
  WRITE_AMPLIFY (write byte rate) → yellow; two+ families together → red n3-ransom. node_modules/.git/build
  outputs, atomic-write locks and transient temp files are noise-skipped; thresholds are deliberately
  conservative (miss > false-positive). markSuspected() (honeypot/canary confirmation, N4) lowers a
  plugin's thresholds.
- Idle ledgers are pruned on the VetStatus TTL cadence (24h). Alarm-only: never intercepts.

### 5.5 Canary watermarks & integrity canaries (N4, 0.1.14)

- **Honeypot watermark (exfil confirmation)**: `ensureHoneypot` now embeds one unique high-entropy canary
  (40-hex, no keyword — keeps the anti-honeypot "no vet/honeypot keyword" guarantee) into each lure value
  field (the base64 private-key body for credentials.json); the active canary set lives in memory only
  (`canaryStore`, never written to a registry file). Existing lures are never rewritten (idempotent), so they
  keep their canary until deleted (self-heal re-injection).
- **Outbound correlation**: the network wrappers scan URL (once per request) and request body text (per chunk,
  cross-chunk accumulation, 64KB tail cap) via the optional 7th `patchNetworkModule` param; dgram messages and
  fetch URL/string bodies are scanned in the guard; spawn arguments are scanned in the ledger fs observer.
  Matching runs three variants (direct / URL-decode / one base64-decode) and only when canaries are active.
  A hit → red `canary-leak` (confidence certain — no legitimate reason to send a honeypot secret anywhere).
  The offending plugin is also marked suspected in the N3 ledger (thresholds drop to minimum). Canary
  reassembly across multiple exfil requests (sharding) is explicitly out of scope (documented boundary).
- **Integrity canaries (scope: ~/.dsh only)**: `ensureIntegrityCanaries` places two small marker files under
  ~/.dsh with fixed content + a self-referencing sha256. `classifyOp` treats write/delete of these paths as
  red `integrity` (distinct from the credential honeypot kind) — the earliest trigger when ransomware
  encrypts the profile/credentials surface, a backstop for the N3 destruction signatures. Reads are not
  alarmed (content is fixed and known).

### 5.11 Semantic contract — M1 (0.1.21, P0-5 record stage)

- A plugin can ship a local, offline-authored behavior contract (`vet.contract.json`, schema 1): the fs paths it
  reads/writes/deletes, the hosts/ports it connects to, the commands it spawns, and the env vars it reads.
  Contracts are written by the user's own agent locally (reusing the AUDIT_PROTOCOL authoring pattern) — **VET
  makes zero model requests and stays deterministic**; enforcement is always code, never LLM.
- **Laxity validator** (`src/guard/contract.ts`, pure/deterministic): rejects overly-flexible contracts —
  bare `**`/`*`/empty path patterns, mid-globstar (`a/**/b`), unreachable path forms (`~/...` home-glob,
  `/` root, `./...` relative — none can ever match an absolute runtime path), wildcard hosts (`*`),
  wildcard commands, and malformed schema. Bounded forms are accepted: `/<dir>/**` directory-prefix recursion,
  `/tmp/<seg>/out` single-segment wildcard, `*.example.com` one-label host suffix. A rejected contract does
  not load (N1 stays at declared-vs-scanned); a `destroy` scope or unknown `meta.generator` raises a warning,
  not a rejection.
- **Trust priority (three levels)**: code facts (static scan) > runtime observations (T2) > contract promises,
  enforced by `contractPriority()`. A contract can *explain/denoise* an observation inside its declared scope,
  but can never override a code fact or swallow an out-of-scope observation.
- **Record stage only — wired (0.1.21, 方案 A)**: with config contract.enabled (default on) and a per-plugin
  contract file at ~/.dsh/vet/contracts/<name>.json, the T2 sink (createT2Sink(status, contractResolver))
  reconciles each runtime alarm against the plugin's contract:
  - out-of-scope alarm → info m1:contract-violation (collapses by source/kind/plugin/field, count accumulates);
  - rejected contract → yellow m1:contract-rejected (once per plugin);
  - a *code fact* (N1 hidden capability) contradicting the contract → yellow m1:contract-distrusted
    (once per plugin) — the contract is proven untrustworthy against the higher authority.
  The contract is strictly advisory: it never suppresses code-fact/observation alarms and never intercepts
  (N7 untouched). No contract file → byte-for-byte zero behavior change. Escalating contract violations into
  alarm evidence is a deliberate, later rollout decision (0.2.x).

### 5.6 Alarm aggregation (VetStatus)

- Ring buffer (default 20) + per-id dedup window (60s) + **TTL expiry (default 24h)** — a single false
  positive doesn't turn the shield permanently yellow/red.
- Shield level: any red → red; any yellow or a recent non-clean scan → yellow; otherwise green.

### 5.10 Forensics mode (0.1.21, P0-2 — confirmed-malicious micro log)

- Once a plugin is **armed** (`src/guard/forensics.ts`, triggered by the N4 canary-leak confirmation in
  `recordCanary`), every subsequent fs/child_process op (ledgerFsObserver) and network op (ledgerNetObserver)
  of that plugin is appended to `~/.dsh/vet/forensics/<plugin>-<ts>.jsonl` (directory 0700, file 0600).
- Operates on the same data plane as the N3 ledger (operation-shape + target only; **never session/chat
  content**). `arm` is idempotent, `record` is fail-open (disk errors are silent — forensics is an
  enhancement, not a block path), and the armed set is in-memory (cleared on restart). Honest boundary: only
  the plugin's fs/network ledger surface is captured — native binaries, worker realms and process-memory
  exfiltration remain invisible (same boundary as N3).


### 5.7 Confirmation block (N7, 0.1.14 — the only interceptor)

The single feature that blocks. The decision axis (v4) is **irreversibility**: destruction whose original
content cannot be recovered → **intercept**; tampering that is recoverable (reinstall / remove implant /
baseline compare) → **alarm only**, never risking a false block.

- **Family 1 — destruction/ransomware confirmation** (`src/guard/confirm-block.ts`): once a plugin is
  confirmed destructive (N3 destruction-signature combination `n3-ransom` / integrity-canary write-delete /
  N4 canary leak — wired in `runtime-guard.ts`), its subsequent destructive-property fs ops
  (write/unlink/rename/cp/truncate/createWriteStream, incl. Sync variants) throw.
- **Family 2 — credential-body destruction** (single-shot, immediate, exact file-level): delete-family ops
  (unlink/rm/rmdir/rename to the credential) and overwrite-write to an *existing* credential file
  (`writeFile`/`truncate`/`createWriteStream`) are blocked; `appendFile` and writing a *new* file (recoverable)
  are alarm-only. Credential files: `~/.ssh/id_{rsa,ed25519,ecdsa,dsa}(.pub)`, `~/.dsh/.credentials.yaml`,
  `~/.aws/credentials`, `.pgpass`, `.netrc`, `.git-credentials`, `.npmrc` (HOME env first for testability).
- **Family 3/4 — persistence/privilege & supply-chain write**: `classifyOp` flags writes to
  bashrc/cron/systemd/ld.so.preload/sudoers.d/profile.d/autostart/authorized_keys/hosts/ssl →
  yellow `persistence-write`, and node_modules package files / cordis.patch.yml / cordis.yml / plugin.json →
  yellow `install-write` (copy-pair ops check both source and destination). Alarm-only by default; a user may
  explicitly upgrade a family to `block` via `confirmBlockFamily3/4` (the wrapper then intercepts on the same
  destructive-property op face — appendFile etc. still never blocked).
- **Zero-false-intercept guards**: official attribution (`@deepseek-ai/*`), unattributed ops (the host user),
  and vet self IO (`withVetSelfIo`) bypass interception · only that plugin, only destructive-property ops, and
  only after a certain-confirmation signal · the block throws with an actionable message (downgrade
  `confirmBlock` to `alarm` and retry) and writes a red `n7-block` alarm · **fail-open**: any decision error
  passes the call through and is recorded as an internal error, never blocking or corrupting a legitimate call.
- **Lifecycle**: the blocked set is process memory (cleared on DSH restart; config changes require restart).
  `confirmBlock` mode and family overrides come from `src/config.ts` and are applied at guard install.

### 5.8 Upgrade behavioral diff (N6, 0.1.15 — version-aware capability tracking)

Supply-chain poisoning almost always lives in "a new version of an old package"; per-version isolated scans
cannot see what the new version *additionally asks for*. N6 persistently records the N1 capability manifest
per `name@version` and diffs past vs. present on upgrade — **only "capability changes" are signals, never
"code changes"** (`src/guard/version-diff.ts`).

- **Storage**: `~/.dsh/vet/capabilities.json` (0600, dir 0700) — single JSON store keyed
  `name@version` reusing the content-baseline load/save atomic-rename infra (implementation decision vs. the
  plan's per-file layout: atomic write + audit in one structure); LRU keeps the most recent 1000 versions
  (oldest dropped by `recordedAt`). Same env override (`DSH_PLUGIN_VET_BASELINE_DIR`) for test isolation.
- **Hook**: wired into the `internal/plugin` auto-scan completion — every scanned plugin records its
  manifest; when a different version of the same package is seen, the previous version is picked by
  `recordedAt` (no semver parsing, tie-break = later insertion).
- **Severity** (local, deterministic): any newly added capability → yellow `upgrade-diff`; a new
  high-sensitivity combination (exec + network, sensitive-path + network, sensitive-path + exec) → red.
  Removed capabilities are audit-only (never alarm — narrowing is benign). Cold start (no previous version)
  records only; a new manifest declaring exec+network double-high gets a yellow `upgrade-cold` notice.
  Same-version re-record refreshes `recordedAt` without diffing. Fail-open: storage corruption/missing
  version/manifest → no-op, never disturbs plugin loading.
- **Audit tool**: `vet_diff` — read-only local history + last-two-version behavior changelog for a package
  (hosts/fsPaths/spawnCmds/imports added|removed, network/exec flips); no scan, no network.

### 5.9 Hardening batch (0.1.16 — post-review fixes)

Full code review output implemented in one line: publish-artifact bundling (C1), ESM named-import blind-spot
marking (C2), env snapshot + cache nonce (C3), attribution tamper detection (C4), T2 ops-surface expansion
(M5), store tamper self-check (M7), segment-level sensitive-path matching (M8) and sidecar PID-reuse
protection (M9); R2/R3/R4/R9/R10/R14/R15 rule patches (ENGINE static-v12). Details in CHANGELOG 0.1.16.
Trust-relevant highlights:
- C1 使『同进程恶意插件 require vet 内部模块改写全局状态』失效：发布物 bundle 化 + files 白名单，
  内部状态（setRootIndexing/withVetSelfIo/confirmBlock/canaryStore/capabilityDiff）闭包封闭不可达。
- C3 使缓存/存储目录不可被进程内改 env 重定向；缓存条目带宿主注入 nonce，伪造干净缓存被忽略。
- C4 使归因文本不可被全局静音/伪造滥用：prepareStackTrace/stackTraceLimit 篡改 → attribution-tampered
  red + 族 2 凭据破坏照拦（哨兵身份）。
- M7 使 capabilities/baseline 存储被外部改写可观测（vet-store-tamper 黄灯）。

### 5.12 Baseline-mismatch 定性重构（0.1.21）

**问题**：同版本号重装/本机补丁触发红警「疑似供应链篡改」，实际可能是基线陈旧或合法修改。

**方案**：双机制——registry 对账 + 补丁登记。

1. **Registry 对账**（report 模式）：mismatch 时异步对账 npm registry（同版本发布内容不可变=内容真值）：
   - 本机字节 == registry → 基线陈旧，自动刷新基线 + yellow「基线已对齐官方 registry」
   - 本机字节 != registry → 红警坐实「与官方 registry 字节也不一致」
   - 对账不可用（网络失败/tar 缺失）→ 维持红警 fail-closed「registry 对账不可用」
   - deny 模式：同步记红 fail-closed（零网络，P2-7 同款约束）

2. **已声明本机补丁**：配置 `acknowledged-package-hashes`（键 `name@version`，值 sha256 hex 数组）：
   - 命中 → 豁免基线比对 + 一次性 yellow「已声明的本机补丁状态」
   - 未命中 → 走 registry 对账路径
   - 用途：LAN 信任补丁等合法修改，登记后消除红警，透明不静默

**配置示例**：
```yaml
# ~/.dsh/profiles/web/cordis.yml 或 vet 配置文件
plugins:
  vet:
    acknowledgedPackageHashes:
      "@deepseek-ai/dsh-client-connection@0.1.0-rc.8":
        - "e396626b275719de626a3338ed5566f7b556846cee52e7e85e947f00ced8442d"
```

**红警消息**：改为可操作指引（含短 hash 与登记方法），i18n 补 `baseline-patch-ack` / `baseline-refreshed` 两类建议。

### 5.13 N3 密钥外泄归因分级（0.1.21）

**问题**：无主（宿主自身流量）PEM 形状命中 → red「100% 确认密钥外泄」——宿主会话体/文档天然含密钥样文本（安全报告、测试夹具），形状命中≠外泄实锤。

**方案**：归因分级：
- 归因第三方插件 → red「按外泄处置」（原语义不变）
- 无主（宿主自身流量）→ yellow「格式命中待人工研判，非确认外泄」
- 金丝雀命中（recordCanary）不受影响：预埋值出现即近乎实锤，保持 red

**i18n**：`suggest.n3-key-leak` / `.unattributed` 措辞同步修正。

### 5.14 Capability 提取降噪（0.1.21）

**问题**：
- hosts：模板拼接残片（如 `[`）混入
- fsPaths：注释样文本/报错文案/相对模块引用混入
- hasExec：bundle 自带同名辅助函数（fork/exec）误触 upgrade-cold「执行+网络双高」

**方案**：
1. **hosts 形状校验**：拒绝模板拼接残片；localhost（含端口）与方括号 IPv6 放行；其余要求含点域名形状
2. **裸字面量 fsPath 收紧**：仅接受路径前缀开头且无空白且非相对模块引用；跳过模板拼接片段；fs 调用实参位的结构化提取保留完整 looksLikePath 语义（含敏感段）
3. **hasExec 门控**：裸 spawn/exec/fork 标识符仅在文件确实引用 child_process 时计为执行能力；Function("return this") realm shim 不算动态执行

### 5.15 Self-scan trust annotation — vet 扫 vet（0.1.21）

把 vet 当作待审插件扫（dsh.so SECURITY SCAN 面板 / `scan_plugin` target=package），其源码天然命中全部
危险能力词表——T1/T2 的实现就是监视 fs/child_process/net，检测规则文件里写着 curl|sh 正则、honeypot 里
造着假私钥。原始报告呈现为海量 Critical，普通用户极易误读为"安全层本身不安全"。

与"扫到自己就跳过/变绿"的作弊式豁免相反，vet 走**对本体可验证的评判标准**（有界豁免）：

1. **① 能力声明降级**（`src/report/self-scan.ts`，纯函数，绝不影响非本体扫描路径）：危险 token（模块 /
   出站目标 / 环境变量 / 敏感路径 / 子进程命令）逐个与 vet 自带的能力声明比对——token 全在声明内 →
   视为已声明能力面（info）；**任一个未声明**（出站非回环非 osv.dev host、未知 `process.env.*`、凭据/密钥
   路径、shell 管道、worker_threads/vm/cluster 等 IPC 原语）→ 保留原 severity，新增能力照旧 red。
   检测规则数据/黑名单/诱饵/文案文件（rules/*、runtime-net、honeypot、i18n、capability）与
   test/spec/e2e 开发夹具按文件级豁免——均仅 pinned-match 生效（② 钉扎兜底，非 pinned-match 时文件形同
   陌生人，豁免失效）。
2. **② 每版本产物钉扎**（`src/report/self-pin.ts` + `vet-self-pins.json` + `scripts/gen-self-pin.mjs`）：
   版本 → 扫描集 sha256，按版本发布、不写死单 hash（升级同版自扫不误报；字节不符任一发布钉扎——含被替换
   的 vet——→ 一律非 pinned-match，按陌生人全扫）。`pinned-match` = 当前字节 == 被审计发布物 → 可出
   Trusted；`dev-tree`/`unpinned` → 不予信任背书（amber）。钉扎范围 = 本体权威源码集
   （`src/report/self-scope.ts`：排除 gitignore 非本体目录 lib/、dsh-src/、plugin-scan-tmp/、
   dist/coverage/build，跨机可复现、与面板扫 vet 源码仓同源）。
3. **③ 展示数据**（`scan_plugin` 输出 `selfScan` 块 + 评分卡 Trusted 卡）：`static` 保留原始
   verdict/findings 完整透明，`selfScan` 给出零化已声明项后的 verdict/score + 归属统计（declared /
   datasetSelfRef / devFixtures / retained）+ 必须复查清单。**dsh.so 接入点：面板对 vet 本体改走
   `scan_plugin` 出口；有 `selfScan` 时以其 `verdict`/`staticScore` 作标题态（Trusted = pinned-match &&
   verdict clean），原始 findings 可折叠展开；`selfScan` 缺失（普通插件）维持原静态判定呈现，行为零变化。**
4. **④ 发布自扫门禁**（`scripts/check-self-contract.mjs`，挂 `prepublishOnly`）：版本未钉扎 / 本地字节与
   发布钉扎不符 / 已使用但未声明的 decisive（critical|high retained）→ 拒绝发布——保证"能发出去的版本
   声明一定完整"。发布仪式：`npm run build && npm run gen:self-pin`（提交 `vet-self-pins.json`）→ 正常走
   prepublish（含本门禁）。

信任边界（不得放宽）：出站 host（非回环非 osv.dev）、未声明 env、凭据/密钥路径、IPC 原语四个方向出现的
任一 token 一律保留，无待定豁免；**钉扎（pinned-match）是豁免生效的前提**。测试：`test/self-scan.test.ts`
（27）、`test/self-pin.test.ts`（6）；端到端实测本体自扫 pinned-match + clean，325 findings 全分类。

## 6. Audit protocol (vet-audit-protocol skill)

vet ships no built-in LLM audit tool. Review is **executed by the agent following the skill steps**
(`AUDIT_PROTOCOL.md`):

scan_plugin static criteria → read manifest/source → verify each finding → proactively dig deeper
(network/files/processes/credentials/library semantics) → hand-write a health record to
`~/.dsh/vet/audits/<plugin>-<version>-<ts>.md` using the system write capability.

With `requireAudit: true`, loading a third-party plugin without a record → report mode alarms / deny mode
blocks. Record naming is strict (`<name>-<version>-<ts>.md`), preventing prefix forgery.

## 7. Plugin body and distribution

- Entry `src/index.ts`: name/inject/Config/apply, no default export.
- Config: schemastery schema (`src/config.ts`); all fields in the README Config table.
- Tools: `scan_plugin` (deterministic static scan; verdict comes only from the static layer).
- Guards: `internal/plugin` auto-scan + requireAudit gate; `tools/execute` interception.
- Shield: browser half (`conversation.session.header.actions`), polls /vet/status.json, one-click runtimeGuard
  config write (takes effect on restart).
- Distribution: `cordis.patch.yml` mount patch (insert semantics); `files` ships lib/ + docs + patch.
- Resource resolution: package-internal paths (AUDIT_PROTOCOL.md, scanner-bin entry, T1 sidecar, SELF_ROOT)
  are located by `src/pkg-root.ts` — `resolvePkgRoot` (upward package.json search) + `resolveVetFile`
  (candidate existence: lib/ → root → src/), form-agnostic to bundle vs per-file layout (0.1.16 C1
  companion: the fixed two-level `..` locators broke under `lib/index.bundle.js` main — ENOENT on restart).

## 8. Known boundaries (honest list)

- Static scanning is a "speed bump + forensics layer", not a security boundary.
- Indirect references (alias functions, computed access, globalThis.process, indirect eval) yield only info or
  zero findings.
- Runtime-constructed payloads (base64 strings, hex assembly, self-modifying code) can bypass the AST rules;
  **0.1.13 (N2) partially closes the statically-decodable subset** — base64/hex/charCode/constant-concat
  literals are decoded and re-fed into R13/R7/R11 (hits carry `decodedFrom`); payloads assembled from
  runtime data (network/env/args, self-modifying code) remain opaque to the static layer, but N1 surfaces them
  at runtime as hidden capabilities when a sensitive operation executes without any static declaration.
- Runtime-constructed payloads that stay opaque AND a plugin whose behavior never triggers sensitive ops →
  invisible to both layers (documented boundary).
- Non-source files (.jsx/.tsx/.vue/binaries/wasm/shell scripts) are not in the scan surface.
- **N4 canary (0.1.14) honest boundaries**: canary detection only confirms exfiltration of honeypot
  material — non-honeypot secrets (real user credentials) have no watermark and are out of scope · canary
  sharding/reassembly across multiple requests is deliberately not countered (detection-arms-race spiral,
  documented) · matches run on application-layer text (URL/body/spawn) — exfiltration via native binaries,
  process memory or physical side channels is invisible · canary matching only helps while canaries are
  active and the honeypot files exist (idempotent lures keep their canary).
- **N3 ledger (0.1.14) honest boundaries**: cross-session/ultra-slow exfiltration (sensitive read and
  outbound write not in the same plugin lifetime) is not covered — the ledger compares lifecycle counters
  only · native-binary internals are invisible (system-layer monitoring out of scope) · fd-level reads
  (fs.read(fd)) and fetch bodies are not byte-counted (the request write/end channel is) · per-plugin
  attribution is best-effort (mis-attributed ops land in no bucket and are ignored, never the wrong bucket).
- **N7 block (0.1.14) honest boundaries**: interception is process-memory and in-process — a restarted host
  re-evaluates the plugin, and ops not routed through the wrapped module properties (worker_threads realms,
  native addons, direct `require.cache` swaps) bypass interception (recorded boundary; the integrity canary
  + N3 signatures still alarm those paths) · family 2's overwrite guard depends on target existence at call
  time (TOCTOU-window edge, acceptable: the write still lands before any re-check) · family 1 blocks only
  after the first confirmation — the first destructive batch may already have landed (documented; canary hits
  and integrity writes are immediate) · per-family 3/4 `block` overrides shift false-positive risk onto the
  user by explicit configuration, never by default · unattributed plugin code (host/user origin) is never
  blocked by design — a malicious payload running under the host's own identity is out of scope (attribution
  is best-effort).
- **N6 version diff (0.1.15) honest boundaries**: the diff compares *declared* manifests only — a poisoned
  upgrade that hides its new capability behind runtime construction or third-party imports stays invisible to
  the manifest diff (N1's hidden-capability alarm + N2 decoding still cover those at runtime; a new
  third-party import is flagged as "capability unknown" rather than silently ignored) · "previous version" is
  the last *locally recorded* version (by recordedAt) — history only exists if the prior version was actually
  scanned here (first install of a package at an already-new version is a cold start and only records; the
  `vet_diff` tool shows what local history exists) · the store is a single local JSON file — concurrent
  writers share a last-write-wins save (load-modify-save is not mutex-protected; plugin loads are low-rate,
  accepted) · same-version reinstall is not diffed by design (same-version content tampering is covered by
  the content-baseline hash check, not N6).
- **N5 dynamic-string provenance (R15, 0.1.15) honest boundaries**: R15 only inspects the *sink call site*
  argument — a dynamic target built through an alias/helper the rule does not recognize, or reached via ESM
  named imports / worker_threads realms, is not flagged (N1 hidden-capability still alarms the runtime event) ·
  `http(s).request/get` with an unresolved plain identifier is deliberately not flagged (ambiguous with the
  options-object form — noise beats signal there) · info-level by design (v2): many legitimate plugins build
  URLs dynamically, so R15 never escalates on its own — it is the static-side context note for runtime
  signals (N1 red is the escalation) · target resolution is single-file lexical (no cross-module constant
  propagation), so a literal built from another module is treated as dynamic (flagged at info).

- T1/T2 can't catch worker_threads' independent realms, native plugins, process.binding, or low-traffic slow
  exfiltration. N1's mitigation here is honest exposure: the static layer cannot see those realms, so the first
  sensitive action from them triggers `n1-hidden` — it reports the blind spot rather than curing it (root cure
  belongs to OS-level monitoring, out of scope).
- T2 doesn't cover ESM named-import snapshots (Node interop snapshot; verified). 0.1.16 (C2) makes the
  blind spot explicit: N1 manifest `esmNamedBuiltins` + yellow `esm-guard-coverage` under `runtimeGuard: watch`
  — the runtime defense left is T1 sentinel + audit protocol, and this is stated, not silent.
- `internal/plugin` auto-scan only collects ≤6 levels deep, non-hidden sources (deep sources silently
  unscanned).
- /vet/status.json has no auth (the shield's polling needs anonymous GET); when dsh web binds to a
  non-loopback address, LAN clients can read scan conclusions — keep loopback binding if you care.
- **0.1.16 hardening honest boundaries**: C1's closure privacy holds for the *published* bundle — the per-file
  `lib/**` used by tests is developer-only and not shipped · C3's store self-check (M7) compares against
  in-process write hashes, so a *second vet instance* writing the same store is reported as tamper (DSH runs
  one instance per profile; accepted) · C4 treats `Error.stackTraceLimit < 2` or a replaced
  `prepareStackTrace` as tampered — a host framework that legitimately changes them *after* vet loads would
  trip `attribution-tampered` (snapshot is taken at vet load; report as integration note) · M9's cmdline check
  is Linux-only (`/proc`); other platforms keep the old kill-on-alive behavior.