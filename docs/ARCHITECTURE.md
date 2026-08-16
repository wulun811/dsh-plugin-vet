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
{ "ok": true, "report": { "engine", "sourceCount", "findings", "staticScore", "verdict" } }
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

## 5. Runtime guard (T1 + T2 + honeypot, alarm-only)

### 5.1 T1 sentinel (sidecar monitor)

- Every `runtimeIntervalMs` (default 2s) reads host /proc: VmRSS, child-process count, fd count, in-window
  memory growth.
- Over-limit → alarm JSON line back to host: memory over-limit red, fork burst red, fd over-limit yellow,
  growth yellow.
- Granularity = host-global (plugins share the process; can't attribute to a plugin).

### 5.2 T2 hooks (in-process wrapping)

Wraps the built-in exports of `fs`, `fs.promises`, `child_process` (property-level wrapping; ESM named-import
snapshots are a known side channel):

- Dangerous operation → capture stack → attribute to the plugin package name (stack-frame path ↔ plugin root
  longest-prefix match) → alarm.
- Coverage: sensitive-path writes/deletes, key-file reads, subprocesses with shell/download-exfiltration
  keywords, destructive commands (rm/mv/dd/mkfs…) hitting sensitive paths, shell redirection to sensitive
  paths, reconnaissance primitives (readdir/stat/access on sensitive paths), honeypot-lure touches.
- **Never blocks a call**; officially attributed spawn gets noise reduction.

### 5.3 Honeypot lures

- Default location `~/.dsh/.local`: directory/file names and contents carry no honeypot keywords
  (anti-honeypot).
- Lure values are well-formed but invalid fake credentials (real AWS/OpenAI/npm prefixes, random key bodies;
  id_rsa is a real-format one-shot RSA key pair, never used anywhere).
- Idempotent: existing lures aren't rewritten; deleted lures are rebuilt. Permissions 0700/0600.

### 5.4 Alarm aggregation (VetStatus)

- Ring buffer (default 20) + per-id dedup window (60s) + **TTL expiry (default 24h)** — a single false
  positive doesn't turn the shield permanently yellow/red.
- Shield level: any red → red; any yellow or a recent non-clean scan → yellow; otherwise green.

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

## 8. Known boundaries (honest list)

- Static scanning is a "speed bump + forensics layer", not a security boundary.
- Indirect references (alias functions, computed access, globalThis.process, indirect eval) yield only info or
  zero findings.
- Runtime-constructed payloads (base64 strings, hex assembly, self-modifying code) can bypass the AST rules.
- Non-source files (.jsx/.tsx/.vue/binaries/wasm/shell scripts) are not in the scan surface.
- T1/T2 can't catch worker_threads' independent realms, native plugins, process.binding, or low-traffic slow
  exfiltration.
- T2 doesn't cover ESM named-import snapshots (known side channel, documented in the README).
- `internal/plugin` auto-scan only collects ≤6 levels deep, non-hidden sources (deep sources silently
  unscanned).
- /vet/status.json has no auth (the shield's polling needs anonymous GET); when dsh web binds to a
  non-loopback address, LAN clients can read scan conclusions — keep loopback binding if you care.