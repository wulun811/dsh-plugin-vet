# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [0.3.13] - 2026-09-24

DSH `0.1.5-rc.2 → 0.1.7-rc.1` sync (the family grew 240 → 277 installed packages; the official
tag diff is 7.5k files). Two adaptation items came out of it plus one noise policy the upgrade
made urgent: after a family-wide version bump every official package is a *first-seen* strict
scan, and the published build outputs (`lib/**`, minified bundles, `.d.ts`) made 27 of 277
official packages non-clean (4 `critical`) — live auto-scan had already recorded 5 `suspicious`
verdicts and held the shield yellow. Engine version bumped `static-v25 → static-v26` — all
stale scanner caches are invalidated.

### Added — official-package artifact grading (`request.officialFamily`, static-v26)

- **Non-authored artifacts are graded as artifacts.** The engine classifies each scanned file:
  `*.d.ts` declarations, files under a **package-root-relative** build-output directory
  (`lib/dist/build/out/esm/cjs/umd`), and minified/bundled content (one line ≥1000 chars, or
  ≥3 lines over 500). Findings in those files get a category prefix
  (`构建产物：` / `压缩产物：` / `类型声明：`).
- **For official catalog members whose bytes are trusted the decisive tiers fold to `info`**
  (`critical`/`high` → `info`, message marked `（官方包降噪）`; first-seen and match both count,
  which is the upgrade case), so a DSH upgrade no longer turns the shield yellow on
  machine-generated output. Bytes count as trusted when they are unmodified, **or** when the
  current package hash is listed in `acknowledged-package-hashes` (a local patch the user has
  declared: the diff is claimed, the files are still machine-derived from official source). An
  **undeclared** `mismatch` does **not** fold — the premise no longer holds, so it keeps the
  strict scan; auto-scan goes further for declared patches (it skips scanning them entirely, so
  there is no artifact noise at all), while the `scan_plugin` tool face is an explicit audit
  request and therefore still scans and folds. Third-party packages keep full severity and only gain the
  prefix. Authored source (`src/**`, `scripts/**`, root-level `*.mjs`/`*.js`, `package.json`,
  `assets/**`) is never folded. Measured on the 0.1.7-rc.1 install: **27 → 4 non-clean**;
  the 4 residuals are all findings in authored source (`cordis`/`cordis-plugin-loader`/
  `schemastery` `src/**`, `libreoffice-kit-wasm` `sources/**/build.mjs`).
- **Identity verification is untouched** — the fold changes rule tiers only. Official identity
  is still established by the content-hash baseline, the registry reconciliation and the
  `official-not-in-catalog` yellow card; the host sets `officialFamily` from the official
  catalog (seed ∪ registry overlay), and the flag enters the cache key so a folded report can
  never be served to a third-party scan of the same bytes.
- **Official install hooks use the rule's own generic manifest semantics** (`R10` postinstall
  → `info` "capability surface: legitimate official install step") instead of the strict
  `high`, which auto-scan previously produced because it never passed `targetKind`.

### Fixed — R12 now understands array-form `dsh.bundle.patch`

- DSH 0.1.7-rc.1 accepts `dsh.bundle.patch` as a string **or an ordered array of files**
  (rc.2 only accepted a string; official `@deepseek-ai/dsh-web-app` already ships a 5-file
  array). The old check only understood strings, so an array declaration was skipped entirely
  — reproduced: an array with a missing file produced **zero findings and `clean`**. Now every
  declared path is checked (`high` naming the missing one), and a malformed declaration
  (empty array, non-string entries, non-string/non-array) is `high` — DSH's own
  `bundlePatchFiles` throws on exactly those shapes.

### Fixed — the DSH 0.1.7 type surface

- `@deepseek-ai/dsh-tools` no longer re-exports `JsonValue` (it moved to the new
  `@deepseek-ai/dsh-util-values` in the 0.1.7 family). vet's three tool modules imported it
  from `dsh-tools` → TS2614 against the new family. They now use a local structural mirror
  (`src/json-value.ts`) — zero new dependencies, nothing host-private in vet's public types,
  and immune to further host package splits.
- Dev dependencies bumped to the family vet is verified against (`cordis ^4.0.4`,
  `dsh-* ^0.1.7-rc.1`, `schemastery ^3.18.4`) so CI typechecks the real API. **Peer ranges stay
  wide** (`dsh-* ^0.1.1-rc.1`) — npm `latest` is still `0.1.5-rc.3`, and narrowing them would
  make DSH 0.1.7's new plugin peer preflight disable vet on older installs (the preflight
  evaluates with `includePrerelease`, which vet's ranges satisfy).
- Official catalog seed regenerated against the 0.1.7-rc.1 install tree: **278 → 319 names**
  (41 additions, no removals) — without it every newly split official package would raise an
  `official-not-in-catalog` yellow.

### Changed — declared local patches are an observation, not an alarm

- A hit in `acknowledged-package-hashes` now records `baseline-patch-ack` as **`info`** instead of
  `yellow` (all three sites: official mismatch, official first-seen-suspected, third-party P7).
  The declaration is the user's own act and the state is known and non-actionable, so it no longer
  counts toward `alarmCount` or the shield level — it stays visible in the panel's logged section,
  dismissible and restorable, and the "verify the patch origin" suggestion is still rendered.
  Sticky semantics are untouched: the ack is keyed to a specific `name@version` **hash**, so any
  further byte change stops matching and falls back to the undeclared-mismatch path (yellow, plus
  a strict scan on the tool face).
- Declared patches now also count as trusted bytes for artifact grading (see above): auto-scan
  skips them entirely, and `scan_plugin` folds their machine-generated artifacts to `info` while
  keeping every finding as evidence.

### Tests

- New `test/artifact-grading.test.ts` (14 cases): classifier units (including the regression
  that an **absolute** path containing the npm-global `lib/` prefix must not classify the whole
  package as build output), official fold vs third-party annotation, authored-source
  non-folding, `.d.ts` and minified bundles, cache separation between the two gradings, and the
  install-hook generic path.
- `test/scanner.test.ts` R12 block: array patch complete → clean, array with a missing file →
  `high` with the missing path as evidence, malformed shapes → `high`.
- `test/plugin.test.ts`: `officialFamily` four states (first-seen / match / undeclared mismatch /
  declared mismatch, the last one end-to-end through `scan()` — clean with the fold prefix);
  `test/baseline-reconcile.test.ts`: a declared patch is not scanned at all on the auto-scan path
  (deny runs `scanSync`, so an absent `lastScan` is a deterministic proof) and its alarm is `info`.

### Notes

- Verified against DSH `0.1.7-rc.1`: vet's API surface (`defineTool`, `ToolExecution`,
  `ToolExecutionResult`, cordis `Context`/`Fiber`, client `slots.inject/register`,
  `locale.register`, `WebRoute`, `dsh.client`/`dsh.bundle` manifests) is source-compatible;
  the code-execution guard targets (`run_code`/`cordis_define`/`cordis_run`/`workflow`) are
  unchanged in 0.1.7; the new peer preflight accepts vet's ranges.
- Boundary: the fold is a rule-tier policy, not a trust decision — an official-name package
  whose *authored source* carries a payload still scans decisively, and the host's hash/registry
  layer remains the authority on whether the bytes are the official ones.

## [0.3.12] - 2026-09-12

Self-review correction of the 0.3.11 R3 dev/ops tier: the shipped v24 implementation matched
the dev-verb **basename at any directory depth**, which capped nested runtime files too —
contradicting both the published intent ("root-level only, `scripts/` excluded") and the
0.3.9 line that `scripts/` is product code. Engine version bumped `static-v24 → static-v25`
— all stale scanner caches are invalidated.

### Fixed — R3 dev/ops tier is now genuinely package-root scoped

- The tier now applies only to files **flat at the package root** — depth 1 relative to the
  `package.json` location, which the engine derives from the file list (`RuleContext.pkgRoot`,
  scanner-internal). Nested files (`scripts/check-*.mjs`, `lib/install.js`, `src/dev-*.mjs`)
  never match, closing the "name a payload script dev-install.mjs to dodge the top tier"
  window at nested depths; runtime filenames (`transport/cli/desktop/start-*`) still never
  match. Without a `package.json` in the scan there is no root to anchor to, so the
  downgrade is conservatively **not** applied (finding stays `critical`).
- Everything else from 0.3.11 stands unchanged: `exit`/`reallyExit` only,
  `getBuiltinModule`/`mainModule`/`module` stay `critical` anywhere, test/CI downgrade
  precedence, `dev-script` marker, code mode and sandbox unaffected.

### Tests

- `test/r3-devtool-tier.test.ts` (rewritten): every tree now ships a `package.json` (the
  realistic registry shape); +cases for the correction: `scripts/check-pr-title.mjs`,
  `lib/install.js`, `src/dev-tool.mjs` stay `critical`; no-`package.json` scan → `critical`
  (conservative). The reporter's 8-plugin baseline is reenacted with a package root.
- `test/hardening-rules.test.ts`, `test/n5-dynamic-provenance.test.ts` —
  `ENGINE_VERSION` assertions `v24 → v25`.
- 80 test files, 1187 passed | 1 skipped.

## [0.3.11] - 2026-09-12

Follow-up release from the same registry partnership (zhousm666/dsh.so): wires their
64-hit R13 corpus as regression fixtures (delivered in §7 of the issue thread) and adds
an R3 (direct process access) mid-tier for dev/ops scripts, per their 329-plugin
dual-engine (static-v20 vs static-v23) evaluation. Engine version bumped
`static-v23 → static-v24` — all stale scanner caches are invalidated.

### Added — regression fixtures for the 64-hit R13 corpus (§7)

- `test/fixtures/r13-corpus-64.json` — the verbatim corpus as delivered: 64 findings /
  35 plugins (53 × `static-v20`, 11 legacy `engine: null`), reconciled against the issue
  body: 10 × `.onion` (0 valid addresses), 1 test-file hit, 1 redacted webhook template.
- `test/r13-corpus.test.ts` (data-driven):
  - ① 10 onion-marked entries → zero hits (all invalid labels);
  - ② 17 prose-or-label entries → zero hits (whole-literal endpoint shape);
  - ③ redacted entry → `info`;
  - ④ test-file entry → `info`, verdict `clean`;
  - ⑤ 9 source-verified deny-list/guard entries → `info` (evidence-faithful guard
    reenactment per plugin);
  - ⑥ shape-level guardrail: the corpus's bare endpoint literals still surface `high`
    in a plain literal context (`discord.com/api/webhooks`, `hooks.slack.com/services`,
    `http://169.254.169.254`) — no over-suppression; the sentence-cropped
    `http://metadata.google.internal.` is a shape boundary → zero hits;
  - ⑦ guard-context variants of ⑥ → `info`.

### Changed — R3 dev/ops-script mid-tier (registry verdict inflation)

Per their 329-plugin stratified sample: 8/329 plugins had their verdict pushed to
`critical` solely by R3-`critical` on root-level dev/ops scripts (`check-pr-title.mjs`,
`dev-install.mjs`, `uninstall.mjs`, `docker-init.mjs`, `cli.ts`, `transport.js`, …).

- `process.exit`/`process.reallyExit` in files whose basename is a clear dev/ops verb
  (`check-*`, `dev-*`, `docker-*`, `*-install`, exact lifecycle names, …) is downgraded
  `critical → high` — still decisive (verdict `suspicious` at worst, no longer the top
  banner) — with a greppable `dev-script` context marker in the message (same
  observability pattern as the R13 guard/test/redacted markers).
  - *Correction (0.3.12): the shipped v24 implementation matched the dev-verb basename
    at any directory depth, which also capped nested runtime files (`scripts/check-*.mjs`,
    `lib/install.js`). The v25 engine restricts the tier to package-root files
    (depth 1 relative to the `package.json` location); without a `package.json` in the
    scan the downgrade is conservatively not applied. See the 0.3.12 entry.*
- Deliberately narrow, so the 0.3.9 anti-false-negative stance is untouched:
  `getBuiltinModule`/`mainModule`/`module` stay `critical` anywhere; runtime-shaped
  filenames (`transport.js`, `cli.ts`, `desktop.ts`, `start-*.mjs`, `session-drive.mjs`)
  and `scripts/`-directory files (incl. `build.mjs`) are not matched
  (integration-dsh-so #5 unchanged); code mode and sandbox runtime unaffected.

### Tests

- `test/r3-devtool-tier.test.ts` — +9 cases: dev five-some downgraded, runtime three-some
  and `scripts/build.mjs` stay `critical`, `getBuiltinModule` in a dev script stays
  `critical`, test/CI downgrade precedence, code-mode unaffected, the reporter's 8-plugin
  baseline reenacted.
- `test/r13-corpus.test.ts` + `test/fixtures/r13-corpus-64.json` — 64-entry corpus wired
  (see above).
- `test/hardening-rules.test.ts`, `test/n5-dynamic-provenance.test.ts` —
  `ENGINE_VERSION` assertions `v23 → v24`.
- 80 test files, 1185 passed | 1 skipped.

## [0.3.10] - 2026-09-11

R13 (network-exfil) false-positive governance, based on an upstream bug report backed by a
registry-wide scan (14,672 vet records, 64 R13 hits over 35 plugins, zero actionable hits;
5 source-verified deny-list/SSRF-guard cases). Every claim was reproduced locally before
fixing. Engine version bumped `static-v22 → static-v23` — all stale scanner caches are
invalidated.

### Fixed — R13 `network-exfil` false positives (signal inversion)

Previously R13 flagged a substring match anywhere inside a string literal as
`high/likely` — the very literals security-conscious plugins use to *block* these
endpoints (deny lists, SSRF guards, CIDR tables), plus prose/labels/docstrings that
merely mention them. A purely defensive plugin (deny-list + docs) scored 4 / `suspicious`.
Now:

- **Endpoint shape required** — the whole literal must look like a host/IP/URL
  (template literals: any static segment counts). Prose, labels, docstrings and rule
  descriptions no longer produce findings at all.
- **Tor labels validated** — only real labels (`[a-z2-7]{16}` v2 / `[a-z2-7]{56}` v3) +
  `.onion` match; `action.onion`, bare `.onion`, and prose mentions no longer hit.
- **Deny-list / guard context downgraded to `info`** (capability-surface observation,
  verdict no longer upgraded): equality-comparison operands (`host === "metadata…"`),
  `new Set([…])` bindings consumed by `.has()`/`.includes()`/`.indexOf()`, `Object.freeze([…])`
  tables, and containers whose binding name carries guard semantics
  (`DENY/BLOCK/REFUSE/FORBID/GUARD/PRIVATE/RESERVED/INTERNAL/METADATA/SSRF`). Target lists
  (e.g. `Set` + `for..of` + `fetch`, no membership consumer) stay `high` — no false-negative
  regression.
- **Test/CI files downgraded to `info`** (same policy as R3's directory downgrade).
- **Redacted placeholders** (`[REDACTED]`, `***`, `xxxx`) downgraded to `info`.

True-positive channels (webhook URLs, cloud-metadata endpoints, valid onion addresses in
non-guard/test context) remain `high/likely`, verified by control fixtures.

### Tests

- `test/r13-r14.test.ts`: +9 regression cases covering every mitigation plus the
  no-false-negative controls (target-list `Set`, template URL with interpolation gap, N2
  base64 decode) — 78 test files, 1168 passed | 1 skipped.

## [0.3.9] - 2026-09-11

Comprehensive review-fix release: every true positive found in the full deep review
(four parallel review agents + individual reproduction against the built artifacts)
is addressed. Engine version bumped `static-v21 → static-v22` — all stale scanner
caches (including previously solidified partial results) are invalidated on first boot.

### Fixed — scanner engine (hardening / silent-evasion directions)

- **Budget-exhausted partial results are no longer written to cache** — a deadline-skip
  on the first scan no longer permanently solidifies a false `clean` (the payload file,
  typically ordered last, could get silently skipped forever even when the host budget
  later allows a full scan). Partial reports are simply not cached; the next scan
  re-scans in full.
- **A single broken file no longer crashes the whole package scan** — `const x = x + 'a';`
  (self-referential initializer, legal syntax) previously drove `stringyValue` into
  infinite recursion → `RangeError` → entire scan `ok:false`, silently discarding
  critical findings from the package's other files. `stringyValue`/`numberyValue` now
  have cycle detection + depth caps, and the scan loop is per-file fault-tolerant
  (new `R8-rule-error` meta finding; `R8` added to `RULE_IDS`).
- **Extensionless FIFO no longer hangs the scan** — `isExtensionlessJs` now has the same
  `stat().isFile()` guard as the native-binary sniffer (a FIFO with no extension could
  block the synchronous loop until host SIGKILL).
- **`extOf` computed from basename** — a dot-containing directory segment (e.g. the
  ubiquitous `~/.dsh/` install tree) previously fabricated a pseudo-extension for
  extensionless files, making the round-16 extensionless-bin detection dead code on
  real install paths.
- **`R9 isRedosPattern` linearized** — bracket pairing is precomputed in one pass with a
  work budget; a 64 KB deeply-nested regex previously took ~5.6 s inside a single file
  (non-preemptible, defeating the timeout structure).
- **Out-of-loop `package.json` reads are size-capped** — `packageShape` / `buildDepsInfo`
  / OSV no longer read a multi-GB forged manifest into memory (bypassing the 8 MB
  in-loop precheck).

### Fixed — host-side scan surface

- **`listSourceFiles` now includes bin/scripts-declared entry files** — extensionless
  `bin/cli` (npm standard form; previously invisible on the auto-scan path, verified
  with a live `curl|sh` payload) and any script-referenced path that exists as a regular
  file inside the package root are enumerated.
- **`isSensitiveFsPath` splits on both `/` and `\`** — a Windows-path credential target
  (`C:\Users\x\.ssh\id_rsa`) previously escaped the red-combo judgement entirely.
- **`isSensitivePath` folds `.`/`..` segments** (`normPath`) — a `..` traversal inside a
  `node_modules` exemption (`…/.dsh/node_modules/x/../../.credentials.yaml`) previously
  hid the real sensitive target from T2/N3/N1 (verified `false` before the fix).

### Fixed — runtime guard (observability)

- **Runtime alarms are emitted before the wrapped call** — fs/cp and network wrappers
  previously sank the alarm *after* invoking the original function, so a destructive
  command that exits non-zero (which `execSync` always throws) executed for real with
  zero alarms (the file-header contract and dgram/fetch side were already "report first,
  call after"). Ledger record is still best-effort on the failure path.
- **`n3-exfil-match` red now requires a read→write association window** — lifetime
  cumulative byte counts with no time gate made the [0.4, 3.0] ratio band a near-certain
  false red for any long-running plugin (verified: 2 KB startup secret read + 17×50 B
  unrelated telemetry writes → red). The magnitude red is now gated by the same
  `exfilAssocWindowMs` used by the soft-yellow branch.
- **`fs.open(path, { flag: 'w' })` object-form flags are honored** — family-2 "open =
  truncate" blocking and the fs-write classification both missed the object form.
- **T1 sentinel respawn budget is a sliding 30-minute window**, not a lifetime counter —
  occasional crashes no longer permanently disable respawn after 5 incidents.

### Fixed — N6 upgrade diff & store robustness

- **Native-binary "swap" is no longer silent** — `hasAnyAddition`/`describeDelta`/
  `vet_diff`/panel diffSummary now surface native *name* changes even when the boolean
  flag doesn't flip (previously `system.node → evil.node` produced zero alarms and no
  tool-layer display).
- **A single null/corrupt store record no longer neutralizes the whole audit center** —
  `findPreviousRecord`/`pruneCapabilities`/`history`/`label` skip non-object records
  (previously a `null` entry threw `TypeError` and the entire package's diff went silent).
- **Degenerate scans no longer write an N6 baseline** — when a scan parses zero sources
  with an empty capability manifest (files unreadable / all skipped), the version diff
  record is skipped at the caller, so the next normal scan is a cold start instead of a
  false-red cascade.
- **Contract M1 reconciliation strips the path from net-egress targets** —
  `webhook.site/post/abc` against a `connect: ['webhook.site']` contract no longer
  misreports an out-of-scope crossing (verified `within:false` before the fix).

### Fixed — persistence & presentation

- **`cordis.patch.yml.bak.latest` backup written via exclusive-tmp + rename** — the
  fixed-name `writeFileSync` followed a pre-planted symlink (SEC-5 discipline restored:
  rename replaces the link itself, not its target).
- **`dismiss`/`restore` memory state uses the same key as `snapshot.isFold`** — with a
  mergeKey alarm, "ignore" no longer silently fails when the persistent store cannot be
  written.
- **Persisted dismissal list is capped (200, LRU by `dismissedAt`)** — the only manual
  cleanup was "restore"; the on-disk list could grow unbounded.
- **`scan:upgrade` bucket that escalates to red now replaces the stale blue message.**
- **Telemetry-config baseline survives transient unreadable polls** — the "delete-then
  swap" two-phase rewrite can no longer reset the baseline with zero signal.

### Tests

New `test/review-0.3.9-fixes.test.ts` (11 cases) plus updated engine-version assertions
across the suite: self-referential initializer isolation, cache-gate on budget exhaust,
FIFO no-hang, >8 MB manifest cap, bin-entry enumeration + engine hit, backslash/traversal
sensitive paths, native swap visibility, null-record store guards, contract host+path
stripping. Full suite: **78 files, 1158 passed | 1 skipped**.

## [0.3.8] - 2026-09-10

### Added

- **Native binary awareness — C4 (0.3.8, DSH 0.1.5 sync)**: the official family ships
  platform binaries for the first time (`@deepseek-ai/node-addon-system-linux-x64` with
  `.node` addons), while precompiled native code is completely invisible to the JS rule
  surface — a third-party plugin smuggling `.node` blobs is a classic malicious technique.
  `CapabilityManifest` gains **`hasNativeBinary`** + **`nativeBinaries`** (deduped basenames,
  cap 10), computed from pure file-surface evidence: extension hits (`.node .dll .dylib .so
  .exe .wasm .ocx .sys`) plus magic revalidation (ELF / PE (MZ + `PE\0\0` at e_lfanew) /
  Mach-O thin+fat / wasm `\0asm`) that also catches compiled binaries renamed to `.js`
  inside the scan surface. Hit files are recorded, never read/parsed (no OOM or corpus
  contamination), and excluded from `sourceCount`. Host enumeration
  (`package-sources.listSourceFiles`) now includes native-extension files — and its
  previously case-sensitive extension matching is fixed (`.NODE`/`.SH` had once again slipped
  past the host filter). Nutrition label gains a `📦 原生二进制` flag + file list, plugin
  detail panel a seventh row, `vet_diff`/`scan_plugin` schema the new fields. Engine bumped
  to **static-v21** (output-shape change; old caches invalidated). Upgrade-diff severity:
  plain native addition stays blue `info` (official binary packages bump routinely — red
  spam violates the 0.3.6 aggregation doctrine), but native + (network | exec | sensitive
  path) added in the same version is a **red** combo (unauditable payload + delivery or
  execution leg). Legacy records (pre-0.3.8, field absent) surface native as
  first-observation info on the next version change.

## [0.3.7] - 2026-09-10

### Fixed

- **Local file entries (`file:` URL / `link:` / bare paths) no longer raise a bogus
  `audit-required:file:` yellow (0.3.7, DSH 0.1.5-rc.1 sync)**: the cordis 4.x loader
  normalizes profile inserts and local plugin entries to `file:///…` URLs (or keeps
  `link:/…` / bare-path forms). Feeding those to `extractPackageName` sliced them into the
  meaningless pseudo-package `file:` — never official-classifiable, never archive-matchable,
  so `requireAudit` produced a permanent, unactionable yellow every boot (the message even
  instructed agents to audit a package name that cannot exist). New `classifyLocalEntry`
  short-circuits package-name semantics for such entries: vet's own `link:` mount is fully
  exempt; other local entries record as one aggregated blue `info` observation row
  (`mergeKey: scan:local-entry`, full path in the message) that never touches `alarmCount`
  or shield level.

### Changed

- **Official catalog seed regenerated against the DSH 0.1.5-rc.1 installed family
  (261 → 278 names)**: the `@deepseek-ai/cordis` fork family now nests inside the installed
  `@deepseek-ai/dsh` tree (the `@jieai` global scope is gone); 19 new official names joined —
  session-format migration chain (`dsh-session-format`, `-catalog`, `-v0-to-v1/v1-to-v2/
  v2-to-v3`), `dsh-api-workspace-files`, `dsh-tool-present`, `dsh-http-proxy`,
  `dsh-chunked-list`, client-UI sidebar/upload splits, `@deepseek-ai/node-addon-system`
  (+`-linux-x64`, first platform-binary official packages); two pre-modularization
  `node-addon-landlock-run*` names dropped (renamed to `node-addon-system*`). This clears the
  stale post-upgrade `official-not-in-catalog` yellows on legit new packages while keeping
  genuine unknown `@deepseek-ai/*` names (typosquat defense) yellow.

## [0.3.6] - 2026-09-03

### Changed

- **Upgrade alarms (N6 upgrade-diff / upgrade-cold) downgraded to blue `info` and aggregated
  into one row (0.3.6, DSH npm-public modular upgrade feedback)**: after a DSH upgrade the
  whole official family bumps at once (observed live: 19× `upgrade-diff` + 1×
  `official-not-in-catalog` yellow alarms filled the 20-slot buffer and held the shield at
  yellow). Plain added capabilities now record as **info** observations (blue, excluded from
  `alarmCount` and shield level) and all upgrade alarms fold into a single row via
  `mergeKey: scan:upgrade` with a running count; red stays red for the high-risk combos
  (exec+network / sensitive-path+network / sensitive-path+exec — the poisoning signature),
  and `VetStatus` takes the max severity on merge so one red combo turns the whole aggregated
  row red. Shield floating upgrade-diff card renders info in blue (`tok.info`). Full per-package
  diffs remain available via `vet_diff` / nutrition labels / plugin detail.
- **Official catalog seed collection widened to four sources
  (`scripts/gen-official-catalog-seed.mjs`, 219 → 261 names)**: `dsh-src/packages` +
  `dsh-src/apps` (`@deepseek-ai/dsh`, `dsh-web-frontend`) + `dsh-src/vendor` (cordis fork
  family: `@deepseek-ai/cordis`, `cordis-plugin-*`, `cosmokit`, …) + the locally installed DSH
  family (`npm global root/@deepseek-ai/dsh/node_modules/@deepseek-ai`, auto-detected).
  Rationale: npm registry **search** does not index the cordis family (verified: no hits in
  2500 slots for `@deepseek-ai/cordis` / `cosmokit` / `schemastery` / `dsh-acp-app`), so the
  old packages-only seed let legit official packages appear "out of catalog" → yellow
  `official-not-in-catalog` watch after every upgrade; the widened seed makes the whole
  published family offline-trusted. Registry refresh remains the online complement for names
  unknown even to the seed.

### Added

- **Official catalog trust anchor (0.3.5, user-side 0.3.3 evaluation)**: `~/.dsh/vet/official-catalog.json`
  is now the source of truth for "what counts as an official `@deepseek-ai/*` package" — the
  seed is generated from `dsh-src/packages` (`scripts/gen-official-catalog-seed.mjs`), refreshed
  online via a bounded npm registry scope enumeration only when an out-of-catalog official-name
  appears (never at boot; deny mode stays zero-network). Judgment at scan time, which every
  plugin already passes: name in catalog + hash matches the official registry tarball → trusted
  and anchored on first sight (no more TOFU window); name in catalog + hash mismatch → **yellow
  observation, not red** (user decision: false positives burn more trust than misses); name not
  in catalog ("the extra one" an impostor would have to be) → **yellow observation**, no trust
  anchor, no interception — the scan + observation surface exposes impostors without runtime
  paranoia.
- **P8 fs-probe denoise for DSH housekeeping probes (0.3.5)**: `lstat/stat/access` against
  `~/.dsh/` lock-sibling files (`<file>.lock`, atomic-write stale-lock probes) and
  unattributed probes of session-log-shaped files are silent; official-name-attributed
  housekeeping probes (session-store owner rotation, settings persistence) are downgraded to a
  single aggregated **info** observation (visible, dismissible, excluded from `alarmCount` and
  shield level) instead of yellow spam. Third-party attribution, body reads/writes/deletes,
  honeypots and integrity canaries are untouched.

### Changed

- **`baseline-mismatch` for official packages is now yellow** (was red) in both deny and report
  paths, and `registry 对账不可用` no longer fails closed to red — a missing network check is not
  evidence of tampering. Third-party post-install baseline violations (P7 change-detection)
  remain red (high-confidence supply-chain signal, different trust class).
- **`first-seen` official packages are verified on first sight** (report mode): if local bytes
  equal the official registry tarball, the content trust anchor is registered immediately
  (`official-verified` info observation) instead of waiting for a second load to `match`.

### Fixed

- **Impostor first-sight detection hole**: a tarball naming itself `@deepseek-ai/*` used to
  record a first-seen baseline and pass review silently; with the official catalog it is
  flagged by a deterministic set-membership check the moment it loads.
- **Registry 核对单页截断（0.3.5 审查加固）**: 在线全集核对改为有界分页枚举（最多 4 页 ×
  250 槽位；实测 scope 231 个官方包散布在前 4 页——单页首页只含 201 个，尾部真官方包
  （如 `dsh-code-runtime-python`）此前永远无法「自动核对并入目录」，黄牌永续）。
- **首见校验不一致的黄不粘滞（0.3.5 审查加固）**: `baseline.json` 记录新增 `suspected`
  疑标——registry 首见校验/对账坐实「本机 ≠ 官方」时持久置位；此后本地基线自证 match
  不再自动授予内容信任锚（伪造 in-catalog 名 tarball「首见一次性黄牌 + 第二载 match
  自证入锚获运行时全域静默」的缝合上），改为持续黄牌 `official-match-suspected`，直到
  acknowledged-package-hashes 登记（= 用户声明负责，照常入锚 + baseline-patch-ack 黄牌）
  或字节更新为官方（对账一致自动清除疑标）。
- **首见验证并发限流（0.3.5 审查加固）**: report 模式全新 profile 首批官方包的 registry
  验证走小池（并发 ≤4），消除启动期网络/CPU 突发。
- **覆盖层读取大小上限（0.3.5 审查加固）**: official-catalog.json 超 8MB fail-open 回
  种子，拒绝整读撑内存。
- **deny 模式黄牌文案修正（0.3.5 审查加固）**: official-not-in-catalog 不再向 deny
  用户声称「已触发 registry 核对」（deny 零网络，P2-7）。
- **测试夹具隔离（0.3.5 审查加固）**: official-catalog 套件夹具改落临时 profile
  node_modules，不再骑在仓库 node_modules/@deepseek-ai 上（afterAll 无条件清理有
  误删真实依赖的风险）。
- **dsh.so logo 字标基线（0.3.5 审查修正）**: assets/dsh-so-logo-dark.svg 的 `.so`
  在部分渲染器（SVG-as-img/Firefox 等）因 `dominant-baseline="central"` 的 tspan
  继承不一致而整体下坠——改为两段共用显式字母基线（默认 alphabetic，全渲染器一致），
  `.so` 与 `dsh` 底边必然同高；y 按字标视觉中心 ≈ 方块中心标定，与旧渲染逐像素等价；
  顺带显式 width/height 归一化固有尺寸（300×79 vs 680×180 的跨渲染器差异）。
- **Suite 0.3.5 审查加固**: +catalog 分页/覆盖层上限/疑标-ack 联动用例 → **76 files /
  1135 tests**。

### Added

- **Alarm-fatigue rebuild for C2 coverage alerts (0.3.3, user-side 0.3.2 evaluation)**:
  official packages (content-baseline trust anchor, first-seen/match) no longer raise yellow
  `esm-guard-coverage` alarms — their ESM-named-builtin T2 blind spot is an accepted
  architectural fact, so it is now emitted as an **info observation** aggregated into a single
  cross-package row (`×N` count, mergeKey `scan:esm-guard-coverage:official`), excluded from
  `alarmCount` and shield level, while remaining visible in the alarm timeline / detail page /
  nutrition label (detection and retention layers stay untouched; N6 upgrade-diff and the T1
  sentinel keep covering change scenarios). Third-party packages keep the yellow alarm (that
  boundary **is** the audit value for them).
- **Persistent stateful dedup for coverage alerts (P3)**: new `~/.dsh/vet/known-boundaries.json`
  records `(kind, pkg, version, capabilitiesHash)` — the same boundary is not re-reported for
  unchanged version+capabilities across restarts (kills the "restart always replays the same
  batch" fatigue), while a capability-diff change (the only informative scenario, same change
  source as N6) re-raises. Fail-open: unreadable/unwritable store degrades to "re-report"
  (never silent). In-session `Map` now keys on the capability hash so capability changes can
  re-report even when the store cannot persist.
- **P7 fs-probe denoise**: unattributed (host-frame) lstat/stat/access probes of
  `~/.dsh/sessions/**` transient artifacts (`*.tmp` etc.) — DSH's own session-store housekeeping
  — no longer raise yellow `fs-probe`; plugin-attributed touches, write/delete operations,
  honeypots and integrity canaries still alarm.
- **P6 boot summary**: one debounced log line per startup scan wave summarizing C2 boundary
  observations (official = info-aggregated, third-party = yellow count), making the
  "14 official packages sharing one architectural boundary" fact explicit.
- **Suite 0.3.3**: `known-boundaries` store cases (auto-revoke on version/capability change,
  cross-process persistence, corrupt-record fail-open, read-only store), official-anchor C2
  info-aggregation wiring, third-party P3 dedup wiring (no replay / re-alarm on capability
  diff), mismatch-unconfirmed official names staying yellow, P7 denoise wiring + boundaries,
  and info-not-counted-in-`alarmCount` status cases → **75 files / 1113 tests**.

### Changed

- **`alarmCount` semantics narrowed to "actionable risk" (0.3.3)**: info-severity observations
  stay in the alarm list (logged section, dismissible) but no longer count into `alarmCount`
  or the shield level — the panel number now means "things you can and should act on" instead
  of mixing in permanently unresolvable architecture facts.

- **Intro panel copy census (round-23)**: hardcoded product claims replaced with observed
  numbers — 20 rule classes (R1–R20) / 144 regex-level detection forms (AST census of
  `scanner-bin/rules`) / 42 live alarm types (all `src/guard` kinds minus 9 internal
  classifiers); the stale "187 official packages" stat is removed; T2 wording corrected to
  observation/alarm-only (interception stays exclusive to N7 + deny/paranoid tiers, now stated
  in a positioning footnote); new bullets for the per-plugin detail page (rule-hit wall / OSV /
  nutrition label) and the audit center overview.
- **Deployment & docs (round-23)**: README gains the live
  [dsh.so risk badge](https://www.dsh.so/artifact/dsh-plugin-vet/), a verified deployment note
  (dsh.so publicly credits vet-led scanning on its plugin submission & security-report pages), and
  light/dark shield panel screenshots (`assets/white.jpg`, `assets/dark.jpg`; `assets` added to
  the pack whitelist). The shield intro panel now shows the vet logo plus the dsh.so logo with a
  one-line provider credit (logos inlined into the client bundle as data URIs).
- **Suite metrics round-22**: +`test/cli-args` cases, N7 `open/openSync` wiring regressions
  (wrapper-level family-1/2), `watchInvariantMessage` platform-gate cases, T2 arg-cap bounds
  (`firstString`/`allStrings`/`pathArgValue`/`joinCapped` + giant-arg classify), archive
  digit-suffix anti-forgery, `decideDenyBlock` fail-closed, trailing-slash instruction-file
  collection, vet_label null-array render, and a full engine regression block (require()-crash,
  `node:` capability flags, R3 element/destructure forms, R1/R2 escape forms + shadowing,
  R7 `sk-proj-`/`github_pat_`, R2 true-module-top-level) → **74 files / 1095 tests**;
  census 2864 standalone `expect(` (+18 helpers).

### Fixed

- **N7 family-2 `open`/`openSync` block was dead wiring (round-22, high)**: `decideBlock`'s
  SA2-5 branch (write-flag `open` on an existing credential → block) was fully implemented and
  unit-tested at the predicate level, but the runtime wrapper only invoked `decideBlock` for
  `BLOCK_FS_OPS` members — which excludes `open`/`openSync` — so `fs.openSync(cred,'w')`
  truncation was alarm-only even in default `block` mode. The wiring gate now includes
  `open`/`openSync`; family-1 (a previously confirmed destructive plugin) also blocks
  write-flag `open` on any target (read-only `open` stays unblocked).
- **scanner-wide crash on valid input (round-22, high)**: `const x = require();` (syntactically
  valid JS — runtime-error only) crashed `literalText(args[0])` inside `moduleBindings`
  (used by R9/R11/R20 + capability extraction) → in files mode one such file aborted the
  **entire multi-file scan** with `ok:false` (all findings lost). Argument-length guard added.
- **`runtimeGuard: watch` invariant failed on Windows/unsupported platforms (round-22)**:
  the T1-skip is deliberate design (platform gate, info log), but the load-time invariant only
  checked "not spawned" → with `hardened`/`paranoid` profiles the whole plugin failed to load
  on Windows (deny gate + T2 hooks gone with it). The invariant now keys on
  `sidecarSupportedOn(platform)` (pure predicate `watchInvariantMessage`).
- **T2 observer DoS by subject input size (round-22)**: `classifyOp` scanned full
  attacker-controlled args (`allStrings`/`firstString` had no cap) on every wrapped fs/child_process
  op — one pre-built giant string reused in a loop costs the host O(input) per event for calls
  that must fail anyway (PATH_MAX/argv limits). New `MAX_ARG_CHARS` (64 KB) per-argument cap +
  `joinCapped` total cap on the command scan; sensitive-token prefixes stay inside the window.
- **Archive loose-match anti-forgery hole (round-22)**: digit-leading sibling package names
  (`aws-sdk-2`'s record matched `hasAuditRecord('aws-sdk')` via the "version starts with digit"
  rule) — the exact false-"audited" class the M1 rule exists to stop, live on the deny
  fail-closed path. Loose match now requires the version segment not to continue with `-`
  (prerelease `1.0.0-beta.1` unaffected). `@a/b` vs `a-b` escape collision remains a documented
  boundary (archive compat).
- **`vet-gate --mode=deny` silently ran report mode (round-22)**: CLI only parsed `--key value`;
  the `=`-form (`--mode=deny`) produced the key `"mode=deny"` → `mode` undefined → deny gate
  never blocked, no error. `parseCliArgs` (moved to `src/cli-args.ts`, testable) handles both
  forms; `decideDenyBlock` also clamps an invalid `denyOn` to `critical` (fail-closed) instead
  of `x >= undefined` never blocking.
- **Nested `skills/**` instruction files silently dropped from the R18/G-1 surface (round-22)**:
  a package root with a trailing slash (`/pkg/` — typical shell/LLM input) made
  `full.slice(root.length + 1)` cut one extra character (`skills/…` → `kills/…`); root-level
  `AGENTS.md` passed by accident, masking it. Root is normalized before collection.
- **vet_label crashed on `ghostDeps: null` records (round-22)**: corrupt/legacy store entries
  with null dep arrays passed the `!== undefined` check and threw on `.length` (same class as
  the earlier DSH.SO render bug; the sibling fields had `Array.isArray` guards, these two did
  not). Both now guarded.
- **ENGINE static-v19 → static-v20 (round-22)**: R1/R2 escape regex widened (`return (process)`
  paren form, `globalThis['process']` prefix element access — both previously zero-hit) and
  single-sourced between the two rules; R1 alias resolution now honors shadowing (a parameter
  named like the alias no longer yields a false critical); R3 covers `globalThis['process']`
  element access and destructured members (`const { exit } = process; exit(1)` was info, now
  critical per member semantics); R7 covers `sk-proj-…` and `github_pat_…` (current OpenAI/
  GitHub key formats, the `-` previously broke the char class); R2's "top-level const require"
  denoise now truly requires module scope (function-scoped `const require` reports the code-mode
  escape-attempt medium again); capability extraction normalizes `node:`-prefixed requires
  (`require('node:http')` now sets `hasNetwork`, `node:child_process` `hasExec` — previously the
  N1 manifest under-reported and the runtime differential raised false hidden-capability reds).
- **Shield poll race (round-22)**: two in-flight polls (slow response + 5s interval or manual
  refresh) could let the older response overwrite the newer snapshot; a request-seq guard drops
  stale responses (same keep-previous-state discipline as the round-21 shape guard).
- **Bundle banner claimed an old version (round-22)**: `lib/index.bundle.js` banner hardcoded
  "0.1.16 C1" while the package moved on; it now embeds `package.json` version.
- **Client hardening nits (round-22)**: `ShieldIcon` mask ids are instance-unique (`useId`) —
  duplicate `<mask id>` across mounted shields was invalid HTML with cross-instance coupling;
  `PluginsListPanel` guards `staticScore`/`at` with `Number.isFinite` (null/NaN wire drift no
  longer unmounts the panel tree); `FoldSection` expanded bodies taller than 420 px scroll
  instead of silently clipping; `tools/execute` guard passes through non-`ToolExecutionResult`
  shapes from `next()` instead of crashing on `result.content`.

- **Shield snapshot-shape guard (round-21)**: the panel's 5s poll used to `JSON.parse` + blind-cast
  whatever `/vet/status.json` returned. The route has legitimate paths that answer **parseable
  non-snapshot JSON** (SEC-6 cross-origin 403 envelope `{ok:false,note}`, host error envelopes):
  such a payload overwrote the live snapshot and every render `??`-default turned
  "data unreachable" into a **fake all-green 0-alarms shield** — the worst silence for a security
  product. Poll now validates the wire shape (`level` string + `alarms` array) via a single-source
  predicate (`guard/shield-shape.ts`, bundled into the client by esbuild, tested from `lib/`) and
  keeps the previous snapshot on any mismatch (same behavior as fetch failure).
- **Suite metrics round-21**: +`test/shield-shape.test.ts` (3 cases incl. the 403 envelope regression),
  +2 `readTimes` time-gate cases in the N3 ledger suite (pure predicate + fake-timer integration),
  +3 TIME-parser empty-segment expects, +3 field-level corruption regressions (scalar array field in
  `diffManifests`, trailing-`#` comments in config parsing, unknown severity in self-scan scoring)
  → **74 files / 1070 tests**; census 2783 standalone `expect(`.

- **Metrics panel on macOS (round-20)**: the shield panel's live host metrics (`metrics.js`) are no
  longer Linux-only. Darwin reads come from the same stock CLT as the T1 sentinel — one
  `ps -A -w -w -o pid,ppid,rss,time,command` yields child count + mcp/vet per-category RSS + host CPU
  time (TIME-column diff, same multi-core semantics as the Linux utime+stime calc), `lsof -w -Fn`
  yields fd. Because `readHostMetrics` is polled **inside the host process** every 5s, all sampling is
  an **async snapshot cache** (TTL 4s; lsof 15s) — reads never block the host event loop, the first
  poll degrades to `—` and self-heals. The sampling probe (ps is itself a host child while running)
  is excluded from child counts via its pid. Disk-I/O remains Linux-only (no stock per-process byte
  counter on macOS) and now reports **−1 → `—`** in the panel instead of a fake `0`; Windows is
  unchanged except that honesty (V8-side numbers only). `countDarwinLsofFd` moved to a shared
  `darwin-sysinfo.ts` (single definition; `runtime-watch` re-exports for compatibility).
- **Suite metrics round-20**: +`test/metrics-darwin.test.ts` (17 cases: TIME/rss parsers, probe-excluded
  summarize, full dispatch via injected fake runner incl. inFlight coalescing / TTL cadence / stale-cache
  on timeout, real-`execFile` defaultRunAsync incl. timeout+missing-binary, cross-check against the real
  `ps` with production-shaped `--vet-sidecar`/mcp fixtures) → **73 files / 1062 tests**;
  `lib/guard/metrics.js` moved back into coverage accounting (deps-injection killed the "hard to mock"
  excuse; measured 89.24/93.96/89.24/84.43, gate unchanged 85/80).
- **T1 sentinel on macOS (round-19)**: the sentinel is no longer Linux-only. Darwin sampling goes
  through the stock CLT: one `ps -Axo pid=,ppid=,rss=` per tick yields host RSS + child count +
  self-ppid (the S6 host-death adoption check keeps its exact semantics), and `lsof -w -Fn` counts
  fds every 3rd tick (~6s refresh; timeout → -1 degrade — macOS lsof can block on stale mounts, so
  cadence trades freshness for safety). Singleton sibling-discovery and M9 kill-identity verification
  gain darwin paths (`ps -ww -o args=`); all platform logic lives in exported pure parsers +
  an injectable `CmdRunner` (unit-testable on Linux CI; the same real `ps` path also cross-verifies
  there since procps supports `-o args=`). Support floor: modern macOS only (11+, the Node 22 floor) —
  older versions auto-degrade (unparsable output → tick skipped, never crash/false-alarm). Windows
  and other platforms remain explicitly skipped by the platform gate. The Linux /proc path has
  zero behavior change; the host metrics panel (`metrics.js`) stays Linux-only (-1/0 fallback).
- **CI macOS matrix (round-19)**: `.github/workflows/ci.yml` verify job now runs on
  ubuntu-latest **and** macos-latest (build + typecheck + full suite + mutant gate + pack integrity +
  tarball dry-run); coverage-threshold enforcement stays on ubuntu (floor calibrated against Linux
  measurements). This turns "mac compatibility" from a claim into a per-commit gate.
- **Suite metrics round-19**: +`test/t1-darwin-watch.test.ts` (12 cases: pure ps/lsof/command-table
  parsers, the darwin `pidCmdlineIsVetSidecar` real-`ps` path cross-verified on Linux procps, and
  `sidecarMain` darwin dispatch with an injected fake runner) and the macOS platform-gate flip →
  **72 files / 1045 tests** (measured coverage 89.2/93.8/89.2/84.4; test-bucket runtime 288 → 300).
  The old `hostPpidChanged` positive test was Linux-gated (its `!==linux` behavior is the restricted-proc
  contract, not a bug) so the suite is honest on the macOS runner.
- **Assertion census reproducible (round-18)**: `scripts/count-assertions.mjs` lexically scans the
  test suite (comments/string literals excluded) and reports the assertion count — **2783 standalone
  `expect(` calls** as of round-21 (2751 at round-20, 2685 at round-19, 2660 at round-18) plus 16 chain-matcher helpers (`expect.any` /
  `expect.objectContaining` / `expect.stringContaining` / `expect.arrayContaining` used as embedded
  parameters) across all `.test.ts` files; README (en/zh) Development now documents the number and
  the reproduction command.
- **Mutant corpus round-17 (+3 mutants)**: +M32 (R16 subpath ghost — undeclared-parent subpath
  import must stay ghost), +M33 (R14 uppercase download-and-exec in non-JS scripts — the
  case-insensitivity regression guard), +M34 (R15 dynamic network targets — sink-observation
  regression guard). Corpus now **34 mutants / 8 benign controls across 17 rule faces** (R1×4, R2×5,
  R3×1, R5×1, R6×1, R7×1, R9×2, R10×1, R11×3, R13×2, R14×1, R15×1, R16×1, R17×1, R18×1, R19×1,
  R20×8; M12 spans R2+R6).
- **R16 subpath unit coverage (round-17)**: `v2-ghost-zombie` locks the three subpath cases —
  declared-parent subpath clean (`react/jsx-runtime`), scoped declared-parent clean,
  undeclared-parent subpath still ghost.
- **Suite metrics reproducible (round-17)**: 71 files / 1033 tests (v2-ghost +3 subpath cases,
  runtime-guard +2 semantic-hold asserts); the landing page's per-suite chart now derives from
  `scripts/test-buckets.mjs` (explicit file→area mapping over a vitest JSON output — reproducible
  totals; current buckets: 279 scanner / 288 runtime / 228 plugins / 151 self / 87 qa).

- **R20 secondary exec bindings / decode-path extensions (round-16, ENGINE `static-v17` → `static-v18`)**:
  the "dangerous command inside exec/spawn-family arguments" rule now fires through **secondary
  bindings** — destructuring aliases (`const {exec} = require('child_process')`), `util.promisify`
  -wrapped exec, alias-forwarded references, child_process values inlined inside object literals, and
  property-chain root determination (`obj.exec()` on an unknown object still never matches — the
  two-signal "exec call + dangerous command" gate holds), plus an `execAliasRefs` execution-position
  alias set. The N2 decode corpus gains `Array.join` assembly decoding and `Buffer.from(...)`
  concatenation / identifier recursion (atob alignment). `curl|sh` / `wget|sh` / PowerShell `-enc`
  shapes are now matched case-insensitively (R14's non-JS-script rules synced); dynamic mid-argument
  command strings with static fragments match via a placeholder pattern (`partial` annotation);
  argument-level and file-level corpora dedupe on identical text. Engine bump
  `static-v17 → static-v18` (rule change ⇒ cache invalidation).
- **R11/R9 detection-surface corrections (round-16)**: R11 `require('fs')` / `require('node:fs')`
  direct calls and destructure/alias-bound bare-identifier calls now count as fs bindings; the N2
  decoded corpus is gated by an fs footprint (no fs usage ⇒ a decoded string alone no longer triggers
  red). R9 fork-bomb/Worker counting is gated on child_process/worker_threads bindings — a local
  same-name function or object method no longer false-positives. `stringyValue`/`numberyValue` gain
  `isShadowedForStringy` lexical-shadowing protection (a shadowed parameter is no longer mis-parsed as
  a module-level constant; top-level constant parsing unchanged). Over-long literal backtracking in
  R7/capability is truncated (64KB / 16KB); `collectPathJoin` results pass `looksLikePath` so `'a/b'`
  shorthand is not silently collected as a sensitive path.
- **Scan-surface coverage (round-16)**: `extOf` normalizes case so `.SH`/`.CMD`/`.MD`/`.TS` uppercase
  variants enter the surface; extension-less files are parsed as JS when they carry a node shebang or
  are referenced from `package.json` `bin`/`scripts` (the npm-standard entry shape was previously
  invisible); `packageShape` collects `scripts` path tokens. `RULE_IDS` now enumerates `OSV` / `OSV-T`
  (engine data-source rules join the rule enum); protocol `ENGINE_VERSION` mirrored on both sides and
  lock tests synced.
- **Mutant corpus round-16 (+6 mutants, +2 controls)**: +M26–M31 cover R20 four obfuscated shapes,
  R11 direct require, N2 `Buffer.from` recursion; +C07/C08 guard the fs-footprint gating and
  shadowing-protection no-regression. Corpus now **31 mutants / 8 benign controls across 14 rule
  faces** (R1×4, R2×5, R3×1, R5×1, R6×1, R7×1, R9×2, R10×1, R11×3, R13×2, R17×1, R18×1, R19×1,
  R20×8; M12 spans R2+R6).

### Changed

- **Platform-support docs made unambiguous (round-19b)**: README (en/zh) gains a top-level
  **Platform Support** matrix (static scan / T2 hooks+honeypot+shield / T1 sentinel / metrics panel
  × Linux / macOS 11+ / Windows-other) as the single source of truth; the old limitation #16 prose
  (which read confusingly) collapses to a one-line pointer to it. Also records the CI reality:
  GitHub Actions has retired older hosted macOS images (`macos-latest` = macOS 15 Sequoia; 12 gone,
  13/14 deprecating), so only modern macOS is ever gate-tested — consistent with the Node 22 floor.
- **Coverage floor ratcheted (round-18)**: vitest thresholds lines/functions/statements **70 → 85**,
  branches **50 → 80**. The old floor sat ~19pp below the measured level (89.13/93.84/89.13/84.41 at
  this head) and could not catch regressions; the new floor keeps ~4pp headroom for normal
  refactoring while turning any material coverage drop red. README (en/zh) and the landing page
  threshold captions updated, plus the coverage chart/hero stat re-measured to the fresh values.

### Fixed

- **Field-level corruption permanently silenced a package's N6 upgrade-diff (round-21)**:
  `diffManifests` guards whole-object corruption (round-4 H2) and `?? []` guards missing fields, but a
  tampered/hand-edited store with an array field set to a scalar (`hosts: "abc"`) still threw inside
  `arrayDelta` (`'abc'.filter`) — swallowed by `recordScan`'s catch, which also meant the *new* record
  never landed: that package's upgrade-diff/upgrade-cold alarms died silently forever, exactly the
  invisible failure mode H2 promised to eliminate. `arrayDelta` now normalizes non-arrays to empty
  sets at entry (diff proceeds, never throws).
- **Trailing `# comments` merged into telemetry config values (round-21)**: the block/row extractors
  only stripped surrounding quotes, so `mode: FULL # prod` yielded `FULL # prod` — a pure-comment YAML
  edit (URL/mode unchanged) produced a false "telemetry config changed" yellow, and the comment text
  leaked into the alarm message via `mode=` (violating this module's raw-config-never-in-alarms
  privacy discipline). A shared `readYamlScalar` now truncates at the YAML-correct comment boundary
  (` #`) and extracts quoted content intact; flow form was already immune (regex stops at whitespace).
- **self-scan scoring could produce NaN `staticScore` (round-21)**: `computeSelfScore` kept a bare
  `WEIGHTS[f.severity]` lookup while the mirrored `scanner-bin/score.ts` gained `?? 0` in round-15 —
  KEEP IN SYNC drift. An unknown severity (protocol drift/tampered report JSON) poisoned the sum to
  NaN (serializes to `null`; and `Math.max/min` NaN propagation made a malformed report *look* maximal
  while `computeSelfVerdict` still returned clean). Now mirrored: unknown weights contribute 0.
- **Windows panel reported a firm "0 children" (round-21)**: on win32/other platforms
  `readHostMetrics` had no data source yet returned `childCount: 0` — indistinguishable from
  "actually zero", the same fake-0 dishonesty round-20 removed for disk-I/O. Now `—` (−1); the
  panel already had the `>= 0` dash guard, and `childCount` participates in no arithmetic anywhere
  (verified). Summed fields (`mcpRssMb`/`vetRssMb`/`cpuPct`) stay 0 by design — they feed the RAM
  total and history.
- **N3 ledger `readTimes` pruning could be DoS-amplified by its own subject (round-21)**: the
  round-5 lazy prune fired a **full Map scan on every read event** once size > 256 — and the
  hostile main scenario for this ledger is exactly "scan thousands of distinct paths in 10s"
  (credential hunting), where windowed keys never drop and each read pays O(size) → O(n²)
  observation cost inside the host. Pruning now has a time gate (at most one scan per window,
  pure predicate `shouldPruneReadTimes` + regression test with fake timers); memory stays bounded
  per window either way.
- **`parseDarwinCpuMs` silently accepted empty segments (round-21)**: `Number('') === 0`, so a
  malformed TIME like `12:` parsed as 12 minutes instead of being rejected — a wrong CPU delta,
  not a degrade. Empty segments are now explicit −1 (parser contract: fall out honestly).
- **L3 detail panel re-fetch loop when host passes an unstable `t` (round-21)**:
  `useEffect(..., [name, t])` — a fresh `t` function identity from the host's slot renderer on any
  parent re-render would retrigger the whole fetch (loading flash + refetch of `/vet/plugin`) even
  though only `name` matters. `t` now lives in a ref (latest translation still used for async
  error copy); effect depends on `[name]` only.
- **M9 sidecar test fixture was never alive (round-18)**: the PID-identity test spawned
  `node -e <script> --vet-sidecar` — after `-e`, node parses the flag as **its own option** and dies
  with `bad option` exit(9), so the "sidecar" child never survived a few milliseconds. The case
  passed only by racing the zombie's transient `/proc/<pid>/cmdline` residue (a synchronous test
  blocks libuv's reaper) — flaky under parallel load (1/1033 observed). Fixture now mirrors
  production shape (`[scriptFile, '--vet-sidecar']` — the flag is the script's argv, the option
  parser never sees it), with try/finally reaping (no child leak on assertion failure) and a 10s
  readiness window (QA-8 budget). Test-only: no engine/rule change, no ENGINE_VERSION bump. Also
  documented `scripts/count-assertions.mjs`'s known boundary (quoted regex literals can desync the
  string-state scan; cross-checked against pure grep — 2660/2660).
- **R16 ghost-dependency subpath false positive (round-17, ENGINE `static-v18` → `static-v19`)**: the
  ghost-dependency reconciliation matched imports by exact string only, so standard subpath imports
  such as `react/jsx-runtime` (parent declared in devDependencies) were reported as ghost — a generic
  false positive for every React client plugin, incl. vet's own `lib/client.js`. Ghost detection now
  resolves subpaths (`declared.some(d => i === d || i.startsWith(d + '/'))`): declared-parent subpaths
  never warn; undeclared-parent subpaths (`ghost-pkg/sub`) still do. Engine bump (rule change ⇒ cache
  invalidation); `react-dom` also declared in devDependencies (host-provided browser-external; the
  hand-written `react-dom.d.ts` stays).
- **R9 nested-quantifier self-findings (round-17)**: the two hot-path path heuristics in
  `runtime-denoise` used nested-quantifier regexes (`(?:[^/]+\/)*` for the `~/.dsh/**/node_modules`
  exemption, `(?:\.[a-z0-9]+)*` for session-log shard suffixes) — flagged medium by vet's own R9 and
  quadratic in the worst case on the per-fs-op hot path. Rewritten as linear index/walk checks with
  identical semantics (order/trailing-slash and non-alphanumeric-shard edges asserted in
  `runtime-guard.test.ts`). vet's self-scan no longer reports either.
- **Landing-page wording (round-17)**: `site/index.html` claimed vet "never blocks" (meta description,
  `f2.tag`, `feat.sub`, `t5`); the opt-in watch mode (hardened/paranoid) indeed blocks confirmed
  destructive operations for N7 families 1/2 by default. Wording now matches the package description
  ("Alarm-only; blocks confirmed destructive ops.") — alarm-only by default, interception only in the
  opt-in watch mode and only for confirmed destructive operations. Same pass for the site's en/zh
  dictionaries.

- **Static-scan correctness round-up (round-16)**: the above extensions also fix blind spots — the
  binding/decode/casing/ext-surface gaps meant real shapes previously produced zero findings (R20 via
  `promisify`/destructured aliases, decodes via `Array.join`/`Buffer.from`, uppercase-ext and
  shebang/bin entry files, R11 direct `require('fs')` calls); the fs-footprint gate removes decoded-
  string-only false positives, the binding gate removes R9 local-function false positives, and
  `isShadowedForStringy` removes parameter-shadowing misreads. Regression suite
  `test/round16-regressions.test.ts` + 8 fixtures; 8 new fixed-case assertions across
  `r20-shell-exec` / `n2-decode` / `n5-dynamic-provenance` / `hardening-rules`.
- **Runtime + security hardening (round-16)** — trust anchor, corridors, write paths, egress:
  - **`isOfficialTrusted` trust anchor (SEC-1)**: runtime-defense suppression (alarm/block/leak/canary
    rows — dgram alarm+canary, fetch alarm, N7 block gate in runtime-patch/runtime-guard/runtime-sink)
    is now registered **only by content verification** — baseline match (twice-verified installs) or a
    registry-equal-hash reconciliation; a **first-seen/TOFU official-name package is deliberately NOT
    registered** (runtime defenses stay active in the riskiest window); `reconcileMismatch` registers
    only in the `officialHash === verdict.hash` branch (resolved-but-different = tampered, never
    trusted); vet itself is always trusted; display corridors (ledgers, loopback) keep the name-based
    `isOfficial` label.
  - **Spawn relative sensitive tokens (SA2-2)**: bare `rm`/`shred`/`truncate`/`dd`/`mkfs*` tokens in
    spawn args classify as destruction-leading (sensitive if any relative path); `cp`/`mv` excluded
    (backup-pattern noise).
  - **Status ring red-preserving trim (SA2-3)**: `trimToMax` never evicts red alarms to make room for
    a yellow storm; all-red only drops the oldest red.
  - **N7 family-2 extensions (SA2-4/-5)**: paired-path overwrite ops (`cp`/`copyFile`/`rename`) cover
    the destination side (with `safeExists` for the soft target), and `open`/`openSync` write-capable
    flags (`r+`/`w+`/`a`/`wx`) enter family 2 — credential faces stay interceptable under
    write-open/overwrite shapes.
  - **Capability-diff observation caps (SA2-7)**: per-kind 128 / per-plugin 200 records, oldest
    evicted.
  - **`internal/plugin` root-undefined fail-closed (SA2-6)**: with an unresolvable package root, deny
    now fails closed (blocked) unless either a human audit archive exists under `requireAudit` (D30
    documented contract) or the entry is vet itself (realpath-verified, self-boot safety); the vet
    self-exemption was narrowed from name to realpath identity.
  - **Registry reconciliation resource bounds (SEC-2/3)**: `tar -tvzf` member-type pre-check rejects
    device members (`l`/`h`/`c`/`b`/`p` — hardlinks/char/block/FIFO, GNU+BSD dual-layout size parse);
    total unpacked 1GB / 100k-member caps; 32MB stdio cap.
  - **`scan-summaries` key sanitization (SEC-4)**: record keys `__proto__`/`prototype`/`constructor`
    are normalized (`_` + name) on read/write/query — prototype-pollution containment.
  - **Exclusive-mode atomic writes (SEC-5)**: `writeTmpExclusive` (O_EXCL `wx`) for all six store
    paths (content-baseline, version-diff, stats, dismissed-alerts, scan-summaries, status-route
    patch) — a pre-planted symlink is never followed; EEXIST → unlink + retry; honeypot decoy/canary
    writes use inline `wx`.
  - **Status-route same-origin check (SEC-6)**: `GET /vet/status.json` + `/vet/plugin` return 403 when
    an `Origin` header is present and does not match the host (missing Origin passes — same-origin
    browser GETs carry none).
  - Tests: `test/round16-runtime-security.test.ts` (14 cases); `n7-confirm-block` /
    `n3-attribution` updated to trust-anchor semantics (+`resetOfficialTrustForTest`).
- **Engineering / gates (round-16)**: `mutant-score --gate` now enforces the **rule kill matrix** —
  any rule row with killed < required fails the gate (prevents one mutant's other-rule hit from
  watering down per-rule coverage); CI runs `check:mutants` + `check-pack-integrity` on every push,
  `check:self` only on tag pushes (main-branch dev-tree pins don't block daily commits — re-pin
  follows the release arrangement); self-pin scope narrowed to the shipped-artifact whitelist
  (`lib/**` + `docs/ARCHITECTURE.md`; `docs/local`, `MUTANT-QA.md` excluded — they never enter the
  tarball); `plugin.test` report-scan assertion wrapped in `vi.waitFor` (parallel-CI subprocess
  settling jitter); 9 test files unified from `../src` to `../lib` imports (same channel as the other
  62); v020 fixture literals switched to runtime-joined constants (repo secret-scan discipline).

- **R20 — shell download-and-exec in JS exec/spawn-family arguments (round-15)**: hardcoded `curl|sh` /
  `wget|sh` / PowerShell `-enc`/IEX/DownloadString / system download primitives (certutil/bitsadmin/mshta/
  regsvr32/rundll32) / interpreter `-c`-style download-exec **inside literal arguments of exec/spawn/
  execFile/fork** is now a static finding — high for pipe/encoded/primitive shapes (verdict → suspicious),
  medium for `curl -o` download-to-disk (download ≠ exec). Fires only when the file has a child_process
  binding ("exec call + dangerous command" two-signal gate — an unknown-object `obj.exec()` never matches);
  array-form args (`spawn('sh', ['-c', …])`) are expanded element-wise; N2-decoded args (base64/hex/
  charCode) are matched with a `decodedFrom` annotation and the file-level decoded corpus joins the match;
  generic packages and test/CI files downgrade to info. Engine `static-v16 → static-v17` (rule change ⇒
  cache invalidation). Before this, the shape had **zero static findings** (R6 has no curl pattern, R14
  scans only non-JS script files) — surfaced in an external adversarial drill (curl|bash planted signal
  was graded info-level only). Tests: 3 new mutants (M23-M25) + 1 benign control (C06) + dedicated suite.
- **capability manifest: `path.join` / `path.resolve` argument collection (round-15)**: literal path
  segments in join/resolve calls now enter `fsPaths` ("宁可多列" — e.g. `path.join(os.homedir(), '.ssh',
  'id_rsa')` records `.ssh` and `id_rsa` even with a dynamic prefix; all-literal calls also record the
  posix-joined full path). Dynamic arguments are never guessed. Closes the assembled-path static blind
  spot (drill-verified: such code previously produced `fsPaths=[]`) for the nutrition label / N6 diff /
  N1 hidden-capability baseline — declared is no longer misjudged as hidden.
- **Plugin-list pagination (round-21)**: users with many third-party plugins couldn't see past the
  first 20 rows — "Recent plugins" panel now renders the index page by page (20 rows per page) and
  "Audit status" rows page by page (14 rows per page), each page appended via a "Load more" button
  (shown X/Y), so the corridor no longer truncates at 20. Server index cap raised 50 → 200 (aligned
  with the scan-summaries LRU of 200 — status.json is polled whole every 5s, ~200 rows is a few dozen
  KB on a local handshake, no lag; the client only draws one page at a time, never all 200). Honest
  bound: with more than 200 third-party packages the index truncates at 200 (scan-summaries LRU is the
  same ceiling); that scale is outside the realistic corridor and would need a real server-side page
  endpoint.

### Fixed

- **README / README.zh / SECURITY.md drift sync (round-15)**: the docs claimed vet "never acts / never
  blocks / alarm-only" while the code ships N7 confirmation-blocking (default `confirmBlock: block`
  families 1/2, active whenever `runtimeGuard: watch` is on — incl. via `hardened` tier / shield toggle).
  Positioning, config rows, the runtime-monitoring headings, trust boundary 7 and SECURITY.md now state
  the real interception scopes precisely. Also fixed: stale test counts ("250 cases" / "633 cases" →
  71 files / 1029 tests, coverage thresholds incl. statements ≥ 70%), the stale `0.1.4.tgz` install
  example, a broken R18 table row + a duplicated R16 row, the missing EN `selfScan` Trusted-card and
  0.3.1 guard↔tier-binding notes, the missing `statements` coverage threshold, and the supply-chain row
  that listed **dependency-version vulnerabilities as "not parsed"** while the scanner queries OSV for the
  plugin + its direct dependencies (exact versions; transitive trees via opt-in `upstream-radar`); the
  stale "known-vulnerability matching is deferred (D15)" comment in `supply-chain.ts` now points at
  `engine.ts` `checkOsv` / `transitiveDeps`. R20 rows added to both rule tables; engine version bumped in
  the docs (`static-v17`).
- **win32 compatibility fixes (backported from Windows testing)**: ① cache-entry filenames rename
  `sha256:` → `sha256_` (a `:` is illegal in Windows filenames, legal on Linux — read/write sides stay
  symmetric; Linux behavior unchanged, only a one-time cold cache). ② `scan-plugin` file-target
  absolute-path check `startsWith('/')` → `isAbsolute()` (cross-platform equivalent on POSIX).
  ③ `status-route` patch writes fsync via an `r+` writable handle with failure-degradation (Windows
  rejects fsync on read-only handles with EPERM; rename still guarantees atomic replacement, fsync is
  only crash-durability insurance). ④ tests: `/proc`-based runtime-guard cases and the `/dev/null`
  assertion get win32 branches/skips.
- **release-gate hardening: flaky timing test made load-robust (pre-0.3.1)**: the
  `n3-mass-delete` alarm-window test used a 5 ms observation window and a 30 ms wait; six synchronous
  `unlink` events can straddle the window when a GC/microtask pause lands mid-loop under parallel test
  load (seen when vitest and the mutant gate ran concurrently), failing `expect(hit).toBe(true)` with a
  false negative. The window is now 60 ms and the post-window wait 150 ms (2.5× margin) — semantics
  unchanged (threshold reached inside the window → alarm; after expiry, stale counts must never re-alarm).
  Verified 3× in isolation and in the full suite.
- **round-20 test write-through fix: guard scan-chain tests no longer pollute the real `~/.dsh/vet/`**:
  `baseline-reconcile` (`@deepseek-ai/vet-fixture`), `hardening-ops` C2 wiring (`@esm-test/pkg`) and
  `n6-version-diff` internal/plugin wiring (`@vet-test/n6pkg`) ran the real scan chain while isolating
  only baseline/caps dirs, missing summaries — `recordScanSummary`/`recordVersionScan` write to disk
  unconditionally once a scan completes, so fixture packages leaked into the user's real
  `~/.dsh/vet/capabilities.json` (4 residue records measured; after a restart they surfaced as
  "third-party pending audits"). Fix: all three now redirect `setCapabilitiesDirForTest` +
  `setSummariesDirForTest` to tmp (same discipline as plugin.test.ts round-17), reset in afterEach;
  verified after the run: real file mtime unchanged, zero test residue in content.
- **round-19 official packages removed from the audit corridors entirely (replacing round-18's
  label-in-place stopgap)**: round-18 gave official packages an "official plugin" label but kept them in
  the plugin index — but from the user's point of view, "who cares how official plugins look": the
  corridor's purpose is "among the third-party plugins the user installed, which need attention/audit".
  DSH-shipped official packages are guarded by content-hash baseline + static scan + alarms, unrelated to
  these lists; however nice the label, 20 index slots / 14 audit rows were still flooded by dozens of
  official packages while the third-party plugins that actually need review sank out of view.
  Fix: `buildAuditSummary` now `continue`s for official/trusted packages (`isOfficial`: `@deepseek-ai/*`
  plus vet itself) — none appear in pending-audit, new-install or plugin-index corridors; every slot goes
  to third-party. Kept: ① official scan/hash/alarm paths unchanged (D1 intact, mismatch still red);
  ② `/vet/plugin` detail endpoint still carries the `official` flag and the detail page keeps the
  "official plugin" chip (when an official package is opened by name from an alarm/honeypot, it explains
  why there is no audit archive) — the entry is no longer a corridor citizen. round-18's index `official`
  field and client badge branches removed (index no longer contains official entries; dead code).
- **round-18 official packages no longer shown as "stranger/un-audited" plugins** (superseded by
  round-19 — the earlier fix for the same problem: label-in-place instead of corridor removal):
  round-17 fixed only the pending-audit count — the audit center rows, 🆕 new-install badge and plugin
  detail chip still rendered from the index/`newPlugins`, so official packages (no human audit archive by
  design — gate = content-hash baseline + static scan) all showed "⏳ installed without an audit record"
  and counted as "new". Fix: ① index/detail carry an `official` flag (`isOfficial`: `@deepseek-ai/*`
  plus vet itself) — audit rows and the plugin bus show "official plugin" + 🛡 badge (hover explains the
  gate, no human archive required), ranked alongside "audited" instead of pending (third-party pending
  stays on top); ② `newPlugins` excludes official packages (shipped with DSH, not "newly-appeared
  stranger packages") — the 🆕 badge counts third-party only; ③ plugin detail gains the "official plugin"
  chip (hover, same explanation). Statically suspicious/blocked official packages still show ⚠/⛔ first
  (D1 semantics unchanged: first-seen is still fully scanned).
- **round-17 official-package audit-required alarm storm resolution**: after round-16 (decision 1)
  unblocked the official-package skip path, the requireAudit gate fired at every official package — with
  `requireAudit: true`, all DSH-bundled official plugins (`@deepseek-ai/*`, dozens) raised
  "audit not completed" yellow alarms on load and flooded the audit-center pending backlog. Fix:
  ① gate strictly limited to third-party (`official.kind === 'not-official'`) — official packages
  (first-seen/match) keep the content-hash baseline + static scan gate (decision 1 semantics unchanged:
  first-seen still fully scanned, only deny escalation exempt; no human audit archive required);
  ② pending-audit list excludes `@deepseek-ai/*` (plugin index/new-install list still keep official
  entries). Behavior returns to the pre-round-16 official exempt short-circuit and the documented
  "third-party plugins" scope.
- **round-16 official packages first-seen also run the static scan (decision 1)**: `@deepseek-ai/*`
  first-seen/content-identical packages no longer skip scanning entirely — the self-hashed baseline
  cannot stop a forged official-name first-seen from being trusted (a malicious tarball records its own
  bytes as the baseline on first install); first-seen/match now scan statically as usual (results
  archived / capability diff / observation alarms all run), only deny escalation is exempt (the official
  trust anchor is not blocked by a static verdict); allowlist / cordis builtin / content-baseline
  disabled (explicit user choice) still skip entirely.
- **round-16 self-pin = shipped-artifact scope + any-pin match (decision 2, upgrade experience first)**:
  pin/self-scan scope changed from the src source tree to the shipped artifacts (`lib/**` + root
  manifests + `docs/**`, `vet-self-pins.json` self-reference excluded) — a production install (tarball
  contains only lib/) reaches pinned-match on first self-scan (Trusted available), no longer forever
  dev-tree; pinned-match now means byte-matching any published pin — during an upgrade window (host
  process version lag / pin table and package.json interleaved updates) the two vets no longer refuse
  each other; replaced/tampered bytes still match no pin and are fully scanned as strangers.
- **round-16 scan_plugin file-target bounding (decision 3)**: file scans accept only absolute paths +
  regular files — rejecting relative/`~` expansion, directories, devices/FIFOs/symlinks (`/dev/zero` etc.
  infinite-stream readFileSync has no EOF and blows up the scanner subprocess memory, fifo hangs until
  timeout); the engine cacheKey stage and scan loop skip non-regular files with R8.
- **round-16 second batch of low-severity fixes** (details in each module comment): ① sidecar hot-reload
  mutual-kill race — an instance that already armed a sentinel no longer kill-and-takeover (prevents
  new/old instances killing each other in a loop); takeover waits for the old sentinel to exit before
  spawning (prevents sibling-lock self-kill spinning respawn×5); fast exit(0) does not count toward the
  respawn cap; ② exfil-ledger window array count cap (2048, preventing unbounded growth and O(n²) from a
  million events in 10s) + spawn↔net association switched to single pointers O(n+m); ③ patchModule/
  patchNetworkModule roll back already-wrapped ops when a mid-loop throw occurs (prevents half-wrapped
  residue); ④ applyRuntimeGuardImmediate failure path calls disposeActiveGuard to reset (prevents
  "config shows off but hooks/sentinel half-alive"); ⑤ when stack attribution is tampered, N7 family-1
  interception degradation is explicitly named in the C4 red alarm text (family-2 credential destruction
  still blocks); ⑥ the sentinel re-checks the host ppid every round — after host exit is adopted by init,
  it self-kills immediately even if the PID was reused by the system (hedge against kill(0) misjudging
  liveness); ⑦ guard toggle/tier writes fsync tmp before rename (prevents empty config on power loss/
  crash); ⑧ cordis_run dead entries become a tripwire — when a future schema carries
  code/source/script payloads they immediately enter the scan surface (zero false positives today);
  ⑨ unreadable audit archive dir → one-time warn (previously silently treated as no-archive, so deny
  could block a legit plugin for a false-negative reason); ⑩ baseline save failure → yellow
  baseline-save-fail (disk full/perms no longer silent; wired into official/third-party/reconcile paths).
- **0.3.1 tier ↔ guard linkage**: Light defense ⇔ guard off, Medium/High defense ⇔ guard on — toggling
  "enable/disable runtime guard" automatically links the defense tier (enabling raises the tier to
  medium, an already-set high tier is not downgraded), selecting a tier switches the guard immediately;
  the server response carries `profile` and the panel tier badge updates instantly — the contradictory
  "guard enabled but shows light defense" state no longer occurs.
- **0.3.1 plugin-detail scoped-package-name fix**: `/vet/plugin`'s name validation wrongly treated `/`
  as an illegal character, so scoped packages (`@scope/name`) always got 400 on detail open (frontend
  showed "no information") — now allows `/`, rejects only control chars/backslash/`..` traversal, with a
  regression test.
- **0.3.1 honeypot copy**: no longer uses tier jargon users can't read (hardened/paranoid) — "auto-enabled
  by Medium/High defense profile, or set honeypot.enabled manually".
- **0.3.1 layered-stack positioning root-cause fix**: secondary/tertiary panels restored to the old
  isomorphic positioning — `left: '100%'` (root container shrinks to the main panel's real rendered
  width) + `top:0/bottom:0` equal height, the browser computes the outer edge. The redesign had used a
  fixed pixel offset (`+340`) without locking box-sizing, so with the host's content-box the main panel
  rendered ~368px (340+padding) and the layer's left edge pressed 28px into the main panel's right edge —
  the root cause of "all secondary UIs stack on top of the main panel" (user feedback: the old
  `left: calc(100%+8px)` was fine; it started overlapping after the planned redesign).
- **0.3.1 guard-toggle transient notice**: button "enabling…/disabling…" → success "enabled/disabled!"
  auto-dismisses after 2s (failure keeps a red note), no lingering persistent copy.
- **0.3.1 guard toggle takes effect immediately**: the toggle assembles/disassembles the runtime guard
  right away, no DSH restart required (the write itself is line-level surgery, `!!js` tag safe).

### Added

- **Panel redesign 0.3.0 (OBSIDIAN MOSS GOLD)**: the shield GUI was reskinned per docs/local design
  mockups and split into directories (`client/theme.ts` dual-board theme tokens + `components/` +
  `panels/`; Shield.tsx narrowed to an orchestration layer). Main panel: 3 ring-trend composite cards
  (decision ②b: value + direction in one card; client/server 64-point trend windows), memory and
  run-time I·O collapsible sections (green collapsed / yellow·red auto-expanded, red danger zone red-lit
  with inner glow, fd-leak warning), big defense-stat numbers, audit-bar entry. Layered-stack interaction
  (D2/D7): secondary panels always cascade out from the main panel's right edge (**not the mockup's
  browser-right-edge drawer**), side-by-side never overlapping, hugging the main panel's outer edge
  (final revision: no whole-group left-shift; extreme narrow windows overflow to the right), Esc steps
  back layer by layer; plugin detail is the only tertiary panel — L1 "recent scans" click opens the
  **recent-plugin list (20-entry corridor)** before detail, timeline/audit center open detail directly on
  plugin-name click. New data plane (all read-only GET / optional status.json fields, backward compatible
  with old clients): `metricsHistory` ring buffer (64 points); **scan-summary store**
  `~/.dsh/vet/scan-summaries.json` (per-package verdict/score/rule-codes/OSV summary, atomic write +
  LRU200 + write-on-change, dual-path written by auto-scan and vet-gate); audit & honeypot aggregator
  (pending = vet-seen ∩ no-archive union semantics, new = first-seen within 72h, honeypot touches
  aggregated from the alarm stream, batched archive probe = one readdir to avoid N-package amplification);
  `GET /vet/plugin?name=` detail endpoint (capability label + scan summary + version diff + audit state).
  Floating cards: upgrade-diff and honeypot alarm cards appear with state and are clickable to drill in.
  a11y/i18n: Esc layer-back, prefers-reduced-motion full-tree degradation, ~50 new i18n keys zh/en synced.

### Fixed

- **Guard-toggle incident fix (2026-08-26)**: the shield "enable/disable runtime guard" and "safety tier"
  write paths used js-yaml full re-serialization of `cordis.patch.yml` — js-yaml does not understand
  cordis's `!!js` expressions (e.g. `port: !!js ctx.webStartup.port ?? 3456`), load throws "unknown tag"
  and the whole patch was rewritten to only the vet entry, wiping webserver/insert/settings configs;
  DSH's `watchUserPatches` watches that file and hot-reloads, so applying the broken patch caused LAN
  service anomalies/connection drops. Fix: (1) write path changed to **line-level text surgery** — only
  add/remove/replace the `runtimeGuard`/`profile` single lines inside the vet entry; comment headers,
  `!!js` expressions, other plugin entries and the insert list are preserved verbatim; shapes that cannot
  be safely line-edited (multi-document `---` / inline vet config expression) fall back to object
  reconstruction with a check prompt, and other entries with syntax damage fail closed (refuse to write,
  no stacking writes); (2) pre-write YAML validation extended with `!!js`/`!!js/function` tags (canonical
  long name `tag:yaml.org,2002:js`, kept as string, never executed) — valid DSH files are no longer
  misjudged as damaged; (3) **toggle takes effect immediately**: after writing the config, the runtime
  guard is reassembled/disassembled in the current process right away (reuses installRuntimeGuard's
  prevGuardDisposer re-entry: old sentinel swapped out, T2 hooks reinstalled, config object flipped live,
  new state visible on the next status.json poll), no dsh-web restart required; the teardown path cleans
  by the module-level active disposer, so freshly assembled instances are not left uncleaned.

### Added

- **Mutant corpus kill-rate QA (mutant-score)**: muteval methodology landed —
  `test/mutants.manifest.json` authoritatively registers 31 malicious mutants (constructor chain/
  run_code host domain/eval·new Function·vm·indirect require/charCode combo obfuscation/hardcoded
  credentials/fork bomb/ReDoS/destructive paths ×2/Discord webhook·cloud-metadata egress/
  patch yml !!js injection/AGENTS.md instruction injection/fullwidth typosquat, covering 14 rule
  faces R1-R20) + 8 benign controls; `scripts/mutant-score.mjs` reuses the same engine entry as
  plugins-matrix for evaluation, kill criterion = rule hit (not verdict — R5/R9-2/R17/R18/R19 are all
  clean + observation layer); files-mode corpus unified with `.fixture.js` suffix (DEV_FIXTURE_RE fixture
  exemption discipline); `npm run check:mutants` gate: all malicious killed + 0 benign false-kills +
  evaluation-failure fail-closed, wired into prepublishOnly (4th release gate), full vitest health check
  in sync; runtime-surface shapes (double-encoded URLs etc. blocked at T2) are listed separately as
  known-coverage-gaps, not part of the static gate. Mechanics in docs/MUTANT-QA.md.

- **Safety tiers (0.3)**: `profile: standard | hardened | paranoid` preset-expands into the existing
  granular switches (hardened: runtimeGuard watch + thirdPartyBaseline + honeypot, R17/R18/R19 info
  observations raised to yellow (alarm-only, verdict unchanged); paranoid: + requireAudit + denyOn
  suspicious + N7 families 3/4 block). Three disciplines: verdict semantics unchanged, explicit wins
  (keys written into patch are explicit, presets don't override), false-positive cost rises with tier.
  `observeLoopback` defaults to on (signal specificity: loopback + control-plane paths + third-party
  attribution, official attribution exempt); the shield gains a one-click "safety tier" switch
  (POST /vet/profile writes the patch, preserving runtimeGuard/requireAudit and other existing keys;
  same-origin check + tier whitelist) and current-tier explanation; the `?` help panel gains a tier
  explanation section; shows a notice while runtimeGuard is disabled.

### Fixed

- **round-6 review, three items**: ① dismissed-alerts atomic write cleans tmp residue on rename failure
  (the old implementation left old `.tmp.*` files permanently under ~/.dsh/vet after a process restart
  changed pid); ② mutant-score fail-closed on malformed manifest (structurally invalid → exit 2; a
  missing single corpus entry goes to the evaluation-failure list rather than masquerading as a
  "survivor" — the engine silently returns an empty clean report for a nonexistent file, so a path typo
  would mislead as a detection gap); manifest path supports VET_MUTANT_MANIFEST override (test friendly,
  absolute/relative both fine); ③ contract home-dir `~` validation merged into one condition
  (`startsWith('~')` already covers everything, eliminating form misreads).
- **C3 snapshot-discipline gap (review fix)**: content-baseline/version-diff/stats/forensics modules'
  default storage dirs previously executed `homedir()` live on **every call** (POSIX prefers `$HOME`) —
  an in-process plugin changing `process.env.HOME` could redirect baseline/capabilities/stats/forensics
  storage (pre-planting a forged baseline, neutralizing N6 upgrade diffs, disabling tamper detection);
  unified to a module-load-time constant (same discipline as confirm-block/contract/honeypot/archive).
- **Destruction-signature window pruning not closed (5th review fix)**: exfil-ledger's
  deletes/renames/writeEvents only pruned on "same-kind new event" push — a plugin going silent after
  hitting the threshold within the window left stale counts forever, and any later other fs event
  re-entered via replace after the 60s dedup window ended, so n3-mass-delete/rename/write-amplify alarms
  permanently re-lit and the shield stuck yellow; now every destroyChecks prunes all three windows
  uniformly (counts reflect the real window).
- **fetch(Request) request-body observation tee buffer unbounded (5th review fix)**: clone is a tee
  semantic — the old implementation fully read `clone().text()`, so a GB-scale streaming upload body
  nearly doubled the vet process memory (same process as the plugin) with OOM risk; now pre-checks by
  content-length (deterministic over-limit → skip body observation, URL side still scanned) + streams
  and cancels after reading the first 4MB.
- **Registry reconciliation resources unbounded (5th review fix)**: tarball/packument had no size limit
  (abnormal/oversized responses fully absorbed into memory), tar member-listing/unpacking had no timeout
  (decompression bomb occupies CPU/disk indefinitely; also the sole root cause of the inflight single
  flight cache permanently occupied); now content-length pre-check (packument 20MB / tarball 256MB) +
  tar 30s timeout — with fetch and unpacking both bounded, every reconciliation promise settles and
  cleans up.
- **Name-based self-exemption and attribution exclusion switched to identity (5th review fix, install-gate
  bypass)**: internal/plugin self-exemption previously compared only the package name
  (`entryName === PACKAGE_NAME` early return) — a malicious tarball writing its name as
  @jieai/dsh-plugin-vet skipped autoScan/requireAudit/third-party baseline entirely (scan-plugin already
  had realpath validation; the two sides were asymmetric); T2 attribution mapping likewise excluded
  name-impersonating packages from attribution (behavior became ownerless, observation downgraded). Now
  unified via pkg-root realpath identity (vet itself exempt; root resolution failure conservatively
  exempts in bundle form), impostor packages scan and attribute normally.
- **tools/execute and internal/plugin duplicate apply stacking (5th review fix)**: DSH config hot-reload
  may apply the same ctx repeatedly without cleaning old listeners — the same execution/install was
  scanned multiple times (double scan + double VET prefix + double deny interception); module-level
  remembers the previous listener and disarms it before reassembling (same mindset as runtime-guard).
- **T2 observation chain top-level exception isolation (5th review fix, defense in depth)**: the sink is
  the top level of observation — a throw there propagates back through the wrappers into the plugin's
  own call (fs side: "operation already done but throws", dgram/fetch side: observation segment runs
  before the original call, a throw directly blocks the request); now the sink is fully try/catch,
  observation failures are silent (each link in the chain is verified not to throw today; this is
  depth-in-depth).
- **Numeric configs accepting 0 busy-loop/immediate-timeout surface (5th review fix)**:
  `z.natural()` allows 0 — scannerTimeoutMs:0 = all scans 0ms timeout, runtimeIntervalMs:0 =
  setInterval-0 busy loop over /proc (sentinel burns a full core); numeric keys unified to `min(1)`,
  sidecar argv entry clamped again (defends direct spawn / legacy config shapes).
- **Unknown-verdict deny silent failure (5th review fix)**: a scanner-protocol drift producing an
  unknown verdict made the RANK lookup undefined and `undefined > RANK[worst]` always false — deny
  silently passed with no log; unknown verdict now follows the same fail-closed path as scanFailed.
- **timeout NaN/0 penetration (5th review fix)**: `--timeout abc`/trailing garbage becomes NaN via
  parseInt, and `NaN ?? default` stays NaN all the way to the scanner (setTimeout(NaN)=0ms immediate
  timeout); CLI validates a positive finite number + client side falls back to default for
  non-finite/≤0.
- **Contract filename vs docs mismatch (5th review fix)**: loadContract only recognized the normalized
  name ('/'→'_') while docs said `<name>.json` — a contract an agent wrote per docs always failed to
  load (M1 silently dead); now dual-track (normalized name first + original name), compatible with old
  storage.
- **Contract validation ~ shape penetration (5th review fix)**: isValidPathPattern only blocked
  '~/…'; bare '~' and '~user' (POSIX home-expansion shapes) passed (comment promised "home-dir ~
  rejected"); now all '~'-prefix shapes are rejected.
- **confirm-block/contract path-normalization drift (5th review fix)**: the two modules each had a
  normPath with different semantics (confirm-block only replaces backslashes; contract folds // and
  strips trailing /) — the equivalent double-slash form "/home/u/.ssh//id_rsa" missed the N7 family-1/2
  credential exact list (theoretical bypass shape); extracted a shared path-utils.normPath single source.
- **config-diff flow key mis-extraction (5th review fix)**: URL_MODE_RE had no word boundary —
  the substring 'url:' inside 'endpoint-url: xxx' was captured and hit, so non-url/mode flow keys were
  alarmed as telemetry changes (yellow); key names now get a negative word boundary.
- **self-pin hash comment promise vs implementation mismatch (5th review fix)**: hashScanFiles comment
  claimed "newline normalization" but never implemented it — Windows checkouts (CRLF) computed a
  different hash for the same shipped bytes, so legit installs were misjudged as dev-tree (pinned-match
  never true); now folds CRLF and strips BOM.
- **dismissed-alerts non-atomic write (5th review fix)**: the ignore list wrote directly without
  tmp+rename — a crash window truncated the JSON, all ignores died and alarms resurfaced; and a failed
  write still updated the in-memory cache (user thought it was ignored; alarms returned after restart).
  Now same atomic write + 0600 as other stores; write failure doesn't change the cache.
- **Zero/negative defense (5th review fix)**: VetStatus constructor args clamped (alarmMax<0 would throw
  RangeError via `alarms.length = alarmMax`), count floor 1; capability-diff empty/blank values no
  longer produce content-empty red alarms (previously recorded no observation set yet still alarmed,
  asymmetric); exfil readTimes Map window lazy pruning (the only unpruned growth surface);
  status-route clears the 60s alarm timer after successful registration + rejects blank alarm ids;
  setBaselineDirForTest also invalidates the module-level cache (same isolation semantics as
  stats/version-diff).
- **gate-cli unknown format silent empty output (5th review fix)**: passing a non-json value to
  --format neither errored nor output JSON (exit code fine) — now explicitly errors with exit 2.
- **Sentinel subprocess boundaries (5th review fix)**: stdout gains an error listener (EPIPE when the
  host-side pipe closes no longer crashes the process as an uncaught error); disposer registers before
  assembling (if installT2/heartbeat throws, the already-started T1 sidecar can be cleaned up, no
  orphans); score-mirror and scanner-bin unknown-confidence fallback unified (?? 1, NaN can no longer
  propagate into the total score).
- **Trailing-dot FQDN escaping sensitive-host detection (review fix)**: `webhook.site.` etc. with a
  trailing dot is a DNS-equivalent form — WHATWG URL keeps the trailing dot, previously all
  `=== h || endsWith('.'+h)` checks missed (sensitive-host/allowlist double bypass); `extractNetworkTarget`
  now normalizes uniformly (lowercase + strip trailing dot + strip IPv6 brackets). Also fixed: options-form
  empty hostname no longer grabs an empty string and goes blind (fallback to host); IPv6 bracket form
  `[::1]` and the entire 127.0.0.0/8 block are now treated as loopback (not in the ledger/alarms).
- **Canary/key alarm targets not in plaintext (review fix)**: canary-leak alarm id/target used to carry
  the full 40-char canary string, key-leak target carried the matched key text — a same-host plugin
  reading the state surface could surgically remove pre-planted values (destroying N4's "appearance =
  confirmed" premise) or steal credential identifiers; now uses hashShort fingerprints like key-leak,
  readable info stays in the message (first 16 chars + length).
- **Honeypot lure registering orphan canaries (review fix)**: id_rsa.pem/.pub are real RSA keys (content
  cannot embed a canary), previously still registered 2 never-matching orphan canaries via putWithCanary
  (set bloat + contradicts the "one canary per lure = confirmable exfil" promise); the separate write
  path no longer registers them.
- **dgram.createSocket teardown restore missing (review fix)**: comments claimed the disposer restores
  the createSocket export, but no restore was registered — after hot-reload/unload dgram stayed wrapped
  forever (residual stacking); added the same snapshot-restore as patchModule.
- **Paired-path ops honeypot/integrity target-side blind spot (review fix)**: the target side of
  `cp(/tmp/x, lure)` / `rename(x, canary)` previously didn't participate in honeypot/integrity
  determination (N7 families 3/4 already double-checked); paired-path candidates now include the target
  side (integrity src side = read still not reported, preserving the read-not-reported semantics).
- **Canary outbound scan first window (review fix)**: >64KB request bodies pushed the canary out of the
  tail window so it never re-sent → N4 miss (large-file upload / padding exfil shapes); changed to
  "constant 64KB first window + rolling 64KB tail window" — front hits no longer missed (mid-section
  anti-split/reassembly stays at the same level, recording boundary).
- **Sentinel host-liveness probe no longer depends on /proc (review fix)**: the sidecar previously
  self-killed when reading `/proc/<ppid>/stat` failed — in containers/restricted mounts an unreadable
  /proc ≠ host exited, so T1 went dark on first round (respawn×5 noise); switched to kill(0) probing
  (ESRCH=host dead; EPERM=alive), /proc sampling failure only degrades the field.
- **capability-diff covered() default guard (review fix)**: a static manifest missing an array field
  threw TypeError via `undefined.length`, bubbling into the wrapped plugin call (the only path violating
  the fail-open promise); aligned with diffManifests' `?? []` defense.
- **N6 corrupt records no longer paralyze whole-package diff (review fix)**: a single record missing
  `capabilities` (old-layout residue/manual edit) previously made diffManifests throw TypeError, caught
  and swallowed — that plugin's every later upgrade diff was permanently silent with no notice;
  diffManifests now returns empty diffs for non-object prev/next, recordScan diffs before writing
  (old implementation: when diff threw, the new record was already written and claimed a no-op).
- **tools/execute deny scan-failure fail-closed (review fix)**: a failed scan previously kept worst at
  clean and silently passed (contradicting internal-plugin's M9 "deny scan failure must fail-closed" —
  the code-execution surface is more dangerous than installing a plugin); now deny + scan failure →
  blocked. Also notes are no longer silently dropped when next returns non-text content (fronted as
  standalone text).
- **vet self-scan declared surface gaps (review fix)**: DECLARED_MODULES gains `http2` (vet does import
  and patch it; previously misattributed as declared via the substring 'http'); DETECTION_DATA_FILES
  completed with all rule files in scanner-bin/rules/ (network-exfil/secrets/host-capture/
  destructive-ops etc. previously omitted, so exfil-endpoint samples were counted as a declared
  capability surface).
- **Render/validation small fixes (review)**: vet_diff multi-record note key omitted → render no longer
  outputs literal "undefined"; registry tarball bare `..` members no longer missed (unpack writes
  outside tmpdir); archive old-format comment 15→18 chars.
- **Honeypot lure template sources zero sensitive literals (review fix)**: lure content (`.env`
  key=value lines, credentials.json private-key headers, aws-credentials key names) split into
  Array.join assembly — pre-commit sensitive scan and vet self-scan R7 no longer false-positive (R7/N2
  fold string `+` concatenation back into "key=sk-" shapes hitting env-key-assignment rules, so a
  non-foldable join is used; generated content is byte-identical to the pre-split version). Previously
  the honeypot files were blocked by the pre-commit hook on first commit, and (dogfood case) R7
  self-scan hits — now eliminated at the root.
- **Credential list / contract / canary base snapshot (review fix, C3 discipline gap)**:
  `os.homedir()` prefers `$HOME` on POSIX, so an in-process plugin changing `process.env.HOME` could
  redirect all three dependencies — ① confirm-block family-2 credential body list (interception broken:
  deleting the real ~/.ssh/id_rsa no longer hit); ② contract default contract dir (M1 validation layer
  silently degraded to no-contract); ③ ensureIntegrityCanaries default root (after hot-reload canaries
  register to the new home, real ~/.dsh canaries lose protection). All three unified to a module-load
  snapshot (vet loads before third-party plugins; the value at that moment is the user's real value);
  confirm-block gains a setCredentialHomeForTest test hook.
- **Turning the guard off no longer loses config (review fix)**: `POST /vet/runtime-guard
  {enable:false}` previously deleted the whole vet entry — hardened/paranoid users turning the guard off
  silently lost the tier and explicit keys like requireAudit; now only the runtimeGuard key is removed and
  the entry kept; the entry is only removed when config is empty (keeping the `[]` boot contract).
- **Runtime-guard state read not overreaching (review fix)**: `readPatchRuntimeGuard` scanning stops at
  the vet entry boundary, no longer misreads a same-named `runtimeGuard` key in a later plugin entry
  (unified with readPatchVetKeys' P2-8 boundary rule).
- **Tier observation copy localized (review fix)**: the R19 observation-escalated alarm body
  "typosquat observation" → "package-name impersonation observation"; no empty "e.g.(…)" suffix when no
  evidence sample exists.
- **README/i18n aligned with actual capability**: corrected outdated/contradictory items in the
  "explicitly not detected" table — supply chain is now covered by R10 install hooks (incl.
  prepare/preuninstall) + dependency list + OSV exact-version query (opt-in osvCheck); indirect
  references (`process["getBuiltinModule"]`/`globalThis.process`/`(0, eval)` etc.) detected since
  round-9/F4; R14 row adds .psm1/.zsh and python/ruby/perl download-and-exec; rule toggles and table
  header R1-R18 → R1-R19; official package count 195 → 187 (0.1.1-rc.2 installed set); live alarm kinds
  24 → 41 (i18n suggest dictionary); EN/ZH divergent rows (EN non-source-code file lines, ZH runtime
  behavior lines) completed both ways; i18n home stats synced (19 rule classes / 187 official packages /
  41 alarm kinds).

## [0.2.6] - 2026-08-23

### Added
- **DSH 0.1.1-rc.2 (npm-public) adaptation (round-15)**:
  - Telemetry config monitoring (G-3) now understands the new row-list patch format
    (`- id: session-telemetry-otel` + `config:` block; OTLP exporter passthrough `url`/`mode` keys)
    while keeping the legacy `telemetry:` block format; reads the new home-layer patch
    (`$DSH_HOME/cordis.patch.yml`, hot-reloaded by boot, outranks the profile layer) in addition
    to profile-level files. Privacy discipline unchanged (sha16 url hash only).
  - R19 typosquat core-list extended with npm-public official names (`dsh-agent`, `dsh-subagent`,
    `dsh-sandbox`, `dsh-workflow`, `dsh-web-frontend`, `dsh-api-gateway`, `dsh-app-boot`,
    `dsh-host-webserver`, `dsh-client-connection`); still info-only, never in verdict, rule-data
    change (no engine bump, cache invalidates by content hash).
  - Verified no change needed: plugin contract (cordis@4 bundles), control-plane path shapes
    (`/api/` prefix + `session.*` vocabulary unchanged), official-package baseline (first-seen
    auto-trust per version; new family versions pass), `dsh plugin --profile add` CLI.
  - Docs: README gains the npm-public bundle-mount note; new tests for both patch formats and the
    home-layer override (privacy assertions intact).
  - Follow-up review hardenings (round-15 re-review, launcher-source-verified): `homePatchPath()` now
    mirrors `resolveDshHome` exactly (whitespace-only `$DSH_HOME` = unset, `~` expansion); R19 +5
    doc-visible official names (`dsh-session-telemetry-otel`, `dsh-session-telemetry`, `dsh-goal`,
    `dsh-headless`, `dsh-mcp-client`) diffed against the installed 187-package npm-public set.
    Cross-checked: `--patch` overlays remain launcher-flag-only (invisible to plugins, not
    hot-reloaded → outside G-3's hot-reload model) and the profile `cordis.yml` root is rewritten
    to an empty stub every boot (both recorded as documented limits, no code change needed).
- **Static scan-surface extensions (R17/R18, ENGINE `static-v13` → `static-v14`)** — closes the two
  P0 blind spots from the third-party DeepSeek-Harness plugin audit (40 attack paths, P2/G-1/G-3):
  - **R17 !!js config surface**: root-level `cordis.yml` / `cordis.patch.yml` / `*.patch.yml` /
    `plugin.yml` are now scanned for `!!js` configuration-as-code expressions — presence
    observation (certain, info), dangerous-verb enumeration (info, e.g. `child_process`/`eval(`/
    `fetch(`/shell tools), base64/hex decode hook-in, and **"verb + exfil-host / credential-path"
    double combos → high/likely** (test/CI dirs and generic packages stay info). Text is only
    extracted, never evaluated (red line); narrow line-based parser with hard caps (64 exprs/file,
    8KB/expr, 6 continuation lines) — no complete YAML semantics, no new dependency, no ReDoS surface.
  - **R18 instruction/skill injection observation (G-1)**: `AGENTS.md` / `CLAUDE.md` / `CODEGOV.md`
    and `SKILL.md` under `skills/` or `*.skill` dirs are scanned with **combined-text matching**
    (instruction-rewrite intent × credential/exfil/persistence action, ≥2 independent group hits;
    a single string never fires — no rule-data self-hits). v1 is all-info observation; escalation
    gates on real-corpus false-positive rates in a later version.
  - **Noise/attack-surface discipline**: both surfaces are gated by `request.surface`
    (`configFiles` / `instructionFiles`, default on), which enters the cache key; per-rule off via
    `rules: {R17:false}`; per-deployment off via new `scanSurface` config; R17/R18 files and their
    tests are registered in `DETECTION_DATA_FILES`/fixture exemption so vet's own self-scan stays
    pinned and clean (`check:self` retained decisive = 0). Engine version bump invalidates stale caches.
  - New tests: `test/r17-config-scan.test.ts`, `test/r18-instruction-scan.test.ts` (hits, downgrades,
    surface/rules toggles, cache-key switching, DoS caps).

- **Phase 3 — observation surface (round-13, ENGINE `static-v14` → `static-v15`)**:
  - `observeLoopback` (default off): local-API loopback observation — plugin requests to
    127.0.0.1 enter the N3 ledger, and control-plane path hits (`/api/`, `session.*`, `/plugins/`)
    attributed to third-party plugins raise yellow `loopback-control` (alarm-only, dismissible;
    covers audit paths P15/P17/G-2/G-5 observationally — RPC auth itself remains dsh-side work).
  - `telemetryDiff` (default on): telemetry config sensitization (G-3) — polls profile
    `cordis.yml`/`cordis.patch.yml` for telemetry exporter `url`/`mode` hashes; cold start records
    only, host change → yellow (restart verification). Only hashes are stored — config content never
    enters alarms/archive; independent of `runtimeGuard`, reads via `withVetSelfIo`.
  - `skills` added to T2 sensitive path segments: skill-catalog writes reuse fs-write/install-write
    semantics (G-1 runtime surface).
- **Phase 4 — supply-chain (round-13)**:
  - **R19 typosquat observation (P4/G-9)**: package name/deps vs a curated core list of official
    `@deepseek-ai` names — Levenshtein ≤1 or visual homoglyphs (`dshh`, `d5h`, `dsh_tool_bash`);
    info/heuristic only, never into verdict; DP-based distance (no ReDoS surface); per-package cap 8.
  - `thirdPartyBaseline` (default off, P7 hardening): non-official packages get a first-install
    content-hash baseline; same-version content changes → red, exemptable via
    `acknowledgedPackageHashes`. Change-detection only — the static verdict scan always still runs.
  - New tests: `r19-typosquat`, `loopback-observe`, `config-diff`, `third-party-baseline`
    (803/803 passing; self-scan gate pinned-match, retained decisive = 0).

### Fixed
- **Break the `invariant` ↔ `runtime-guard` circular dependency**: package constants
  (`PACKAGE_NAME`, `PLUGIN_ENTRY_ID`) moved to a new zero-dependency `src/package-meta.ts`;
  `lib/invariant.js` re-exports them unchanged (API compatible, tests keep importing from it).
  `runtime-guard` / `internal-plugin` / `scan-plugin` / `status-route` now import constants
  directly — importing `PACKAGE_NAME` no longer transitively loads the whole runtime-guard
  chain, and the ESM module graph is acyclic.

### Docs
- **README / README.zh: document all `DSH_PLUGIN_VET_*` environment variables** (cache /
  baseline / archive / forensics / contracts / stats dirs + the internal `DSH_VET_SIDECAR_PID`
  registry) — only cache/baseline were previously mentioned.

## [0.2.5] - 2026-08-22

User-reported false alarm: saving `~/.dsh/settings.yaml` (manual edit picked up by the host, or saved by DSH itself) raised unattributed red `fs-destroy` / yellow `fs-probe` on `.settings.yaml.<pid>.<uuid>.tmpdir`.

### Fixed
- **Exempt host atomic-write staging dirs from unattributed fs alarms**: DSH's `writeFileAtomic` stages every save in a `.<name>.<pid>.<uuid>.tmpdir` dir next to the target, then always removes it — pure housekeeping, but the existing exemption only covered `~/.dsh/web/`. Now matched at segment level anywhere under `~/.dsh/`, still only when unattributed + stack untampered; honeypot/integrity kinds, plugin-attributed ops, the real config files, and credential-face temps (`<file>.<hex12>.tmp`, a different protocol) keep alarming.

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