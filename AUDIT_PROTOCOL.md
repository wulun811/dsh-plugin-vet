# VET Audit Protocol (AUDIT_PROTOCOL)

> This protocol is the **audit-process specification** shipped by the vet plugin: when an agent in DSH needs to
> audit a new plugin (or the user asks it to evaluate one), **the agent executes the steps below itself**.
> vet ships no audit tooling and does not investigate for the agent — vet only provides objective static
> criteria (`scan_plugin`) and runtime monitoring; the audit conclusion is formed by the agent and persisted
> as a health record.

## When to use

- The user asks to evaluate a DSH plugin that is about to be / already installed
- Pre-install review of a new plugin from a marketplace or before `dsh plugin add`
- Deep-dive investigation of a suspicious plugin (scan verdict=suspicious/critical)

## Audit steps (agent executes in order)

### Step 1: Static criteria (required, seconds)

Call `scan_plugin` (target=package, packagePath=plugin package directory) to get:

- **verdict**: critical / suspicious / clean (the authoritative judgment from the static layer)
- **staticScore**: 0-100
- **findings**: every static finding (rule id, severity, message, file, line) — incl. R12
  (Cordis/DSH bundle contract: entry file, bundle-patch declaration, name, engines.node)

> verdict=critical ⇒ directly judged **reject install**: skip the remaining steps and write the record
> directly (see Step 5).

### Step 2: Read the manifest (required)

First **locate the plugin package directory** (source of Step 1's `packagePath`):

- Installed plugin: `~/.dsh/profiles/<profile>/node_modules/<package>` — glob for
  `~/.dsh/profiles/*/node_modules/<name>/package.json`, or ask the user for the profile name
- To-install/offline package: just get the package directory (npm cache, local clone)
- If location fails, hand the user `scan_plugin`'s error and ask for the path

Then use `read`/`glob` to read through the plugin package:

- `package.json`: name, version, dependencies (watch high-risk deps: ssh2/shelljs/child_process, etc.),
  peerDependencies, exports/main entry, dsh declarations
- `cordis.patch.yml` (if any): how the plugin mounts — entry shape, nested inserts, conflicts with other bundles
- All source files (lib/, src/), read by line count descending

### Step 3: Verify each static finding (required)

For every `scan_plugin` finding, use `read`/`grep` to locate the exact line and judge:

- **Real problem**: write the evidence (file:line + code snippet)
- **False positive**: state why (e.g. R9 on bounded for-of traversal, R2 on a factory-parameter require in a
  client loader)

### Step 4: Proactive deep-dive (by the plugin's capability surface)

Depending on the plugin's exposed capabilities, verify with `read`/`grep`/`web_search`:

- **Network egress**: fetch/http call sites, targets, timeouts, whether credentials ride along in requests
- **File system**: whether read/write paths are controlled, whether they stray into sensitive directories
  (/etc, ~/.ssh, ~/.dsh credentials)
- **Process/execution**: child_process/spawn/exec call surface, command concatenation injection
- **Credential handling**: how passwords/keys/tokens are stored, transported, persisted (plaintext? permissions?)
- **Library security semantics**: e.g. does an ssh2 connection validate hostVerifier (the default auto-accept
  risks MITM), do dependencies have known CVEs (verify via web_search)

### Step 4.5: Contract & code-quality audit (required)

> The static scan and security deep-dive solve "**malicious**"; this step solves "**badly written**" — a
> non-malicious plugin can still bring down the host through bugs. Guiding principle: contract items
> enumerable at the static layer are covered by R12; here the agent reads the code through and judges item by
> item, writing defects into the record where they affect the "recommendation".

**Cordis/DSH contract check surface** (cross-checks R12, one level deeper):

- Entry & declarations: exports/main points to something real and exports the standard plugin shape
  (name / Config / apply(context, config)); the services declared in `inject` are actually injected and used
  consistently
- DSH version requirements: `engines.dsh` / `@deepseek-ai/dsh-*` peers name a range that admits the **running**
  host (R12 checks the shapes and compares the range; note that DSH pins exact versions in official artifacts,
  so a plugin published against the previous release is refused at install — confirm the plugin is meant for
  this DSH before recommending it)
- Config correctness: the Config schema matches the keys the code actually reads one-for-one (reading keys that
  don't exist, type mismatches, unguarded null/empty)
- Lifecycle hygiene: event listeners/timers/subprocesses have dispose paths; hot reload (re-apply) is
  idempotent, module-level state doesn't linger (vet's own second-round review fixed exactly these: an
  unlistened spawn error crashing the host, half-written stdout lines, alarms that never cleared)

**Code-quality/robustness checklist** (check item by item; record file:line + note for problems):

- Error handling: uncaught promises (fetch/async without catch), empty `catch{}` swallowing errors with no log,
  whether error paths are diagnosable
- Synchronous blocking: sync fs/network/long loops inside event/async callbacks — does it stall the host event loop?
- Resource leaks: are timer/stream/listener cleaned up as you go; can worker/subprocesses become orphans
- Async correctness: missing awaits, fire-and-forget async inside callbacks, edge conditions (empty input /
  overly long input / concurrent re-entry)
- Paths & platform: path.join building absolute paths, Windows separators, sensitive-file read/write posture
- Dependency hygiene: complete dependencies declared (no implicit deps), sane versions, correct peer relations

**Judgment direction**: any "runs but will drag down / silently fail" defect → recommendation drops to
**review** (even if statically clean); contract items (missing entry / inconsistent declarations) → at least
review, up to reject.

### Step 5: Persist the health record (required)

After the review, write the conclusion with the system file-write capability (`write` tool) to:

```
~/.dsh/vet/audits/<escaped-plugin-name>-<version>-<yyyyMMdd-HHmmss>.md
```

**Critical — the filename must match vet's `hasAuditRecord` matcher exactly, or the audit gate will keep firing even though the record exists.** Apply these rules when constructing `<escaped-plugin-name>`:

1. **Stripe the package scope**: remove the leading `@` from scoped names.
2. **Replace every `/` with `-`**: `@deepseek-ai/dsh-client-connection` → `deepseek-ai-dsh-client-connection`.
3. **Local file-path plugins keep their path, `/` → `-`**: `/home/me/.dsh/profiles/web/lan-uuid-polyfill.mjs` → `-home-me-.dsh-profiles-web-lan-uuid-polyfill.mjs` (leading `/` becomes `-`, dots stay).
4. **Timestamp format is `yyyyMMdd-HHmmss`** (with a dash between date and time), e.g. `20260821-073129`.
5. **`<version>` is the installed version string exactly** (e.g. `0.1.0-rc.8`, `1.0.0`). For file-path plugins with no declared version, use `1.0.0` as the default.

Full example for `@deepseek-ai/dsh-client-connection@0.1.0-rc.8`:

```
~/.dsh/vet/audits/deepseek-ai-dsh-client-connection-0.1.0-rc.8-20260821-073129.md
```

(Old records created with the pre-0.2.1 format `-yyyyMMddHHmmss.md` without the dash are still matched for upgrade compatibility; new records must use the dash form.)

Record format (Markdown):

```markdown
# VET health record: <plugin-name>@<version>

- Scanned at: <ISO time>
- Static verdict: 🟢 clean / 🟠 suspicious / 🔴 critical (static score N/100)

## Static findings
- [rule] severity: message (file:line) …

## Agent investigation
- Risk: clean | low | medium | high | critical
- Recommendation: approve | review | reject
- Summary: <agent's review summary>

## Quality audit (step 4.5)
- Contract: entry/inject/Config-schema check conclusion (or "passed")
- Defect list: file:line + problem description + severity
- Impact: do defects affect adoption (drags down host / silent failure → at least review)

## Review trail (evidence)
- Each verified static finding and deep-dive result listed (file:line + conclusion)
```

### Conclusion matrix

| Static verdict | Deep-dive findings | Quality audit (step 4.5) | Recommendation |
| --- | --- | --- | --- |
| critical | — | — | **reject** (direct reject, no deep-dive needed) |
| suspicious | all false positives ruled out | passed | review or approve (with exclusion reasons) |
| suspicious | all false positives ruled out | has defects | **review** (fix quality issues first) |
| suspicious | real problems found | — | reject or review (with evidence) |
| clean | — | passed | approve |
| clean | — | "runs but drags down / silently fails" defects | **review** (statically clean ≠ worth installing) |
| clean | deep-dive finds hidden problems | — | review or reject (with evidence) |

## Enforcement (`requireAudit`)

vet provides two enforcement layers (after enabling `requireAudit: true` in config):

1. **Auto-scan before load** (autoScan on by default): vet static-scans synchronously at plugin mount; deny
   mode blocks critical/suspicious.
2. **Audit gate** (`requireAudit`, off by default): when a plugin loads, check `~/.dsh/vet/audits/` for that
   plugin's record — absent means `report` mode alarms, `deny` mode blocks outright (message references
   `vet-audit-protocol` and demands review first).

> The gate is independent of package resolution and scanning: whether a record exists depends only on whether
> the agent reviewed the plugin per this protocol.
> Even if the agent skips the protocol, an unaudited plugin cannot load (in deny) — that is where "enforced"
> lands: not controlling the agent's thinking, but making "unaudited" become "unusable".

### Record format (0.5.1+)

The file name remains the whole contract for *existence*: `<plugin>-<version>-<yyyyMMdd-HHmmss>.md` under
`~/.dsh/vet/audits/`. A record without a version segment is only matched loosely, and a record for another
version does not qualify the installed one.

The archive body **may** declare the bytes it was written against, as one line near the top:

```
subject_sha256: <64 hex characters>
```

- **present and matching** → the record qualifies as `basis=digest`;
- **present and not matching** → the plugin is `recheck_required`: the record exists but it was written about
  different bytes, so it is not a statement about what is installed now, and `vet-audit-protocol` must be run
  again;
- **absent** → the record qualifies as `basis=legacy`. This is deliberate: 0.4.x never asked for this line, and
  retroactively invalidating every existing record would deny every already-audited plugin on upgrade day.

The digest is `sha256` over the same file set vet hashes for content baselines (hidden files, `node_modules`,
symlinks and documentation excluded; 1000 files / 50 MB / 10 s budget). It is a **statement of what was
reviewed**, not a signature: anyone who can write the archive can write a digest. Its job is to stop a stale
review from clearing new bytes, which is exactly the case that used to slip through.

### The rule set the conclusion was reached under (0.5.20)

A record **may** also declare which static engine produced the scan evidence it rests on, and what that scan
said:

```
rule_set_version: static-v27
scan_verdict: clean
```

Both lines are optional, and they are used as a pair. When the engine in the record differs from the engine this
build ships, vet asks one question before honouring the record: **would the current rule set decide differently
for this package?** It answers with the most recent scan summary for the same name and version, provided that
summary was produced by the current engine and its verdict is worse than the one recorded:

- **worse** (`clean` → `suspicious`/`critical`) → `recheck_required`, with a message naming the rule set rather
  than the digest. Run `vet-audit-protocol` again against the installed bytes.
- **same, better, or unanswerable** (no summary, summary from an older engine, version mismatch, `scan_verdict`
  absent) → the record stands. Reasons are recorded on the qualification state (`standard-irrelevant` /
  `standard-unevaluated`) so the answer is auditable instead of silent.

Why the impact function and not "engine changed → everything is stale": the latter is a mass denial on upgrade
day, and a rule-set change is not evidence that a package changed. Only a different conclusion about *this*
package is.

**The one-load window is real and stated here rather than glossed over.** The gate runs before the scan — it has
to, because blocking must happen before the mount — so on the first load after an engine upgrade it only has
evidence written by the previous engine, which is unanswerable, and the record stands. That load is itself
scanned (when `autoScan` is on, which is the default) and the fresh verdict lands in the scan summary, so the
*next* load is the one that can require a re-audit. With `autoScan: false` nothing ever refreshes that summary,
so the re-audit never triggers — a knowing trade, not a silent one: the state still carries `standard-unevaluated`.

## Boundary (vet's responsibility)

- vet does **not**: install/uninstall plugins, block execution (except deny mode), draw conclusions for the agent
- vet does: static scan to give criteria, runtime-monitor and alarm, define the record-directory convention
  (`~/.dsh/vet/audits`)
- Review is the agent's protocol behavior: transparent process, traceable conclusions, reviewable records