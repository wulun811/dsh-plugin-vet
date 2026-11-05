# 反例台账（CASES）

每个反例回答一个具体问题：「**如果这样发生，系统会不会说出它不该说的话？**」
这张表把每个反例指到真正会红的那条测试上。写不出测试指向的，就写"缺口"——这比写一个空勾选诚实。

批次（**2026-11-05 更正**）：`0.4.3` 从未作为独立版本发布——原计划里它要做的 C01/C02/C11/C32 并进了
0.5.0/0.5.1，证据不在这张表里。本文件覆盖 **0.5.x 这一批**（C03/C12–C24），外加 0.5.x 期间真正
踩到的 F 类（见 `FAILURES.md`）；`0.6.0` 做 C25–C31（新形态）。
这一行原先是按**计划**写的，不是按提交写的——把计划当流水，是这张表最该被纠正的一处。

状态只有三种：**覆盖**（有测试且断言的是结论本身）、**部分**（测试存在但只覆盖一半，或只覆盖了
相邻的机制）、**缺口**（没有测试，写明为什么现在做不了）。

## 0.5.x 批次

| # | 反例 | 期望 | 现在由谁挡住 | 状态 |
|---|---|---|---|---|
| C03 | symlink / hidden / 深度 7 的动态入口 | 明确 scope/unknown，不能标完整覆盖 | `coverage-honesty.test.ts`（`file_tree` 的 `partial`/`unknown` 行）+ `internal-plugin` 的 ≤6 层枚举边界（README 已知边界 1b） | **部分**：深度与隐藏文件有记录，symlink 目录不在快照里这件事**没有专门测试** |
| C12 | OSV 断网 / 超时 / 返回旧统计 | 不把未知情报写成"无依赖漏洞" | `osv-budget.test.ts`（相位被掐断的计数）+ `coverage-honesty.test.ts`（`intel_osv` 的 `unknown`/`partial`）+ `assessment-freshness.test.ts`（情报不缓存） | **覆盖**。"旧快照"这一支不适用：OSV 结论从不进缓存（`scan()` 只缓存静态报告），所以不存在"旧情报被当新"的路径 |
| C13 | 规则命中，但没有实际危险调用 | 能力/风险可以有，**Activity 不得伪造** | `capability-join.test.ts` + `n1-capability.test.ts`（能力是声明面事实）+ `kinds.ts` 的 severity 表（静态命中最高到 suspicious，不比运行时 red 高） | **部分**：静态命中与运行时事件的**措辞分离**靠注册表与文案，没有一条"静态命中不得产生 activity 类报警"的断言 |
| C14 | 静态漏报，但 T2 观察到真实出网 | 真实观察保留，不被静态阴性否决 | `network-egress.test.ts` + `n3-attribution.test.ts` + `n3-exfil-ledger.test.ts` | **覆盖** |
| C15 | T1 看到 host RSS 上升，多个插件同时在跑 | 只记宿主事实；插件归因必须有另外证据 | `domain-record-sites.test.ts`（T1 的几个落点逐个走投影漏斗，主体是 `HOST_SUBJECT`，`project.ts::hintOf` 对 `kind: 'other'` 返回 undefined → 无 `pluginHint`，且与旧字面量逐字段相等）+ `metrics-darwin.test.ts` + `runtime-guard.test.ts`（归因失败 → 报警无主而非丢失） | **覆盖** |
| C16 | 用户 dismiss，随后同一事实 red 升级 | 风险事实留存；升级按既有合同可重新提醒 | `dismissed-id-migration.test.ts` + `dismiss-restore-cross-session.test.ts` | **覆盖** |
| C17 | 旧白名单同名、不同 hash | 例外作用域不得外溢 | `content-baseline.test.ts` + `baseline-reconcile.test.ts`（`acknowledgedPackageHashes` 以 `name@version` 为键 + 摘要绑定） | **覆盖** |
| C18 | 伪造官方包名 + registry 断网 | 不以名字代替来源/字节事实 | `official-catalog.test.ts` + `hardening-attribution.test.ts`（SEC-1 内容信任锚）+ `docs/ARCHITECTURE.md` §5.8 | **覆盖** |
| C19 | 旧 schema 归档（无 hash / 无规则版本） | 旧历史继续可读，但只是 `legacy_record_only` | `archive-compat.test.ts`（`basis: 'legacy'`）+ `assessment-freshness.test.ts`（不因缺字段而拒载） | **覆盖**（规则版本那一半是已知缺口，见下） |
| C20 | 改了规则集，旧缓存重新命中 | 缓存上下文正确失效 | `hardening-cache.test.ts`（`cacheKey`/`validReport` 的 `ENGINE_VERSION` 比对） | **覆盖** |
| C21 | `scan_plugin` / CLI gate / loader 同一冻结输入 | 核心 findings 等价；入口 policy 差异可解释 | `entry-parity.test.ts`（0.5.10，逐字段 + 端到端） | **覆盖**（`generic` vs `plugin` 的单点差异被钉住并解释） |
| C22 | 守卫 `off→watch→off`、HMR 20 次 | 无叠层 Hook/sidecar、无残留自动复活 | `runtime-guard.test.ts`（20 次循环） | **覆盖** |
| C23 | Hook 被别的插件覆盖/恢复 | 心跳发现实际降级，UI 显示 health | `v2-hook-heartbeat.test.ts` + `coverage-honesty.test.ts`（`runtime_hook_health: failed`）+ `domain-record-sites.test.ts` | **覆盖** |
| C24 | 只装 scan-only 形态 | 不制造不存在的 runtime coverage 事件 | `coverage-honesty.test.ts` + `config-view.test.ts`（`runtimeGuard: off` 时 T1/T2 那批键标 `inert`） | **覆盖** |

## 缺口（写清楚为什么现在补不了）

1. **C03 的 symlink 分支**：`ScopedSnapshot` 与源码枚举都跳过符号链接目录，但"跳过了什么、为什么跳"
   没有作为覆盖面的一行（`partial`）被断言。补它需要在枚举层记录排除原因（路径 + 原因），
   属于 0.6.0 的 `SurfaceEnumerator` 工作。
2. **C13 的措辞分离**：需要一条"静态命中不得产生 activity 类文案"的断言。技术上可做（注册表里
   标记 activity-only 的 code，测试断言静态路径不得产出它们），但当前没有静/动两类 code 的显式分组，
   先记账。
3. **C19 的规则版本**：审计档案不写 `rule_set_version`，因此"旧规则集下的结论"与"当前规则集下的结论"
   在档案层不可区分，`standard_changed` 在生产里触发不了。补它必须连影响函数一起做（档案写版本 + 判定、
   加载时比对、只在结论会变时转 `recheck_required`），否则是一次大规模误拒载。
   `test/assessment-freshness.test.ts` 已把现状钉成断言。

## 0.6.0 批次为何不在本文件

C25–C31 全部与**新插件形态**有关（远程 MCP、Skill 提示注入、native/WASM、只读磁盘/伪造缓存、
宿主产生的蜜罐事件、告警风暴）。它们的共同前提是 `SurfaceEnumerator` / `Observer` 两个扩展点，
而那两个扩展点在 0.5.x 里还不存在——拿当前模型去写，写出来的只会是"用当前模型凑出来的近似物"，
那正是 §7.3 四步准入要防的东西。

**顺序修订（2026-11-05，专家复审）**：原写法"先有语义，再有反例"被指出会把因果关系弄反——先设计
接口、再只用这个接口能表达的样本证明接口够好，是循环论证。改为：

1. 先把 C25–C31 写成**七份可证伪的行为合同**：场景、输入、期望的安全结论、以及"什么算失败"。
   此时状态标 `NOT_IMPLEMENTED / NOT_TESTED`——**没有实现不是证据，也不冒充证据**；
2. 再实现 `SurfaceEnumerator` / `Observer`，让合同变成可执行反例；
3. 每个合同落地时，把状态从 `NOT_TESTED` 改成"由哪条测试挡住"，与本表其余行同一口径。

合同先行不产生虚假的绿色，反而让真实攻击场景去约束扩展点的形状。
