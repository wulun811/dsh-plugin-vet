/**
 * 包元数据常量（零依赖模块）。
 *
 * 0.2.6 结构修复：常量原定义在 invariant.ts，但 invariant.ts 依赖 runtime-guard.ts
 * （sidecarSpawned），runtime-guard.ts 又依赖 invariant.ts（PACKAGE_NAME）→ 循环依赖。
 * 常量归位到本模块后，invariant.ts 保留 re-export（外部 import 路径与符号不变），
 * runtime-guard / internal-plugin / scan-plugin / status-route 改为直连本模块，环断开。
 */
export const PACKAGE_NAME = '@jieai/dsh-plugin-vet'
/** bundle cordis.patch.yml 里 insert 的条目 id（profile patch 层按它覆盖配置）。 */
export const PLUGIN_ENTRY_ID = 'plugin-vet'