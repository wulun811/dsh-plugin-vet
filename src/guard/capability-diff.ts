/**
 * N1 声明 vs 观测 能力差分（Cross-Layer Capability Diff）。
 * 静态侧（scanner-bin）给出插件声明的 CapabilityManifest；T2 运行时观测（网络/子进程/敏感 fs）
 * 与此对账："观测到但静态清单没声明" = 隐藏能力被执行（混淆/动态代码得逞）→ red（certain）。
 * 保守原则（v2）——宁可多列、不漏报：
 *   - imports 非空 → 视为"可能具备任何能力"（第三方库能力未知，不递归聚合依赖）；
 *   - 只有"静态完全无足迹（含 imports）且运行时触发敏感操作"才报隐藏能力；
 *   - 只有敏感操作参与差分（net-egress/spawn/fs-* 敏感类），非敏感操作不算。
 * 休眠能力（静态有、长时未触发）不实时报，聚台进观测集供 M2 营养标签展示。
 * alarm-only：差分只产生报警（red），从不拦截。
 * @module dsh-plugin-vet/capability-diff
 */
import type { CapabilityManifest } from "../scanner/protocol.js"

export type ObservedKind = "net" | "spawn" | "fsRead" | "fsMutate"

export interface ObservedAction {
  plugin: string
  kind: ObservedKind
  /** 观测值（报警 target，如主机/命令/路径），用于 message 展示。 */
  value: string
}

export interface HiddenCapability {
  plugin: string
  kind: ObservedKind
  value: string
  message: string
}

const KIND_LABEL: Record<ObservedKind, string> = {
  net: "网络请求",
  spawn: "子进程执行",
  fsRead: "敏感路径读取",
  fsMutate: "敏感路径写删",
}

/** round-16（SA2-7）：观测集上限——每（插件 × 类别）最多 128 个去重观测值；
 * 全表最多 200 个插件。失控/风暴插件不再让观测表（M2 展示与差分扫描都遍历它）
 * 无限膨胀。淘汰策略 = 最旧优先（Set/Map 按插入序迭代）。 */
const OBSERVED_MAX_PER_KIND = 128
const OBSERVED_MAX_PLUGINS = 200

/** 某类观测是否被静态清单覆盖（保守：imports 非空即覆盖一切；否则看本类足迹）。
 * round-4 review（M1）：数组字段缺省守卫——旧扫描器产物/schema 演进可能缺某字段，
 * `undefined.length` 会抛 TypeError 沿 sink → 包装器冒泡到插件自己的调用（唯一违背
 * fail-open 承诺的路径）。与 version-diff.diffManifests 的 ?? [] 防御对齐。 */
function covered(manifest: CapabilityManifest, kind: ObservedKind): boolean {
  if ((manifest.imports ?? []).length > 0) return true
  switch (kind) {
    case "net": return manifest.hasNetwork === true || (manifest.hosts ?? []).length > 0
    case "spawn": return manifest.hasExec === true || (manifest.spawnCmds ?? []).length > 0
    case "fsRead":
    case "fsMutate": return (manifest.fsPaths ?? []).length > 0
  }
}

/**
 * 差分存储：plugin → 静态清单 + 观测集。模块级单例（守卫进程内共享），
 * 插件卸载不清理（观测集保留供 M2 展示；静态清单留待下次扫描刷新）。
 */
export class CapabilityDiffStore {
  private readonly staticByPlugin = new Map<string, CapabilityManifest>()
  private readonly observedByPlugin = new Map<string, Map<ObservedKind, Set<string>>>()

  /** 注册/刷新某插件的静态能力清单（来自扫描报告；undefined = 无清单，不参与差分）。 */
  registerStatic(plugin: string, manifest: CapabilityManifest | undefined | null): void {
    if (manifest === undefined || manifest === null) {
      this.staticByPlugin.delete(plugin)
      return
    }
    this.staticByPlugin.set(plugin, manifest)
  }

  /**
  * 观测推进 + 差分：记录一次敏感操作，若静态清单已注册且未声明该类能力 → 隐藏能力。
  * 无静态清单（从未扫描/官方豁免）→ 返回 null（不差分）。
  */
  observeAndCheck(action: ObservedAction): HiddenCapability | null {
    // round-5 review（B-A10）：空/纯空白 value 不入任何路径——此前空值不记观测集
    // 却仍走 !covered 分支产出内容为空的红警（message 里 ''.slice(0,120)），
    // 「不记录却报警」不对称且污染状态面。
    if (typeof action.value !== 'string' || action.value.trim() === '') return null
    const manifest = this.staticByPlugin.get(action.plugin)
    if (manifest === undefined) return null
    const perPlugin = this.observedByPlugin.get(action.plugin) ?? new Map()
    const set = perPlugin.get(action.kind) ?? new Set()
    if (action.value !== "") set.add(action.value)
    // round-16（SA2-7）：每类观测值上限——超出淘汰最旧（插入序），观测集仍是最新窗口。
    while (set.size > OBSERVED_MAX_PER_KIND) {
      const oldest = set.values().next()
      if (oldest.done) break
      set.delete(oldest.value)
    }
    perPlugin.set(action.kind, set)
    // round-16（SA2-7）：新插件入表前超插件数上限 → 淘汰最旧插件整行。
    if (!this.observedByPlugin.has(action.plugin)) {
      while (this.observedByPlugin.size >= OBSERVED_MAX_PLUGINS) {
        const oldest = this.observedByPlugin.keys().next()
        if (oldest.done) break
        this.observedByPlugin.delete(oldest.value)
      }
    }
    this.observedByPlugin.set(action.plugin, perPlugin)
    // 保守差分：静态无任何足迹（含 imports）且触发敏感操作 → 隐藏能力（red/certain）
    if (!covered(manifest, action.kind)) {
      return {
        plugin: action.plugin,
        kind: action.kind,
        value: action.value,
        message: `隐藏能力被执行：${action.plugin} 静态清单未声明 ${KIND_LABEL[action.kind]} 能力
（${action.value.slice(0, 120)}）——疑似混淆/动态代码绕过静态扫描（N1 差分）`,
      }
    }
    return null
  }

  /** 某插件的已观测集合（供 M2 休眠能力/营养标签使用）。 */
  observedSets(plugin: string): Record<ObservedKind, string[]> {
    const perPlugin = this.observedByPlugin.get(plugin)
    const empty: Record<ObservedKind, string[]> = { net: [], spawn: [], fsRead: [], fsMutate: [] }
    if (perPlugin === undefined) return empty
    return {
      net: [...(perPlugin.get("net") ?? [])],
      spawn: [...(perPlugin.get("spawn") ?? [])],
      fsRead: [...(perPlugin.get("fsRead") ?? [])],
      fsMutate: [...(perPlugin.get("fsMutate") ?? [])],
    }
  }
}

/** 进程级单例（runtime-guard sink 与 internal-plugin 注册共用）。 */
export const capabilityDiff = new CapabilityDiffStore()

/** T2 alarm kind → 差分观测类别（返回 null 表示不参与差分：蜜罐/审计等独立信号）。 */
export function diffKindOf(alarmKind: string): ObservedKind | null {
  switch (alarmKind) {
    case "net-egress": return "net"
    case "spawn": return "spawn"
    case "fs-read": return "fsRead"
    case "fs-probe": return "fsRead"
    case "fs-write":
    case "fs-destroy": return "fsMutate"
    default: return null
  }
}
