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

/** 某类观测是否被静态清单覆盖（保守：imports 非空即覆盖一切；否则看本类足迹）。 */
function covered(manifest: CapabilityManifest, kind: ObservedKind): boolean {
  if (manifest.imports.length > 0) return true
  switch (kind) {
    case "net": return manifest.hasNetwork || manifest.hosts.length > 0
    case "spawn": return manifest.hasExec || manifest.spawnCmds.length > 0
    case "fsRead":
    case "fsMutate": return manifest.fsPaths.length > 0
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

  /** 该插件是否有静态清单（可差分）。 */
  hasStatic(plugin: string): boolean {
    return this.staticByPlugin.has(plugin)
  }

  /** 取静态清单（只读快照）。 */
  staticOf(plugin: string): CapabilityManifest | undefined {
    return this.staticByPlugin.get(plugin)
  }

  /**
  * 观测推进 + 差分：记录一次敏感操作，若静态清单已注册且未声明该类能力 → 隐藏能力。
  * 无静态清单（从未扫描/官方豁免）→ 返回 null（不差分）。
  */
  observeAndCheck(action: ObservedAction): HiddenCapability | null {
    const manifest = this.staticByPlugin.get(action.plugin)
    if (manifest === undefined) return null
    const perPlugin = this.observedByPlugin.get(action.plugin) ?? new Map()
    const set = perPlugin.get(action.kind) ?? new Set()
    if (action.value !== "") set.add(action.value)
    perPlugin.set(action.kind, set)
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

/** 单测辅助：清空全部状态（fixture 隔离）。 */
export function resetCapabilityDiff(): void {
  capabilityDiff["staticByPlugin"].clear()
  capabilityDiff["observedByPlugin"].clear()
}