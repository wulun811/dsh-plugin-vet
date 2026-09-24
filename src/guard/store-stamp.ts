/**
 * vet 存储「自写标记」（M7 归因，0.3.15）。
 *
 * 背景（2026-09-24 实测）：M7 的存储自检只认「字节与自写不符」，于是把**任何**外部改写
 * 一律报成「疑似进程内插件篡改」黄牌。那次真实触发者是 vet 自己的测试进程（vitest 夹具
 * 写进 ~/.dsh/vet/capabilities.json）——合法多进程写路径被误判成攻击。
 *
 * 本模块让每次落盘在存储文件里盖一个 writer 戳（工具 + 版本 + pid + 时间），读回时据此分流：
 *   - 戳是**别的 pid** 且工具标记为 dsh-plugin-vet → 另一个 vet 进程接管了存储
 *     （CLI / 测试 / 第二个 DSH 实例）：info 观察 + 明确归因，并提示「若你并未运行过该进程，
 *     请按篡改处置」
 *   - 无戳 / 戳的 pid 就是本进程 → 本进程写过的字节被改写：进程内篡改（yellow 保持）
 *
 * 边界（不夸大）：戳可被蓄意伪造（改写者能照抄字段），M7 本就是报警型绊线而非强制边界；
 * 这里买到的是「归因诚实 + 已知合法写路径降噪」，不是不可伪造性。
 * @module dsh-plugin-vet/store-stamp
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { resolvePkgRoot } from '../pkg-root.js'

/** 工具标记：只有 vet 自己的落盘路径会写这个值。 */
export const STORE_TOOL = 'dsh-plugin-vet'

export interface StoreWriter {
  tool: string
  version: string
  pid: number
  at: number
}

/** 存储文件里携带的 writer 戳（可缺省：0.3.15 前的存储、被外部改写过的存储都没有）。 */
export interface StampedStore {
  writer?: StoreWriter
}

/** 存储自检证据：file = 被改写的存储文件；foreign = 改写方留下的 writer 戳（无戳 = null）。 */
export interface StoreTamper {
  file: string
  foreign: StoreWriter | null
}

/** 存储自检的处置结论。 */
export type StoreRewrite =
  | { kind: 'foreign-vet'; writer: StoreWriter }
  | { kind: 'unexplained'; writer: StoreWriter | null }

let versionCache: string | undefined

/** 自身版本（package.json 的 version；解析失败 = 'unknown'）。 */
export function selfVersion(): string {
  if (versionCache === undefined) {
    try {
      const parsed = JSON.parse(readFileSync(join(resolvePkgRoot(), 'package.json'), 'utf8')) as { version?: unknown }
      versionCache = typeof parsed.version === 'string' ? parsed.version : 'unknown'
    } catch {
      versionCache = 'unknown'
    }
  }
  return versionCache
}

/** 本次落盘的 writer 戳。 */
export function currentWriter(): StoreWriter {
  return { tool: STORE_TOOL, version: selfVersion(), pid: process.pid, at: Date.now() }
}

/** 形状守卫：从任意 JSON 值里读 writer 戳（非对象/字段类型不符 → null）。 */
export function readWriter(value: unknown): StoreWriter | null {
  if (typeof value !== 'object' || value === null) return null
  const w = value as Record<string, unknown>
  if (typeof w.tool !== 'string' || typeof w.pid !== 'number' || typeof w.at !== 'number') return null
  return { tool: w.tool, version: typeof w.version === 'string' ? w.version : 'unknown', pid: w.pid, at: w.at }
}

/** 归因：别的 vet 进程写的 = 合法多进程写路径；否则（无戳/本进程 pid）视为篡改。 */
export function classifyStoreRewrite(writer: StoreWriter | null, selfPid: number): StoreRewrite {
  if (writer !== null && writer.tool === STORE_TOOL && writer.pid !== selfPid) {
    return { kind: 'foreign-vet', writer }
  }
  return { kind: 'unexplained', writer }
}
