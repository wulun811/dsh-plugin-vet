
/**
 * 取证模式（NEXT-GEN 交叉加固 #6，P0-2）：插件被高置信确认恶意（N4 金丝雀外泄 / 蜜罐命中 /
 * N3 勒索签名）后，把该插件后续的微小 fs/网络活动全量记录到取证流水——"平时不打扰，
 * 确认有鬼就布天罗地网"。
 * 存储：~/.dsh/vet/forensics/<plugin>-<启动时间戳>.jsonl（目录 0700、文件 0600；
 * 每次 DSH 启动新建一个文件，不随 VetStatus TTL 清理——文件保留供审计，用户可自行归档）。
 * 完全本地、alarm-only（取证只记录，不拦截）；fail-open（写盘失败静默，不打扰守卫流程）。
 * 不做会话内容监听——只记录已归因插件的操作形状与目标，与 N3 台账同一数据面。
 * @module dsh-plugin-vet/forensics
 */
import { appendFileSync, mkdirSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'

/** ForensicsEvent：一条取证记录（操作形状 + 目标；不落会话内容）。 */
export interface ForensicsEvent {
  at: number
  plugin: string
  module: string
  op: string
  target?: string
  paths?: string[]
  sensitive?: boolean
}

/** C3：模块加载时快照 env（测试用 setForensicsDirForTest 覆盖；生产路径不调用）。 */
const SNAPSHOT_DIR: string | undefined = (() => {
  const v = process.env.DSH_PLUGIN_VET_FORENSICS_DIR
  return v !== undefined && v !== '' ? v : undefined
})()

let dirOverride: string | undefined

/** C3（第二轮补漏）：默认取证目录在模块加载时定值——homedir() 随 $HOME 变，运行时
 * 回退可被进程内插件改 env 重定向（伪造取证存储）。与 archive.ts 同款纪律。 */
const SNAPSHOT_DEFAULT_DIR = join(homedir(), '.dsh', 'vet', 'forensics')

/** 取证目录根（快照 env + homedir）。 */
export function forensicsRoot(): string {
  return dirOverride ?? SNAPSHOT_DIR ?? SNAPSHOT_DEFAULT_DIR
}

/** 测试专用：覆盖快照目录。 */
export function setForensicsDirForTest(dir?: string): void {
  dirOverride = dir
}

/** 被取证插件集合（进程内存；DSH 重启后清除）。 */
const armed = new Set<string>()
/** 每插件取证文件路径缓存（避免每次 join+mtime）。 */
const fileCache = new Map<string, string>()
/**
 * #10（0.2.2）：会话时间戳——模块加载时固定一次（进程级）。同一 DSH 进程内多次 arm
 * 同一插件复用同一文件（fileCache 幂等）；DSH 重启 = 新模块实例 = 新时间戳 = 新文件，
 * 天然按会话轮转，避免旧实现"每次重启 append 同一文件"的无限增长。测试 resetForensics
 * 会重置它，使"模拟重启"用例可复现。
 */
let sessionStamp: string | undefined

/** 启用取证：把插件加入取证集（幂等）。 */
export function arm(plugin: string): void {
  if (armed.has(plugin)) return
  armed.add(plugin)
  // 首次落一行"开启取证"标记，便于审计时间线起点；失败静默
  withVetSelfIo(() => {
    try {
      // 文件名：<plugin>-<会话戳>.jsonl（无自动 TTL 清理——取证保留供审计，用户可自行归档）
      if (sessionStamp === undefined) {
        // 毫秒精度：同一 DSH 进程内重复 arm/reset 也几乎必然得到新文件名（真实重启相隔更远，
        // 必然轮转）；可读性仍保留（2026-08-21-09-26-53-123）。
        sessionStamp = new Date().toISOString().slice(0, 23).replace(/[T:.]/g, '-')
      }
      const path = join(forensicsRoot(), plugin.replace(/[^A-Za-z0-9_.@-]/g, '_') + '-' + sessionStamp + '.jsonl')
      fileCache.set(plugin, path)
      mkdirSync(forensicsRoot(), { recursive: true, mode: 0o700 })
      appendFileSync(path, JSON.stringify({ at: Date.now(), plugin, kind: 'forensics-start' }) + '\n', { mode: 0o600 })
    } catch {
      // fail-open：取证开启失败不影响守卫
    }
  })
}

/** 是否处于取证模式。 */
export function isArmed(plugin: string | undefined): boolean {
  return plugin !== undefined && armed.has(plugin)
}

/**
 * round-15 review（磁盘填满面）：单个取证文件大小上限——恶意插件被武装后操作频率
 * 由攻击者控制（fs 事件风暴可秒级写爆磁盘；会话轮转只按重启分界，不防单会话内风暴）。
 * 超过上限即停写该插件后续事件（fail-open 纪律：取证是增强，宁可截断不可拖垮宿主磁盘）。
 */
const FORENSICS_FILE_MAX_BYTES = 5 * 1024 * 1024

/** 记录一条取证事件（仅对已武装插件；fail-open）。 */
export function record(plugin: string | undefined, evt: Omit<ForensicsEvent, 'plugin' | 'at'>): void {
  if (plugin === undefined || !armed.has(plugin)) return
  withVetSelfIo(() => {
    try {
      const path = fileCache.get(plugin)
      if (path === undefined) return
      // 大小预检：超限 → 静默截断（fail-open；不 resolved 出副作用）
      try {
        if (statSync(path).size > FORENSICS_FILE_MAX_BYTES) return
      } catch {
        // 文件尚未创建/被删：stat 失败交给 appendFileSync 兜底（fail-open）
      }
      const line: ForensicsEvent = { ...evt, plugin, at: Date.now() }
      appendFileSync(path, JSON.stringify(line) + '\n')
    } catch {
      // fail-open：取证写盘失败静默（不打扰守卫；取证是增强不是防线）
    }
  })
}

/** 测试辅助：清空全部状态。 */
export function resetForensics(): void {
  armed.clear()
  fileCache.clear()
  dirOverride = undefined
  sessionStamp = undefined
}
