/**
 * N7 高置信破坏拦截（Confirmation Block，v4 拍板：破坏=拦截，篡改=报警）。
 * 判定轴：是否不可逆伤害——删掉/覆盖掉的原文找不回来的（破坏）→ 拦截；可恢复的（篡改）→ 报警。
 * 族 1：破坏/勒索确认（N3 破坏签名组合 / 完整性金丝雀写删 / N4 canary 泄漏）后，拦截该插件
 *      后续破坏类 fs 操作（write/unlink/rename/cp/truncate/createWriteStream）。
 * 族 2：凭据本体（精确文件级）删除族 + 覆盖写（到已存在文件）→ 单次即时拦截。
 * 族 3/4：系统持久化/提权面写入、供应链/安装态篡改 → 仅报警（用户处理，不冒误拦风险）。
 * 护栏（零误拦设计）：官方归因、无主操作、vet 自身 IO 永不拦截（hooks 包装器侧豁免）；
 * 路径精确到文件级；只拦该插件、只拦破坏类 fs 操作；拦截 = 抛错。
 * 失败放通（fail-open）：任何判定异常 → 不拦、放行并记录（内部错误不进判定）。
 * blocked 集合为进程内存（DSH 重启即清）；配置变更需重启生效。
 * @module dsh-plugin-vet/confirm-block
 */
import { homedir } from 'node:os'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

export type ConfirmBlockMode = 'block' | 'alarm' | 'off'

/** 族 1 拦截操作面（破坏类；appendFile 等可逆写不拦）。 */
export const BLOCK_FS_OPS = new Set([
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync',
  'rename', 'renameSync', 'cp', 'cpSync', 'copyFile', 'copyFileSync',
  'truncate', 'truncateSync', 'writeFile', 'writeFileSync', 'createWriteStream',
])

/** 族 2：凭据本体路径（精确文件级；~/.npmrc 为整文件——token 所在）。
 * HOME 环境变量优先（测试可注入；运行时与 os.homedir() 一致）。
 * 按 HOME 记忆化：decideBlock 是每次破坏性 fs 操作都走的判定路径，重建数组 + homedir()
 * 是无效开销；HOME 变化（测试注入/环境变更）时自动重算，不缓存过期路径。 */
let cachedCredHome: string | undefined
let cachedCredFiles: string[] | undefined
function credentialFiles(): string[] {
  const home = process.env.HOME || homedir()
  if (cachedCredHome === home && cachedCredFiles !== undefined) return cachedCredFiles
  cachedCredHome = home
  cachedCredFiles = [
    join(home, '.ssh', 'id_rsa'),
    join(home, '.ssh', 'id_ed25519'),
    join(home, '.ssh', 'id_ecdsa'),
    join(home, '.ssh', 'id_dsa'),
    join(home, '.ssh', 'id_rsa.pub'),
    join(home, '.dsh', '.credentials.yaml'),
    join(home, '.aws', 'credentials'),
    join(home, '.pgpass'),
    join(home, '.netrc'),
    join(home, '.git-credentials'),
    join(home, '.npmrc'),
  ]
  return cachedCredFiles
}

function normPath(p: string): string {
  return p.replace(/\\/g, '/')
}

function isCredentialFile(p: string): boolean {
  const n = normPath(p)
  return credentialFiles().some(c => n === normPath(c))
}

// ── 族 3/4 谓词（classifyOp 复用；纯路径判定，零 IO）────────────────────

/** 族 3：系统持久化/提权面（类 Unix；Windows 持久化经注册表不在 fs 面——由 spawn 命令报警兜底）。 */
export function isPersistenceWriteTarget(p: string): boolean {
  const n = normPath(p)
  const segs = n.split('/')
  const last = segs[segs.length - 1]
  // shell 启动文件
  if (['.bashrc', '.bash_profile', '.zshrc', '.zprofile', '.zshenv', '.profile', '.bash_login'].includes(last)) return true
  // cron
  if (n.includes('/cron.d/') || n.includes('/etc/crontab') || n.includes('/var/spool/cron/')) return true
  // systemd / init
  if (n.includes('/etc/systemd/system/') || n.includes('/usr/lib/systemd/system/')
    || n.includes('/lib/systemd/system/') || n.includes('/etc/init.d/') || n.includes('/etc/rc') || n.includes('/etc/rc.d/')) return true
  // 提权/预加载
  if (n.includes('/etc/ld.so.preload') || n.includes('/etc/sudoers.d/') || n === '/etc/sudoers') return true
  // profile.d / autostart / authorized_keys / hosts / ssl
  if (n.includes('/etc/profile.d/') || segs.includes('autostart') || last === 'authorized_keys') return true
  if (n === '/etc/hosts' || n.startsWith('/etc/ssl') || n.startsWith('/etc/ssl/')) return true
  return false
}

/** 族 4：供应链/安装态篡改——node_modules 内包文件写入、cordis 插件补丁配置。 */
export function isInstallWriteTarget(p: string): boolean {
  const n = normPath(p)
  if (n.includes('/node_modules/')) return true
  if (n.endsWith('cordis.patch.yml') || n.endsWith('.cordis.patch.yml')) return true
  if (n.endsWith('/cordis.yml') || n.endsWith('/plugin.json')) return true
  return false
}

export interface BlockDecision {
  /** 1/2 = 确认破坏拦截（默认 block）；3/4 = 族 3/4 显式升级拦截（默认 alarm）。 */
  family: 1 | 2 | 3 | 4
  reason: string
}

const OVERWRITE_OPS = new Set(['writeFile', 'writeFileSync', 'truncate', 'truncateSync', 'createWriteStream'])
const DESTROY_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'rename', 'renameSync'])

/**
 * 拦截决策（在 hooks 包装器内、调用原函数前执行；失败放通：任何异常 → null）。
 * 前提豁免（由调用方保证）：withVetSelfIo 直通、无主（plugin undefined）不拦、官方归因不拦。
 */
export class ConfirmBlockStore {
  private modeLocal: ConfirmBlockMode = 'block'
  /** 族 3/4 覆写模式（默认 alarm：仅报警；显式 'block' 才拦——误拦风险由用户在配置里承担）。 */
  private familyModeLocal: { 3: ConfirmBlockMode; 4: ConfirmBlockMode } = { 3: 'alarm', 4: 'alarm' }
  private readonly f1Blocked = new Set<string>()

  setMode(mode: ConfirmBlockMode): void {
    this.modeLocal = mode
  }

  mode(): ConfirmBlockMode {
    return this.modeLocal
  }

  /** 设置族 3/4 覆写模式（未配置 → alarm）。 */
  setFamilyModes(f3: ConfirmBlockMode, f4: ConfirmBlockMode): void {
    this.familyModeLocal = { 3: f3 === 'block' ? 'block' : 'alarm', 4: f4 === 'block' ? 'block' : 'alarm' }
  }

  familyMode(family: 3 | 4): ConfirmBlockMode {
    return this.familyModeLocal[family]
  }

  /** 族 1 确认（N3 破坏组合 / 完整性金丝雀写删 / N4 canary 泄漏）。 */
  markFamily1(plugin: string): void {
    if (plugin !== '') this.f1Blocked.add(plugin)
  }

  isFamily1Blocked(plugin: string): boolean {
    return this.f1Blocked.has(plugin)
  }

  decideBlock(plugin: string, opName: string, args: unknown[]): BlockDecision | null {
    if (this.modeLocal !== 'block') return null
    try {
      const target = typeof args[0] === 'string' ? args[0] : ''
      // 族 2：凭据本体（优先；单次即时拦截）
      if (DESTROY_OPS.has(opName)) {
        const cred = (Array.isArray(args) ? args : []).filter((a): a is string => typeof a === 'string').find(isCredentialFile)
        if (cred !== undefined) {
          return { family: 2, reason: `凭据本体 ${cred} 被破坏性操作（${opName}）——密钥唯一副本不可恢复` }
        }
      }
      if (OVERWRITE_OPS.has(opName) && isCredentialFile(target)) {
        // 覆盖写仅当目标已存在（原文会丢失）才拦；写入新文件（改/加，可逆）归报警
        if (safeExists(target)) {
          return { family: 2, reason: `凭据本体 ${target} 被覆盖写（${opName}）——原文不可恢复` }
        }
      }
      // 族 1：该插件已有破坏/勒索确认信号 + 破坏类操作
      if (this.f1Blocked.has(plugin) && BLOCK_FS_OPS.has(opName)) {
        return { family: 1, reason: `该插件（${plugin}）已被确认破坏/勒索行为，后续破坏类操作被拦截（${opName}(${target.slice(0, 80)})）` }
      }
      return null
    } catch {
      // fail-open：判定异常 → 不拦、放行
      return null
    }
  }

  /** 单测辅助：清空（进程内存语义）。 */
  clear(): void {
    this.f1Blocked.clear()
    this.modeLocal = 'block'
    this.familyModeLocal = { 3: 'alarm', 4: 'alarm' }
  }
}

function safeExists(p: string): boolean {
  try {
    return existsSync(p)
  } catch {
    return false
  }
}

/** 进程级单例（hooks 判定 + guard 触发共用）。 */
export const confirmBlock = new ConfirmBlockStore()

/** 复用辅助：对进程级单例执行一次拦截判定（与 hooks 侧同一路径，测试/工具可直用）。 */
export function decideBlock(plugin: string, opName: string, args: unknown[]): BlockDecision | null {
  return confirmBlock.decideBlock(plugin, opName, args)
}

/** 单测辅助：重置模块级单例。 */
export function resetConfirmBlock(): void {
  confirmBlock.clear()
}