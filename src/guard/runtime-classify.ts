/**
 * 危险操作分类（fs/child_process 面）
 * P0-4 结构债拆分自 runtime-hooks.ts（纯函数；N7 族 3/4 目标判定在此完成）
 */
import { DESTROY_OPS, WRITE_OPS, READ_OPS, PROBE_OPS, PROC_OPS } from './runtime-ops.js'
import type { HookAlarm, HookConfig, HookOp } from './runtime-ops.js'
import { isPersistenceWriteTarget, isInstallWriteTarget } from './confirm-block.js'
import {
  firstString, allStrings, commandString, hitsShellToken, pathTokens, redirectTarget,
  isSensitivePath, isHoneypotPath, isIntegrityPath, isLockSiblingPath, isSessionLogFile,
} from './runtime-denoise.js'

/** P1-8：破坏性命令词——命中且命令里出现敏感路径（参数或重定向目标）才报警，避免 rm -rf /tmp 这类常规清理误报。 */
const DESTRUCTIVE_TOKENS = new Set(['rm', 'mv', 'cp', 'dd', 'mkfs', 'mkfs.ext4', 'mkfs.xfs', 'shred', 'truncate'])
/** 危险操作分类（纯函数）：返回报警候选（pluginHint 由调用方经栈归因补全）。 */
export function classifyOp(op: HookOp, cfg: HookConfig): HookAlarm | null {
  const { module, op: name, args } = op
  const target = firstString(args) ?? ''
  if (module === 'child_process' && PROC_OPS.has(name)) {
    const cmd = commandString(args)
    // 命令全貌（含 spawn argv 数组的元素）：exec('rm -rf ~/.ssh') 与 spawn('rm', ['-rf', '/home/u/.ssh'])
    // 都能被词/路径检测覆盖。注意 cmd 是字符串，不能展开成字符数组（...cmd 会每字符间插空格）。
    const full = [cmd, ...allStrings(args)].join(' ')
    // P1-8：破坏性命令（rm -rf ~/.ssh / dd of=/etc/… / mkfs / cp 覆盖敏感路径）——只对命令里
    // 出现敏感路径（参数或重定向目标）的组合报警；exec('rm -rf /tmp/x') 常规清理不报。
    const destr = hitsShellToken(full, [...DESTRUCTIVE_TOKENS])
    const redirect = redirectTarget(full)
    const redirectSensitive = redirect !== undefined && isSensitivePath(redirect, cfg, 'mutate')
    if (!hitsShellToken(cmd, cfg.shellTokens)) {
      // 触发条件：破坏性命令 + 敏感路径参数，或 shell 重定向到敏感路径（echo x > /etc/passwd）
      if (!destr && !redirectSensitive) return null
      const paths = [...pathTokens(full), redirect].filter((p): p is string => p !== undefined)
      if (!paths.some(p => isSensitivePath(p, cfg, 'mutate'))) return null
    }
    return {
      severity: 'yellow',
      kind: 'spawn',
      message: `子进程 spawn：${name}(${cmd.slice(0, 120)})`,
      target: cmd.slice(0, 120),
    }
  }
  if (module === 'fs' && isHoneypotPath(target, cfg.honeypotRoots)) {
    // D27 蜜罐：触碰诱饵路径（读/写/删）→ 高置信的翻找密钥信号，独立报警类
    if (DESTROY_OPS.has(name) || WRITE_OPS.has(name) || READ_OPS.has(name) || PROBE_OPS.has(name)) {
      const severity = DESTROY_OPS.has(name) ? 'red' : 'yellow'
      return { severity, kind: 'honeypot', message: `蜜罐命中：${name}(${target.slice(0, 120)}) — 诱饵密钥文件被触碰（疑似翻找密钥）`, target }
    }
  }
  if (module === 'fs') {
    // N4 完整性金丝雀（仅 ~/.dsh 内）：写/删即 red kind=integrity——勒索加密 profile 目录
    // （配置/会话/凭据面）的最早触发信号；读不报（内容固定已知，无害）
    if ((DESTROY_OPS.has(name) || WRITE_OPS.has(name)) && isIntegrityPath(target, cfg.integrityRoots) && !isLockSiblingPath(target)) {
      return {
        severity: 'red',
        kind: 'integrity',
        message: `完整性金丝雀被写删：${name}(${target.slice(0, 120)}) — ~/.dsh 关键文件被篡改（疑似勒索/破坏，N4）`,
        target,
      }
    }
    // N7 族 3/4：系统持久化/提权面写入、供应链/安装态篡改 → 报警（写操作判定前，更具体）
    // cp/rename/copyFile 是成对路径：写目标可能是 dst（覆盖系统文件/落位安装态），两侧都查
    if (WRITE_OPS.has(name)) {
      const writeCandidates = (name === 'cp' || name === 'cpSync' || name === 'rename' || name === 'renameSync'
        || name === 'copyFile' || name === 'copyFileSync') ? allStrings(args) : [target]
      const persist = writeCandidates.find(isPersistenceWriteTarget)
      if (persist !== undefined) {
        return { severity: 'yellow', kind: 'persistence-write', message: `系统持久化/提权面写入（N7 族 3）：${name}(${persist.slice(0, 120)}) — 可恢复，建议核实来源`, target: persist.slice(0, 120) }
      }
      const install = writeCandidates.find(isInstallWriteTarget)
      if (install !== undefined) {
        return { severity: 'yellow', kind: 'install-write', message: `供应链/安装态篡改（N7 族 4）：${name}(${install.slice(0, 120)}) — 可重装恢复，建议重哈希比对`, target: install.slice(0, 120) }
      }
    }
    // isLockSiblingPath：atomic-write 协议锁（<file>.lock）随写随删，豁免；凭据本体照删照报
    if (DESTROY_OPS.has(name) && isSensitivePath(target, cfg, 'mutate') && !isLockSiblingPath(target)) {
      const isSessionLog = isSessionLogFile(target)
      return {
        severity: 'red',
        kind: 'fs-destroy',
        message: `敏感路径删除：${name}(${target.slice(0, 120)})`,
        target,
        ...(isSessionLog && { sessionLog: true }),
      }
    }
    // cp/rename 是成对路径：src 敏感（拷贝密钥出局）或 dest 敏感（覆盖系统文件/密钥落位）都要报
    if (name === 'cp' || name === 'cpSync' || name === 'rename' || name === 'renameSync' || name === 'copyFile' || name === 'copyFileSync') {
      const paths = allStrings(args)
      const sensitive = paths.find(p => isSensitivePath(p, cfg, 'mutate'))
      if (sensitive !== undefined) {
        return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入（${name}）：${sensitive.slice(0, 120)}`, target: sensitive.slice(0, 120) }
      }
    }
    // open/openSync 的 flags 参数带 w/a/+/x → 写意图（fs.open('/etc/passwd','w') 不该按读取报）
    // P1-7：跳过首参（路径本身以 r/w/a 开头会误当 flags，如 open('auth.txt','r')）——
    // flags 认 Node 短合法形态：r/w/a/x（x=排他新建）、可带 s（同步）/x/+（rwx/as/ax/wx 等 2-3 字符），
    // 长度 ≤3；wx+/ax+/as+/rs+ 等复合也要进入写意图判定（旧正则 ^[rwax]\+?$ 漏复合 → 按读报，盲点）。只认首参之后。
    if ((name === 'open' || name === 'openSync') && READ_OPS.has(name)) {
      const flags = args.slice(1).find((a): a is string => typeof a === 'string' && /^(?:[rwax]|[rwa][sx]|[rwa][+]|[rwa][sx][+])$/.test(a))
      if (flags !== undefined && /[wax+]/.test(flags) && isSensitivePath(target, cfg, 'mutate')) {
        return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入（open flags=${flags}）：${target.slice(0, 120)}`, target }
      }
    }
    // isLockSiblingPath：写入锁文件（wx 创建带 PID）也是协议操作，不再误报 fs-write
    if (WRITE_OPS.has(name) && isSensitivePath(target, cfg, 'mutate') && !isLockSiblingPath(target)) {
      return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入：${name}(${target.slice(0, 120)})`, target }
    }
    if (READ_OPS.has(name) && isSensitivePath(target, cfg, 'read')) {
      return { severity: 'yellow', kind: 'fs-read', message: `敏感路径读取：${name}(${target.slice(0, 120)})`, target }
    }
    // M7：列目录/stat/access 敏感路径 = 侦察（凭据狩猎第一步）
    if (PROBE_OPS.has(name) && isSensitivePath(target, cfg, 'read')) {
      return { severity: 'yellow', kind: 'fs-probe', message: `敏感路径侦察：${name}(${target.slice(0, 120)})`, target }
    }
  }
  return null
}
