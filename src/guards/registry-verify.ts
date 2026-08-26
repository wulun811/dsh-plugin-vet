/**
 * P-5 补充（0.1.21）：baseline-mismatch 时的官方 registry 对账。
 * npm 同一版本的发布内容不可变——registry 是内容真值：
 * - 本机字节 == registry 字节 → 原基线陈旧（记录早于官方发布/来自开发通道），应刷新而非报警；
 * - 本机字节 != registry 字节 → 非官方修改坐实（篡改或未登记本机补丁）；
 * - 对账不可用（网络失败/tar 缺失）→ 调用方维持红警（fail-closed）。
 * 仅 report 模式异步调用；deny 模式不做网络对账（P2-7 同款约束：同步路径零网络）。
 */
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { computePackageHash } from './content-baseline.js'

const execFileAsync = promisify(execFile)

const REGISTRY_HOST = 'https://registry.npmjs.org'

export type RegistryVerifyResult =
  | { status: 'resolved'; officialHash: string }
  | { status: 'unavailable'; detail: string }

/** 单飞缓存：同 name@version 的并发加载只对账一次。 */
const inflight = new Map<string, Promise<RegistryVerifyResult>>()

export function verifyAgainstRegistry(name: string, version: string, timeoutMs = 45_000): Promise<RegistryVerifyResult> {
  const key = `${name}@${version}`
  const pending = inflight.get(key)
  if (pending !== undefined) return pending
  const p = doVerify(name, version, timeoutMs).finally(() => { inflight.delete(key) })
  inflight.set(key, p)
  return p
}

async function doVerify(name: string, version: string, timeoutMs: number): Promise<RegistryVerifyResult> {
  try {
    // round-5 review（A#4/#5）：网络对账的资源边界——packument/正文先查 content-length
    // 再读体（异常/超大响应不再整体吸入内存），tar 解包/列成员带超时（解压炸弹不再
    // 无限占用 CPU/磁盘；tar 无界也是 inflight 单飞缓存永久占位的唯一根因——fetch 与
    // 解包全部有界后，verifyAgainstRegistry 的每条 Promise 都会落定清理）。
    // round-15 review（功能降级权衡）：registry 官方 CDN 恒发 content-length；个别镜像
    // （内网代理）可能 chunked 无 CL。为堵「无头超大流整块吸入 OOM」此前直接拒绝无 CL
    // 响应（fail-closed 到 unavailable，调用方按红报告处理，安全侧不损失）。
    const LENGTH_LIMIT_PACKUMENT = 20 * 1024 * 1024
    const LENGTH_LIMIT_TARGZ = 256 * 1024 * 1024
    const TAR_TIMEOUT_MS = 30_000
    const metaUrl = `${REGISTRY_HOST}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`
    const metaRes = await fetch(metaUrl, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' })
    if (!metaRes.ok) return { status: 'unavailable', detail: `packument HTTP ${metaRes.status}` }
    const metaCl = metaRes.headers.get('content-length')
    if (metaCl === null) return { status: 'unavailable', detail: 'packument 无 content-length（拒绝整块吸入）' }
    if (Number.parseInt(metaCl, 10) > LENGTH_LIMIT_PACKUMENT) {
      return { status: 'unavailable', detail: `packument 过大（content-length ${metaCl}）` }
    }
    const meta = await metaRes.json() as { dist?: { tarball?: unknown } }
    const tarball = meta.dist?.tarball
    if (typeof tarball !== 'string' || tarball === '') return { status: 'unavailable', detail: 'packument 无 dist.tarball' }
    // 三轮审查加固：dist.tarball 是 registry 返回的任意字符串——钉死到本函数的 registry 源，
    // 防止被诱导 fetch 任意外部 URL（SSRF 面）。npm 官方 packument 的 dist.tarball 恒为本源主机。
    let tarballUrl: URL
    try { tarballUrl = new URL(tarball) } catch { return { status: 'unavailable', detail: 'dist.tarball 非合法 URL' } }
    if (tarballUrl.origin !== new URL(REGISTRY_HOST).origin) {
      return { status: 'unavailable', detail: `dist.tarball 主机越界: ${tarballUrl.origin}` }
    }
    // round-15 review（重定向加固）：redirect:'error'——30x 不再隐式跟随。注册表与 CDN
    // 交接不经重定向（dist.tarball 直接是 CDN 源）；若未来 registry 开始重定向，宁可
    // unavailable（fail-closed）也不让跳转后的主机绕开上面的 origin 钉死（被攻破的
    // registry/CDN 若可重定向到任意主机，origin 校验形同虚设）。
    const tgzRes = await fetch(tarballUrl, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' })
    if (!tgzRes.ok) return { status: 'unavailable', detail: `tarball HTTP ${tgzRes.status}` }
    const tgzCl = tgzRes.headers.get('content-length')
    if (tgzCl === null) return { status: 'unavailable', detail: 'tarball 无 content-length（拒绝整块吸入）' }
    if (Number.parseInt(tgzCl, 10) > LENGTH_LIMIT_TARGZ) {
      return { status: 'unavailable', detail: `tarball 过大（content-length ${tgzCl}）` }
    }
    const buf = Buffer.from(await tgzRes.arrayBuffer())
    if (buf.length > LENGTH_LIMIT_TARGZ) return { status: 'unavailable', detail: `tarball 过大（实际 ${buf.length} 字节）` }
    const officialHash = await hashPackTarball(buf, TAR_TIMEOUT_MS)
    if (officialHash === null) return { status: 'unavailable', detail: 'tarball 解包/哈希失败' }
    return { status: 'resolved', officialHash }
  } catch (e) {
    return { status: 'unavailable', detail: String(e).slice(0, 120) }
  }
}

/** tarball 字节 → 解包 → computePackageHash（与守卫同算法同预算）。导出仅供测试。
 * round-5 review（A#4）：tar 命令带 timeoutMs——解包是「先于 computePackageHash 预算」的
 * 无界步骤（预算管不到解包），超时由 execFile 以 SIGTERM 终止。 */
export async function hashPackTarball(buf: Buffer, tarTimeoutMs = 30_000): Promise<string | null> {
  const dir = mkdtempSync(join(tmpdir(), 'vet-regcheck-'))
  try {
    const tgzPath = join(dir, 'pkg.tgz')
    writeFileSync(tgzPath, buf)
    // 三轮审查加固：解包前先列成员并校验——拒绝绝对路径 / '..' / 盘符 / 反斜杠成员。
    // GNU tar 默认不拦 '..' 成员，恶意 tarball 可借其把文件写出 tmpdir 之外；反斜杠在
    // GNU tar 里是字面字符，但 Windows bsdtar 会当路径分隔符转换（四轮审查补口）。
    // npm 官方 pack 归一化路径分隔符，正常 tarball 不含反斜杠成员，误杀风险为零。
    // 残留限制（记录）：符号链接成员仍可能指向目录外；registry 走 TLS 属可信源，此为纵深防御而非边界。
    const listed = await execFileAsync('tar', ['-tzf', tgzPath], { timeout: tarTimeoutMs })
    for (const raw of listed.stdout.split('\n')) {
      const entry = raw.trim()
      if (entry === '') continue
      if (
        // round-4 review（L2 补漏）：裸 '..' 成员此前漏检——`includes('../')`/`endsWith('/..')`
        // 都不覆盖恰好等于 '..' 的成员（GNU tar 默认不拦，解包可直接写出 tmpdir 之外）
        entry === '..' ||
        entry.startsWith('/') || entry.includes('../') || entry.endsWith('/..') ||
        /^[a-zA-Z]:/.test(entry) || entry.includes('\\')
      ) return null
    }
    await execFileAsync('tar', ['-xzf', tgzPath, '-C', dir], { timeout: tarTimeoutMs })
    // round-5 review（B-A4）：哈希预算取函数默认值（content-baseline 单点维护）
    const r = computePackageHash(join(dir, 'package'))
    return r?.hash ?? null
  } catch {
    return null
  } finally {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* 清理失败不影响结果 */ }
  }
}
