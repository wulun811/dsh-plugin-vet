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
 * 无界步骤（预算管不到解包），超时由 execFile 以 SIGTERM 终止。
 * round-16（SEC-2/3）：见 hashPackTarball 内注释。 */
export async function hashPackTarball(buf: Buffer, tarTimeoutMs = 30_000): Promise<string | null> {
  const dir = mkdtempSync(join(tmpdir(), 'vet-regcheck-'))
  try {
    const tgzPath = join(dir, 'pkg.tgz')
    writeFileSync(tgzPath, buf)
    // round-16（SEC-2/3）：清单从 `tar -tzf`（仅名字）升级为 `tar -tvzf`（类型+大小+名字）：
    // - SEC-2：符号链接/硬链接/设备/管道成员（类型列 l/h/c/b/p）整体拒绝——旧 `tar -tzf`
    //   不显示成员类型，含 `package/x -> /etc/passwd` 链接成员的恶意 tarball 通过名字校验
    //   后被解包，computePackageHash 跟随链接可读到包根之外的文件（纵深防御：registry 走
    //   TLS 属可信源，仅作边界补强）。npm pack 产物为普通文件（实测 vet/react/tar/esbuild
    //   tarball 全部 '-' 成员），误杀风险为零。
    // - SEC-3：普通成员解包总字节 ≤1GB 且成员数 ≤10 万——单成员名字校验不构成解包体积
    //   上限（压缩炸弹形态：小 tgz 解出巨大目录树），解包前按清单累计并拒绝超限。
    //   行格式（GNU vs BSD 双布局）：GNU `-rw-r--r-- 0/0 1234 2024-01-01 12:00 package/f`
    //   （fields[1] 含 '/'）；BSD `-rw-r--r-- 1 user group 1234 Jan 1 12:00 package/f`
    //   （owner/group 分列，size 在 fields[4]、名字起点 fields[8]）。
    const TOTAL_UNPACKED_LIMIT = 1024 * 1024 * 1024
    const MEMBER_COUNT_LIMIT = 100_000
    const REJECT_TAR_TYPES = new Set(['l', 'h', 'c', 'b', 'p'])
    // maxBuffer：100k 成员 × ~120B/行 ≈ 12MB（默认 1MB 会让大包清单在解包前就抛 maxBuffer）
    const listed = await execFileAsync('tar', ['-tvzf', tgzPath], { timeout: tarTimeoutMs, maxBuffer: 32 * 1024 * 1024 })
    let totalBytes = 0
    let memberCount = 0
    for (const raw of listed.stdout.split('\n')) {
      const line = raw.trim()
      if (line === '') continue
      const type = line[0] ?? ''
      // SEC-2：链接/设备/管道成员整体拒绝（见上注释；目录 'd' 与普通文件 '-' 放行，
      // pax 扩展头 'x'/'g' 等 GNU 兼容形态放行——误杀面保持为零）
      if (REJECT_TAR_TYPES.has(type)) return null
      const fields = line.split(/\s+/)
      const gnu = (fields[1] ?? '').includes('/')
      const sizeField = gnu ? fields[2] : fields[4]
      const size = Number.parseInt(sizeField ?? '0', 10)
      const name = (gnu ? fields.slice(5) : fields.slice(8)).join(' ')
      if (Number.isFinite(size) && size >= 0) totalBytes += size
      memberCount += 1
      // 名称危险校验（与旧 tar -tzf 清单同款：绝对路径 / '..' / 盘符 / 反斜杠；分行解析后
      // 裸 '..' 也能精确命中——GNU tar 默认不拦，解包可直接写出 tmpdir 之外）
      if (
        name === '..' ||
        name.startsWith('/') || name.includes('../') || name.endsWith('/..') ||
        /^[a-zA-Z]:/.test(name) || name.includes('\\')
      ) return null
    }
    // SEC-3：解包体积/成员数上限（累计超限直接拒绝——不进入解包步骤）
    if (memberCount > MEMBER_COUNT_LIMIT || totalBytes > TOTAL_UNPACKED_LIMIT) return null
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
