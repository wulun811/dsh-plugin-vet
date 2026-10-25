/**
 * 0.4.1：自动更新适配提示（两层）的测试。
 *
 * 覆盖四个面：
 * 1. 版本范围判定（零依赖 semver 子集）——含预发布闸门，与 npm semver 语义对齐；
 * 2. 离线兼容层——运行中 DSH 超出本版已复验范围 → out-of-range；读不到 → unknown（不误报）；
 * 3. 在线层闸门——「有新版」还不够，必须「新版声明覆盖本机 DSH」才 update-available；
 * 4. 出网纪律——节流 24h、单飞、失败 fail-quiet（不谎报）、deny 模式不出网。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { satisfiesRange, compareSemver, isNewer, parseSemver } from '../lib/guard/dsh-compat.js'
import {
  detectDshVersion,
  compatStatus,
  getUpdateView,
  maybeCheckForUpdate,
  setUpdateAutoCheck,
  setUpdateCheckDirForTest,
  seedRemoteForTest,
  updateCheckPath,
} from '../lib/guard/update-check.js'

/** 符号链接能力探针：Windows 无开发者模式/非管理员时 symlinkSync 抛 EPERM——
 * 该环境无法物化符号链接场景，跳过对应用例（CI 特权 runner 与 POSIX 照常执行）。 */
const canSymlink = ((): boolean => {
  const d = mkdtempSync(join(tmpdir(), 'vet-symprobe-'))
  try {
    symlinkSync(join(d, 'a'), join(d, 'b'))
    return true
  } catch {
    return false
  } finally {
    rmSync(d, { recursive: true, force: true })
  }
})()

/** 造一个可读的假 profile（含 node_modules/@deepseek-ai/dsh/package.json），供离线层探测用。
 * 不再依赖开发机的 ~/.dsh/profiles/web——那会让断言在其他机器上被静默跳过。 */
function fakeProfile(dshVersion: string): string {
  const root = mkdtempSync(join(tmpdir(), 'vet-prof-'))
  const d = join(root, 'node_modules', '@deepseek-ai', 'dsh')
  mkdirSync(d, { recursive: true })
  writeFileSync(join(d, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh', version: dshVersion }))
  return root
}

describe('0.4.1 版本范围判定（零依赖 semver 子集）', () => {
  it('解析：三段号 + 预发布 + v 前缀 + build metadata', () => {
    expect(parseSemver('1.2.3')).toMatchObject({ major: 1, minor: 2, patch: 3, pre: [] })
    expect(parseSemver('v0.2.0-rc.2')).toMatchObject({ major: 0, minor: 2, patch: 0, pre: ['rc', '2'] })
    expect(parseSemver('0.2.0-rc.1+build.7')).toMatchObject({ pre: ['rc', '1'] })
    expect(parseSemver('not-a-version')).toBeNull()
    expect(parseSemver('1.2')).toBeNull()
  })

  it('比较：预发布 < 正式版；数字段 < 字母段', () => {
    expect(compareSemver('0.2.0-rc.1', '0.2.0')).toBe(-1)
    expect(compareSemver('0.2.0-rc.1', '0.2.0-rc.2')).toBe(-1)
    expect(compareSemver('0.2.0-rc.10', '0.2.0-rc.9')).toBe(1)
    expect(compareSemver('0.2.0-alpha', '0.2.0-rc.1')).toBe(-1)
    expect(compareSemver('0.2.0', '0.2.0')).toBe(0)
    expect(compareSemver('bad', '0.2.0')).toBeNull()
  })

  it('isNewer：非法版本一律 false（宁可漏报，不可谎报有新版）', () => {
    expect(isNewer('0.3.19', '0.3.18')).toBe(true)
    expect(isNewer('0.3.18', '0.3.18')).toBe(false)
    expect(isNewer('garbage', '0.3.18')).toBe(false)
    expect(isNewer('0.3.19', 'garbage')).toBe(false)
  })

  it('caret：major>0 锁 major；0.x 锁 minor；0.0.x 锁 patch', () => {
    expect(satisfiesRange('1.5.0', '^1.2.3')).toBe(true)
    expect(satisfiesRange('2.0.0', '^1.2.3')).toBe(false)
    expect(satisfiesRange('0.2.9', '^0.2.0')).toBe(true)
    expect(satisfiesRange('0.3.0', '^0.2.0')).toBe(false)
    expect(satisfiesRange('0.0.3', '^0.0.3')).toBe(true)
    expect(satisfiesRange('0.0.4', '^0.0.3')).toBe(false)
  })

  it('预发布闸门（与 npm semver 一致）：组内需同 M.m.p 的带预发布比较器', () => {
    // 同 M.m.p → 允许预发布入选
    expect(satisfiesRange('0.2.0-rc.2', '^0.2.0-rc.1')).toBe(true)
    // 预发布是 0.1.1 ≠ 0.2.0 → 该组不接纳 0.2.0-rc.2
    expect(satisfiesRange('0.2.0-rc.2', '^0.1.1-rc.1')).toBe(false)
    // 但 `||` 的另一组接纳（这正是本版 dshCompat 的形态）
    expect(satisfiesRange('0.2.0-rc.2', '^0.1.1-rc.1 || ^0.2.0-rc.2')).toBe(true)
    // 组内无预发布 → 带预发布版本一律不满足
    expect(satisfiesRange('0.2.0-rc.2', '<0.3.0')).toBe(false)
    expect(satisfiesRange('0.2.0-rc.2', '>=0.1.0 <0.3.0')).toBe(false)
    // 正式版不受闸门限制
    expect(satisfiesRange('0.2.0', '>=0.1.0 <0.3.0')).toBe(true)
    expect(satisfiesRange('0.3.0', '<0.3.0')).toBe(false)
  })

  it('非法版本 → false；空范围按 npm 语义 = *（匹配正式版，不含预发布）', () => {
    expect(satisfiesRange('bad', '^0.1.0')).toBe(false)
    expect(satisfiesRange('0.2.0', 'not a range')).toBe(false)
    // npm: validRange('') === validRange('*') === '*'；且 `*` 按 semver 预发布规则不含预发布版。
    // 已用 semver@7 差分测试确认（2490 例，含边界）本实现对 `*`/`''` 的行为一致。
    expect(satisfiesRange('0.2.0', '')).toBe(true)
    expect(satisfiesRange('0.2.0-rc.2', '')).toBe(false)
    expect(satisfiesRange('0.2.0-rc.2', '*')).toBe(false)
  })
})

describe('0.4.1 离线兼容层', () => {
  it('compatStatus：范围内=ok；范围外=out-of-range；缺信息=unknown（不误报）', () => {
    expect(compatStatus('0.2.0-rc.2', '^0.1.1-rc.1 || ^0.2.0-rc.2')).toBe('ok')
    expect(compatStatus('0.3.0', '^0.1.1-rc.1 || ^0.2.0-rc.2')).toBe('out-of-range')
    expect(compatStatus('', '^0.2.0-rc.2')).toBe('unknown')
    expect(compatStatus('0.2.0-rc.2', '')).toBe('unknown')
  })

  it('版本号读不出来 → unknown，而不是 out-of-range（不能报假的兼容性告警）', () => {
    // 反例：日期版本/nightly 构建的 DSH 版本号过不了 semver 解析——旧实现把它当「超出范围」，
    // 于是一台正常的宿主被报「兼容性未验证」。
    expect(compatStatus('0.2.1.1', '^0.2.1-rc.2')).toBe('unknown')
    expect(compatStatus('nightly-2026-10-25', '^0.2.1-rc.2')).toBe('unknown')
    expect(compatStatus('0.2.1-rc.3', '^0.2.1-rc.2')).toBe('ok')
    expect(compatStatus('0.3.0', '^0.2.1-rc.2')).toBe('out-of-range')
  })

  it('detectDshVersion：锚点不可用 → 空串（fail-open，绝不误判超出范围）', () => {
    // 伪造一个不存在的 profile 目录；argv[1] 是 vitest，也不含宿主 DSH
    const v = detectDshVersion(join(tmpdir(), 'definitely-missing-profile-dir'))
    expect(typeof v).toBe('string')
    // 本仓库测试环境解析不到宿主 DSH 时应为空串；若开发机恰好能解析，则必须是合法版本串
    if (v !== '') expect(parseSemver(v)).not.toBeNull()
  })

  it('detectDshVersion：file: URL 锚点与目录路径等价（Windows 盘符路径不失效）', () => {
    // ctx.baseUrl 在真实宿主上可能是 file: URL。手工截 file:// 在 Windows 上会留下
    // `/C:/…`（盘符前多斜杠），解析不到宿主——必须走 fileURLToPath。
    const prof = fakeProfile('0.2.1-rc.3')
    try {
      expect(detectDshVersion(pathToFileURL(prof).href)).toBe('0.2.1-rc.3')
      expect(detectDshVersion(prof)).toBe('0.2.1-rc.3')
    } finally {
      rmSync(prof, { recursive: true, force: true })
    }
  })
})

describe('0.4.1 在线层闸门（核心：没适配就不弹）', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-upd-'))
    setUpdateCheckDirForTest(dir)
    setUpdateAutoCheck(false) // 默认禁真实出网
  })
  afterEach(() => {
    setUpdateCheckDirForTest(undefined)
    setUpdateAutoCheck(true)
    vi.unstubAllGlobals()
    rmSync(dir, { recursive: true, force: true })
  })

  it('远端有新版但**未声明**覆盖本机 DSH → 不弹（status=unknown，不谎报）', () => {
    seedRemoteForTest('9.9.9', '')
    const prof = fakeProfile('0.2.1-rc.3')
    const v = getUpdateView(prof)
    // 本机能解析出 DSH 版本时 compat 才可能是 ok；关键断言是 status 不为 update-available
    expect(v.status).not.toBe('update-available')
    expect(v.latestVersion).toBe('9.9.9')
    rmSync(prof, { recursive: true, force: true })
  })

  it('远端有新版且**声明覆盖**本机 DSH → update-available', () => {
    // 固定一个假 profile，断言不再依赖开发机路径（旧写法在其他机器上整个用例静默通过）
    const prof = fakeProfile('0.2.1-rc.3')
    seedRemoteForTest('9.9.9', '^0.2.1-rc.3')
    const v = getUpdateView(prof)
    expect(v.dshVersion).toBe('0.2.1-rc.3')
    expect(v.status).toBe('update-available')
    expect(v.latestVersion).toBe('9.9.9')
    rmSync(prof, { recursive: true, force: true })
  })

  it('远端声明覆盖但**不比本机新** → up-to-date（不弹）', () => {
    seedRemoteForTest('0.0.1', '^0.1.1-rc.1 || ^0.2.0-rc.2')
    const v = getUpdateView(fakeProfile('0.2.1-rc.3'))
    expect(v.status).toBe('up-to-date')
  })

  it('registry 版本号读不出来 → unknown（不能把「不知道」说成「已是最新」）', () => {
    // isNewer 对非法版本恒 false，旧代码据此断言 up-to-date 并在卡片上写「已是最新」。
    for (const bogus of ['not-a-version', '0.5']) {
      seedRemoteForTest(bogus, '^0.2.1-rc.2')
      const v = getUpdateView(fakeProfile('0.2.1-rc.3'))
      expect(v.status).toBe('unknown')
    }
  })

  it('从未检查过（checkedAt=0）→ status=unknown（不凭空提示）', () => {
    const v = getUpdateView(fakeProfile('0.2.1-rc.3'))
    expect(v.status).toBe('unknown')
    expect(v.checkedAt).toBe(0)
  })
})

describe('0.4.1 出网纪律（节流 / 单飞 / fail-quiet / deny 不出网）', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-upd-'))
    setUpdateCheckDirForTest(dir)
    setUpdateAutoCheck(true)
  })
  afterEach(() => {
    setUpdateCheckDirForTest(undefined)
    setUpdateAutoCheck(true)
    vi.unstubAllGlobals()
    rmSync(dir, { recursive: true, force: true })
  })

  function stubFetch(payload: unknown, ok = true) {
    const fn = vi.fn(async () => ({
      ok,
      headers: { get: () => null },
      text: async () => JSON.stringify(payload),
    }))
    vi.stubGlobal('fetch', fn)
    return fn
  }

  it('成功检查：落盘远端结论并驱动 update-available', async () => {
    const prof = fakeProfile('0.2.1-rc.3')
    const fn = stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.2.1-rc.3' } })
    await maybeCheckForUpdate()
    expect(fn).toHaveBeenCalledTimes(1)
    expect(existsSync(updateCheckPath())).toBe(true)
    const saved = JSON.parse(readFileSync(updateCheckPath(), 'utf8')) as { latestVersion: string }
    expect(saved.latestVersion).toBe('9.9.9')
    expect(getUpdateView(prof).status).toBe('update-available')
    rmSync(prof, { recursive: true, force: true })
  })

  it('节流：24h 内第二次调用不再出网', async () => {
    const fn = stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.1.0' } })
    await maybeCheckForUpdate()
    expect(fn).toHaveBeenCalledTimes(1)
    await maybeCheckForUpdate()
    expect(fn).toHaveBeenCalledTimes(1) // 被节流拦下
  })

  it('lastCheckedAt 在未来（时钟回拨）→ 仍然复核，在线层不停摆', async () => {
    writeFileSync(updateCheckPath(), JSON.stringify({
      lastCheckedAt: Date.now() + 3 * 365 * 864e5, latestVersion: '', latestTestedRange: '',
    }))
    setUpdateCheckDirForTest(dir) // 清内存缓存，重新从盘读
    const fn = stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.2.1-rc.3' } })
    await maybeCheckForUpdate()
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('单飞：并发调用只出网一次', async () => {
    const fn = stubFetch({ version: '1.0.0', dshCompat: { tested: '^0.1.0' } })
    const a = maybeCheckForUpdate()
    const b = maybeCheckForUpdate()
    expect(b).toBeUndefined() // 第二次被 in-flight 拦下
    await a
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('fail-quiet：HTTP 失败/网络异常 → 不落远端结论、不抛、不谎报', async () => {
    const fn = vi.fn(async () => { throw new Error('ECONNREFUSED') })
    vi.stubGlobal('fetch', fn)
    await expect(maybeCheckForUpdate()).resolves.toBeUndefined()
    expect(getUpdateView(fakeProfile('0.2.1-rc.3')).status).toBe('unknown')
    // 失败也推进尝试时间，避免每 5s 轮询重打网络
    const saved = JSON.parse(readFileSync(updateCheckPath(), 'utf8')) as { latestVersion: string; lastCheckedAt: number }
    expect(saved.latestVersion).toBe('')
    expect(saved.lastCheckedAt).toBeGreaterThan(0)
  })

  it('fail-quiet：非 2xx / 超大 body / 非法 JSON 一律静默', async () => {
    // 每个子用例必须用**干净目录**：setUpdateCheckDirForTest 只清内存缓存，盘上还留着上一个
    // 子用例写入的 lastCheckedAt=now，于是第二、三个子用例根本没发请求（断言靠节流通过）。
    const cases: Array<() => Promise<unknown>> = [
      async () => ({ ok: false, headers: { get: () => null }, text: async () => '{}' }),
      async () => ({
        ok: true,
        headers: { get: (h: string) => (h === 'content-length' ? String(999_999_999) : null) },
        text: async () => '{}',
      }),
      async () => ({ ok: true, headers: { get: () => null }, text: async () => 'not json' }),
    ]
    for (const impl of cases) {
      const fresh = mkdtempSync(join(tmpdir(), 'vet-upd-case-'))
      setUpdateCheckDirForTest(fresh)
      const fn = vi.fn(impl)
      vi.stubGlobal('fetch', fn)
      await maybeCheckForUpdate()
      expect(fn).toHaveBeenCalledTimes(1) // 真的走到了失败分支，而不是被节流拦住
      expect(getUpdateView().status).toBe('unknown')
      rmSync(fresh, { recursive: true, force: true })
      setUpdateCheckDirForTest(dir)
    }
  })

  it('autoCheck 关闭 → 完全不出网（纯离线部署）', async () => {
    setUpdateAutoCheck(false)
    const fn = stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.1.0' } })
    expect(maybeCheckForUpdate()).toBeUndefined()
    expect(fn).not.toHaveBeenCalled()
  })

  it('持久化的远端结论跨进程可见（重新加载目录后仍在）', async () => {
    const prof = fakeProfile('0.2.1-rc.3')
    stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.2.1-rc.3' } })
    await maybeCheckForUpdate()
    setUpdateCheckDirForTest(dir) // 清内存缓存，强制从盘重载
    const v = getUpdateView(prof)
    expect(v.latestVersion).toBe('9.9.9')
    expect(v.status).toBe('update-available')
    rmSync(prof, { recursive: true, force: true })
  })

  it('store 目录不存在时会创建（mkdir recursive）', async () => {
    const nested = join(dir, 'a', 'b')
    setUpdateCheckDirForTest(nested)
    mkdirSync(nested, { recursive: true })
    stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.1.0' } })
    await maybeCheckForUpdate()
    expect(existsSync(join(nested, 'update-check.json'))).toBe(true)
  })

  it.skipIf(!canSymlink)('落盘不穿符号链接：tmp 名被预植为链接到受害文件时，受害文件必须原样', async () => {
    // 攻击面：tmp 名含固定 pid，同用户进程可预植 `update-check.json.tmp.<pid> -> 任意目标`；
    // 裸 writeFileSync 默认 'w' 会跟随链接盲写（实测可毁掉目标）。writeTmpExclusive 的 'wx'
    // 排他创建遇预置物 EEXIST → 删掉重写，绝不写穿链接。
    const victim = join(dir, 'VICTIM.txt')
    writeFileSync(victim, 'ORIGINAL-CONTENT')
    symlinkSync(victim, updateCheckPath() + '.tmp.' + process.pid)
    stubFetch({ version: '9.9.9', dshCompat: { tested: '^0.1.0' } })
    await maybeCheckForUpdate()
    expect(readFileSync(victim, 'utf8')).toBe('ORIGINAL-CONTENT') // 没写穿
    expect(existsSync(updateCheckPath())).toBe(true) // 但正常结论仍然落了盘
  })
})
