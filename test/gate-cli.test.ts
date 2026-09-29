import { describe, expect, it } from 'vitest'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const CLI = join(ROOT, 'lib', 'gate-cli.js')

/** 一个管道缓冲区（Linux 默认 64 KiB）。 */
const PIPE_BUFFER_BYTES = 65_536
/** 每条 R2 动态执行发现约 280 字节 → 4000 条 ≈ 1 MB，远超任何「退出前抢写」的突发量。 */
const FINDING_COUNT = 4_000
/** 暂停消费 stdout 的时长：足以让子进程跑完扫描并尝试输出。 */
const READ_PAUSE_MS = 1_200

interface GateOutput {
  findings?: unknown[]
  blocked?: boolean
}

/**
 * `vet-gate` 输出完整性回归（0.3.17）。
 *
 * 旧实现在 `console.log(JSON)` 之后立刻 `process.exit()`：stdout 是**管道**时写入是异步的，
 * 未 drain 的队列被进程直接丢弃——实测大包 JSON 被截断（`| cat` 下恰好 65536 字节 = 一个
 * 管道缓冲区），且不再是合法 JSON。`vet-gate … | jq`、CI 采集等程序化调用会因此拿到坏数据。
 * 重定向到文件时 stdout 是同步写，缺陷不显形——这正是它长期潜伏的原因。
 *
 * 这里刻意做**慢消费者**：前 READ_PAUSE_MS 不读 stdout，让管道写满后队列只能靠进程自己保住。
 * 旧实现必然丢尾部；新实现会一直等到排空再退出。断言输出可解析且发现数组完整。
 */
describe('vet-gate CLI 输出完整性（管道截断回归）', () => {
  it('大输出在慢消费者管道下仍是完整合法 JSON（发现数组不丢元素）', async () => {
    const pkgDir = mkdtempSync(join(tmpdir(), 'vet-gate-cli-pkg-'))
    const storeDir = mkdtempSync(join(tmpdir(), 'vet-gate-cli-store-'))
    try {
      const lines: string[] = []
      for (let i = 0; i < FINDING_COUNT; i++) lines.push(`eval("payload-${i}")`)
      writeFileSync(join(pkgDir, 'index.js'), lines.join('\n') + '\n')
      writeFileSync(
        join(pkgDir, 'package.json'),
        JSON.stringify({ name: 'vet-gate-cli-fixture', version: '1.0.0', main: 'index.js' }),
      )

      // stderr 走 ignore：避免一个无人消费的 stderr 管道反过来阻塞子进程
      const child = spawn(process.execPath, [CLI, '--package', pkgDir], {
        cwd: ROOT,
        stdio: ['ignore', 'pipe', 'ignore'],
        env: { ...process.env, DSH_PLUGIN_VET_STORE_DIR: storeDir },
      })
      child.on('error', () => {})

      // 慢消费者窗口：不读 stdout
      await new Promise((resolve) => setTimeout(resolve, READ_PAUSE_MS))

      const chunks: Buffer[] = []
      child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk))
      child.stdout.resume()

      const code = await new Promise<number | null>((resolve) => child.on('close', resolve))
      const out = Buffer.concat(chunks).toString('utf8')

      expect(code).toBe(0)
      expect(out.length).toBeGreaterThan(PIPE_BUFFER_BYTES)
      // 核心断言：截断的 JSON 会在这里抛（旧实现即如此）
      const parsed = JSON.parse(out) as GateOutput
      expect(Array.isArray(parsed.findings)).toBe(true)
      expect(parsed.findings?.length).toBe(FINDING_COUNT)
      // 尾部完整：JSON 的最后一个非空白字符必须是闭合对象
      expect(out.trimEnd().endsWith('}')).toBe(true)
    } finally {
      rmSync(pkgDir, { recursive: true, force: true })
      rmSync(storeDir, { recursive: true, force: true })
    }
  }, 60_000)

  it('用法错误走 stderr 且退出码 2（不静默空输出）', () => {
    const res = spawnSync(process.execPath, [CLI], { cwd: ROOT, encoding: 'utf8', timeout: 30_000 })
    expect(res.status).toBe(2)
    expect(res.stderr).toMatch(/Usage: vet-gate/)
  })
})
