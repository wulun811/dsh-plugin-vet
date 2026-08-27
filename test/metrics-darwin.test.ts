/**
 * round-20：宿主指标面板 macOS 支持（metrics.ts darwin 分支）。
 * 纪律与 t1-darwin-watch 相同：解析器是纯函数（Linux CI 上跑真 macOS 输出 fixture），
 * readHostMetrics 的 darwin 路径经注入 runAsync/now 的 fake 驱动，零真实 exec；
 * 交叉验证用 procps 真 `ps`（列名与 BSD ps 兼容，round-19 已验证）+ 真子进程。
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn, execFileSync } from 'node:child_process'
import {
  parseDarwinCpuMs,
  parseDarwinMetricTable,
  summarizeDarwinMetricRows,
  readHostMetrics,
  DARWIN_METRICS_PS_ARGS,
  defaultRunAsync,
  __resetDarwinMetricsCacheForTest,
  type AsyncCmdRunner,
} from '../lib/guard/metrics.js'
import { countDarwinLsofFd } from '../lib/guard/darwin-sysinfo.js'
import { countDarwinLsofFd as reExported } from '../lib/guard/runtime-watch.js'

describe('parseDarwinCpuMs（TIME 列 → 累计 CPU ms）', () => {
  it('三种真实形态：macOS m:ss.cs、macOS ≥1h h:mm:ss.cs、Linux h:mm:ss', () => {
    expect(parseDarwinCpuMs('0:05.42')).toBe(5420)
    expect(parseDarwinCpuMs('1:23.45')).toBe(83450)
    expect(parseDarwinCpuMs('1:02:03.45')).toBe(3723450)
    expect(parseDarwinCpuMs('00:01:30')).toBe(90000)
    expect(parseDarwinCpuMs('0:00.00')).toBe(0)
  })
  it('解析落空 → -1（该字段丢弃，绝不 NaN 传染）', () => {
    expect(parseDarwinCpuMs('garbage')).toBe(-1)
    expect(parseDarwinCpuMs('12')).toBe(-1)
    expect(parseDarwinCpuMs('1:2:3:4')).toBe(-1)
    expect(parseDarwinCpuMs('-1:00')).toBe(-1)
    expect(parseDarwinCpuMs('a:00.00')).toBe(-1)
    expect(parseDarwinCpuMs('1:x.0')).toBe(-1)
    // round-21：空段防 Number('')===0 静默错算（'12:' 绝不能当 12 分整）
    expect(parseDarwinCpuMs('12:')).toBe(-1)
    expect(parseDarwinCpuMs(':30')).toBe(-1)
    expect(parseDarwinCpuMs('1::2')).toBe(-1)
  })
})

describe('parseDarwinMetricTable（ps 全表，真 macOS 排版 fixture）', () => {
  it('列对齐空格 + command 含多空格；畸形行/续行静默跳过', () => {
    const out = [
      '  1     0       4096  0:12.34 /sbin/launchd',
      '  88   1      204800  0:05.00 /usr/local/bin/node /srv/app dsh   --profile   web',
      '  continuation-line-no-numbers',
      '  99   88        512  BADTIME   whatever',
    ].join('\n')
    const rows = parseDarwinMetricTable(out)
    expect(rows.length).toBe(2)
    expect(rows[0]).toEqual({ pid: 1, ppid: 0, rssKb: 4096, cpuMs: 12340, command: '/sbin/launchd' })
    // command 内部多空格原样保留（分类正则要完整命令行）
    expect(rows[1].command).toBe('/usr/local/bin/node /srv/app dsh   --profile   web')
    expect(rows[1].cpuMs).toBe(5000)
  })
})

describe('summarizeDarwinMetricRows（子进程汇总 + 分类 + 探针排除）', () => {
  it('childCount/mcp/vet 分类正确；host 行进 CPU；excludePid 不掺水', () => {
    const rows = parseDarwinMetricTable([
      '  500     1   204800  0:05.00 node /app/dsh --profile web',
      '  501   500     10240  0:01.00 node /srv/mcp/dsh-malong-bridge --stdio',
      '  502   500     20480  0:02.00 node /opt/vet/lib/guard/runtime-watch.js --vet-sidecar 2000',
      '  503   500     30720  0:00.50 /opt/vet/lib/scanner-bin/scanner --json',
      '  504   500      1024  0:00.10 node /app/other-child',
      '  777     2      4096  0:09.00 /usr/lib/systemd/journald',
      '  999   500      2048  0:00.05 ps -A -w -w -o pid=,ppid=,rss=,time=,command=',
    ].join('\n'))
    const s = summarizeDarwinMetricRows(rows, 500, 999)
    expect(s.childCount).toBe(4) // 探针 999 被排除
    expect(s.mcpCount).toBe(1)
    expect(s.vetCount).toBe(2) // sidecar + scanner-bin
    expect(s.mcpRssMb).toBe(10)
    expect(s.vetRssMb).toBe((20480 + 30720) / 1024)
    expect(s.hostCpuMs).toBe(5000)
  })
  it('host 行缺失 → hostCpuMs undefined（本轮不更新 CPU 差分，不造假）', () => {
    const rows = parseDarwinMetricTable('  501   500     10240 node /x 1\n')
    expect(summarizeDarwinMetricRows(rows, 500, undefined).hostCpuMs).toBeUndefined()
  })
})

describe('countDarwinLsofFd 共享化（round-20 抽 darwin-sysinfo）', () => {
  it('runtime-watch 再导出与单一定义同一函数（防漂移）', () => {
    expect(reExported).toBe(countDarwinLsofFd)
  })
})

/* ---------------- readHostMetrics darwin dispatch（全 fake 驱动） ---------------- */

const host = process.pid

const psTable = (hostTime: string): string => [
  `  1     0       4096  0:12.34 /sbin/launchd`,
  `  ${host}     1   204800  ${hostTime} node /app/dsh --profile web`,
  `  501   ${host}   10240  0:01.00 node /srv/mcp/dsh-malong-bridge --stdio`,
  `  502   ${host}   20480  0:02.50 node /opt/vet/lib/guard/runtime-watch.js --vet-sidecar 2000`,
  `  503   ${host}    1024  0:00.10 node /app/other-child`,
  `  999   ${host}    2048  0:00.05 ps -A -w -w -o pid=,ppid=,rss=,time=,command=`,
].join('\n')

const LSOF_FIXTURE = ['p' + host, 'nnode', 'f0', 'f1', 'f2', 'fcwd', 'ftxt', 'f123'].join('\n')

interface Drive {
  calls: string[]
  run: AsyncCmdRunner
}

/** 同步回调 fake：ps/lsof 立即出结果，探针 pid 固定 999（psTable 里埋了对应行验证排除）。 */
function syncFake(opts: { psOut?: (n: number) => string | null; lsofOut?: string | null } = {}): Drive & { psN: () => number; lsofN: () => number } {
  const d: Drive = { calls: [], run: () => undefined }
  let psN = 0
  let lsofN = 0
  d.run = (cmd, _args, _to, cb) => {
    d.calls.push(cmd)
    if (cmd === 'ps') {
      psN += 1
      const out = opts.psOut !== undefined ? opts.psOut(psN) : psTable('0:05.00')
      cb(out, 999)
      return 999
    }
    lsofN += 1
    cb(opts.lsofOut !== undefined ? opts.lsofOut : LSOF_FIXTURE, 998)
    return 998
  }
  return Object.assign(d, { psN: () => psN, lsofN: () => lsofN })
}

describe('readHostMetrics darwin dispatch（注入 fake：零真实 exec）', () => {
  beforeEach(() => {
    __resetDarwinMetricsCacheForTest()
  })

  it('首轮（回调同步）即得 子进程/分类/fd；CPU 需两次采样故 0；io=-1', () => {
    const f = syncFake()
    const m = readHostMetrics({ platform: 'darwin', runAsync: f.run, now: () => 1_000_000 })
    expect(m.childCount).toBe(3)
    expect(m.mcpCount).toBe(1)
    expect(m.vetCount).toBe(1)
    expect(m.mcpRssMb).toBe(10)
    expect(m.vetRssMb).toBe(20)
    expect(m.fdCount).toBe(6)
    expect(m.cpuPct).toBe(0)
    expect(m.ioReadMb).toBe(-1)
    expect(m.ioWriteMb).toBe(-1)
    expect(m.rssMb).toBeGreaterThan(0) // V8 自报，跨平台真实
    expect(f.calls).toEqual(['ps', 'lsof'])
  })

  it('CPU 差分：TIME +500ms / 墙钟 +5s → 10%；lsof 未到 TTL 不再调', () => {
    let t = 1_000_000
    const f = syncFake({ psOut: n => psTable(n === 1 ? '0:05.00' : '0:05.50') })
    const first = readHostMetrics({ platform: 'darwin', runAsync: f.run, now: () => t })
    expect(first.cpuPct).toBe(0)
    t = 1_005_000 // ≥ PS_TTL(4s) → 触发刷新；< FD_TTL(15s) → lsof 不重跑
    const second = readHostMetrics({ platform: 'darwin', runAsync: f.run, now: () => t })
    expect(second.cpuPct).toBe(10)
    expect(f.lsofN()).toBe(1)
    expect(second.fdCount).toBe(6) // 缓存的 fd 跨轮次保持
    expect(second.childCount).toBe(3)
  })

  it('fd 按 15s TTL 降频：15s 内不重跑，越界才重跑', () => {
    let t = 1_000_000
    const f = syncFake()
    readHostMetrics({ platform: 'darwin', runAsync: f.run, now: () => t })
    for (let i = 0; i < 2; i++) {
      t += 5_000 // 1_005_000 / 1_010_000：距上次 lsof <15s
      readHostMetrics({ platform: 'darwin', runAsync: f.run, now: () => t })
    }
    expect(f.lsofN()).toBe(1)
    t += 6_000 // 1_016_000：距 1_000_000 已 16s ≥ FD_TTL
    readHostMetrics({ platform: 'darwin', runAsync: f.run, now: () => t })
    expect(f.lsofN()).toBe(2)
  })

  it('inFlight 合并：回调挂起期间重复轮询不叠 ps；ps+lsof 全落地后恢复调度', () => {
    const cbs: Array<(out: string | null, pid: number | undefined) => void> = []
    let t = 1_000_000
    const run: AsyncCmdRunner = (cmd, _a, _to, cb) => {
      cbs.push(cb)
      return cmd === 'ps' ? 999 : 998
    }
    const m1 = readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(m1.childCount).toBe(-1) // 数据未到 → — 而不是假 0
    const m2 = readHostMetrics({ platform: 'darwin', runAsync: run, now: () => (t += 5_000) })
    expect(m2.childCount).toBe(-1)
    expect(cbs.length).toBe(1) // 第二轮被 inFlight 合并
    cbs[0](psTable('0:05.00'), 999) // ps 落地 → 立即链上 lsof（仍 in flight）
    expect(cbs.length).toBe(2)
    cbs[1](LSOF_FIXTURE, 998) // lsof 落地 → inFlight 释放
    t += 5_000
    const m3 = readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(cbs.length).toBe(3) // 新一轮 ps（第 3 个挂起回调）
    expect(m3.childCount).toBe(3) // 返回上一轮缓存（本轮回调未落地）
  })

  it('ps 超时（out=null）：保留旧值不清零，psAt 不前进故下轮重试', () => {
    let t = 1_000_000
    let psAttempts = 0
    const run: AsyncCmdRunner = (cmd, _a, _to, cb) => {
      if (cmd !== 'ps') {
        cb(LSOF_FIXTURE, 998)
        return 998
      }
      psAttempts += 1
      cb(psAttempts === 1 ? psTable('0:05.00') : null, 999)
      return 999
    }
    const first = readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(first.childCount).toBe(3)
    t += 5_000
    const stale = readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(stale.childCount).toBe(3) // ps 失败 → 旧缓存保持（不清零、不回退 -1）
    t += 5_000
    readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(psAttempts).toBe(3) // 失败不前进 psAt → 每轮照常重试
  })

  it('spawn 同步失败（runAsync 返回 undefined）：不抛错、不卡死 inFlight', () => {
    let t = 1_000_000
    let attempts = 0
    const run: AsyncCmdRunner = () => {
      attempts += 1
      return undefined
    }
    const m = readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(m.childCount).toBe(-1)
    t += 5_000
    readHostMetrics({ platform: 'darwin', runAsync: run, now: () => t })
    expect(attempts).toBe(2) // inFlight 未泄漏，第二轮照常尝试
  })
})

describe('readHostMetrics 平台回退', () => {
  it('win32：零 spawn，OS 侧字段 -1/0 回退，V8 数字真实', () => {
    let calls = 0
    const run: AsyncCmdRunner = () => {
      calls += 1
      return undefined
    }
    const m = readHostMetrics({ platform: 'win32', runAsync: run, now: () => 1_000_000 })
    expect(calls).toBe(0)
    expect(m.childCount).toBe(-1) // round-21：无数据源如实 —，不再伪装"确实没有子进程"的 0
    expect(m.fdCount).toBe(-1)
    expect(m.ioReadMb).toBe(-1)
    expect(m.cpuPct).toBe(0)
    expect(m.rssMb).toBeGreaterThan(0)
  })
})

describe('defaultRunAsync（真实现 execFile——mac 生产路径，Linux CI 直接可测）', () => {
  it.skipIf(process.platform === 'win32')('成功路径：cb 收到 stdout 字符串与探针 pid', async () => {
    const res = await new Promise<{ out: string | null; pid: number | undefined }>(resolve => {
      defaultRunAsync('ps', ['-A', '-o', 'pid='], 3000, (out, pid) => resolve({ out, pid }))
    })
    expect(typeof res.out === 'string' && res.out.length > 0).toBe(true)
    expect(res.pid).toBeTypeOf('number')
  })
  it('超时：cb 收 null（execFile 到点即杀，绝不让宿主面板悬挂）', async () => {
    const out = await new Promise<string | null | 'never'>(resolve => {
      defaultRunAsync('sleep', ['5'], 200, s => resolve(s))
    })
    expect(out).toBeNull()
  })
  it('命令不存在：cb 收 null 且不抛错（lsof/ps 缺失 = 降级不是事故）', async () => {
    const out = await new Promise<string | null | 'never'>(resolve => {
      defaultRunAsync('definitely-not-a-real-cmd-vet-r20', [], 2000, s => resolve(s))
    })
    expect(out).toBeNull()
  })
})

describe('交叉验证：真 ps（Linux procps / macOS BSD 原生同格式）', () => {
  it.skipIf(process.platform === 'win32')('真子进程按 production 形态 spawn 后被分类为 vet/mcp，探针自身可被 exclude', () => {
    const dir = mkdtempSync(join(tmpdir(), 'metrics-darwin-fix-'))
    const script = join(dir, 'keepalive.js')
    writeFileSync(script, 'setInterval(() => {}, 1e9)')
    // round-18 教训：flag 必须跟在脚本文件参数之后（node -e + flag 会被 node 当自己的选项）
    const vet = spawn(process.execPath, [script, '--vet-sidecar'], { stdio: 'ignore' })
    const mcp = spawn(process.execPath, [script, '--zfmcp-probe'], { stdio: 'ignore' })
    try {
      let s = undefined as ReturnType<typeof summarizeDarwinMetricRows> | undefined
      const deadline = Date.now() + 10_000
      while (Date.now() < deadline) {
        const out = execFileSync('ps', DARWIN_METRICS_PS_ARGS, { encoding: 'utf8', timeout: 3000 })
        const cand = summarizeDarwinMetricRows(parseDarwinMetricTable(out), host, undefined)
        if (cand.vetCount >= 1 && cand.mcpCount >= 1) {
          s = cand
          break
        }
        execFileSync('sleep', ['0.2'])
      }
      expect(s !== undefined).toBe(true)
      expect(s?.childCount).toBeGreaterThanOrEqual(2)
      expect(s?.hostCpuMs).toBeTypeOf('number')
      expect(s!.hostCpuMs!).toBeGreaterThanOrEqual(0)
    } finally {
      vet.kill('SIGKILL')
      mcp.kill('SIGKILL')
      rmSync(dir, { recursive: true, force: true })
    }
  }, 30_000)
})
