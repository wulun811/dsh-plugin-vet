/**
 * round-19：T1 哨兵 macOS（darwin）采样面。
 * 三层验证：①解析器纯函数（macOS 真机输出 fixture，Linux CI 可跑）；
 * ②pidCmdlineIsVetSidecar darwin 分支的**真实路径**——Linux procps 与 macOS BSD ps 同支持
 * `ps -o args=`，故在 Linux CI 上也能拿活进程验证（mac CI 再跑一遍即真机语义）；
 * ③sidecarMain 注入 fake run 端到端（darwin 分派、报警 JSON 行、数据源失败降级）。
 */
import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import {
  parseDarwinPsTable, countDarwinLsofFd, parseDarwinSiblings, sidecarMain,
  type CmdRunner, type WatchConfig,
} from '../lib/guard/runtime-watch.js'
import { pidCmdlineIsVetSidecar } from '../lib/guard/runtime-sidecar.js'

describe('parseDarwinPsTable（ps -Axo pid=,ppid=,rss= 全表解析）', () => {
  const HOST = 4321
  const SELF = 4322
  it('宿主 RSS + 子进程数（ppid 匹配）+ self ppid 一次采齐', () => {
    const out = [
      '    1     0 120000',
      `${HOST}     1 250980`,
      `${SELF}  ${HOST}  98304`,
      ` 9999  ${HOST}   1024`,   // 第二个孩子 → childCount=2
      ' 7777  5555   2048',      // 别人家的进程
    ].join('\n')
    const r = parseDarwinPsTable(out, HOST, SELF)
    expect(r.sample).not.toBeNull()
    expect(r.sample!.rssKb).toBe(250980)
    expect(r.sample!.childCount).toBe(2)
    expect(r.selfPpid).toBe(HOST)
  })
  it('宿主行缺失（已退出/表不全）→ sample=null；selfPpid 仍可独立给出', () => {
    const out = `${SELF}  ${HOST}  5000\n`
    const r = parseDarwinPsTable(out, HOST, SELF)
    expect(r.sample).toBeNull()
    expect(r.selfPpid).toBe(HOST)
  })
  it('self 行缺失 → selfPpid=null（调用方不得据此自杀——宁缺勿误判）', () => {
    const r = parseDarwinPsTable(`${HOST}     1 250980`, HOST, SELF)
    expect(r.sample!.rssKb).toBe(250980)
    expect(r.selfPpid).toBeNull()
  })
  it('垃圾行/空行/表头容错（列宽浮动、非数字行）', () => {
    const out = [
      '',
      '  PID  PPID    RSS',           // 意外表头
      '   ab    cd     ef',           // 非数字
      `${HOST}     1  256`,
      `${SELF}  ${HOST}  128`,
      `${HOST}x ${HOST} 999`,         // 前缀数字干扰（\s 边界不匹配 → 忽略）
    ].join('\n')
    const r = parseDarwinPsTable(out, HOST, SELF)
    expect(r.sample!.rssKb).toBe(256)
    expect(r.sample!.childCount).toBe(1)
  })
})

describe('countDarwinLsofFd（lsof -w -p <pid> -Fn 记录计数）', () => {
  it('只数 f 记录；p/5/c/t 等进程头与元数据忽略', () => {
    const out = [
      'p4321', '4321', 'd', 'nnode',
      'fcwd', 'tDIR', 'n/home/u', 'n/',       // cwd 的 f 行也计（与 /proc/fd 同口径的保守上界）
      'f1u', 'f2r', 'txt/mach_o',
      'f3w',
    ].join('\n')
    expect(countDarwinLsofFd(out)).toBe(4)   // fcwd/f1u/f2r/f3w
  })
  it('空输出 → 0；仅行首 f 计数（n/t/c 前缀含 f 不误计）', () => {
    expect(countDarwinLsofFd('')).toBe(0)
    expect(countDarwinLsofFd('nfoo/bar\ntfake\nchdir\n')).toBe(0) // 行首 n/t/c → 不计
    expect(countDarwinLsofFd('f0r\nf1w\nnfoo\n')).toBe(2)
  })
})

describe('parseDarwinSiblings（ps command= 单例认亲）', () => {
  it('同宿主带标记兄弟命中；自己/别家/无标记/表头全排除', () => {
    const out = [
      '  PID  PPID COMMAND',
      '  100  900 node /opt/vet/lib/guard/runtime-watch.js --vet-sidecar 2000',  // 别家宿主（900）
      '  101  500 node /opt/vet/lib/guard/runtime-watch.js --vet-sidecar 2000',  // ✓ 命中
      '  102  500 node /opt/vet/lib/guard/runtime-watch.js',                     // 无标记（宿主 import）
      '  103  500 node /opt/other/app.js --vet-sidecar',                         // 无 runtime-watch
      '  555  500 node /opt/vet/lib/guard/runtime-watch.js --vet-sidecar 2000',  // 自己（self=555）→ 排除
    ].join('\n')
    expect(parseDarwinSiblings(out, 500, 555)).toEqual([101])
  })
  it('ps 失败（空串）→ 空表 = 放行（宁可重复监视不让 T1 熄灭）', () => {
    expect(parseDarwinSiblings('', 500, 555)).toEqual([])
  })
})

describe('pidCmdlineIsVetSidecar darwin 分支（真实 ps 路径，Linux procps 同支持）', () => {
  it.skipIf(process.platform === 'win32')('活进程：带 --vet-sidecar 脚本参数 → true；不带 → false', () => {
    const dir = mkdtempSync(join(tmpdir(), 't1-darwin-'))
    const script = join(dir, 'keepalive.js')
    writeFileSync(script, 'setInterval(() => {}, 1e9)')
    const marked = spawn(process.execPath, [script, '--vet-sidecar'], { stdio: 'ignore' })
    const plain = spawn(process.execPath, [script], { stdio: 'ignore' })
    try {
      // exec 就绪等待（并行负载下窗口可达数百 ms——round-18 同纪律）
      const readyDeadline = Date.now() + 10_000
      while (Date.now() < readyDeadline && !pidCmdlineIsVetSidecar(marked.pid!, 'darwin')) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25)
      }
      expect(pidCmdlineIsVetSidecar(marked.pid!, 'darwin')).toBe(true)
      // plain 子进程也需 exec 完成才有稳定 ps 输出：以「ps 能读到脚本名」为就绪前提
      const plainReady = Date.now() + 10_000
      let plainSeen = false
      while (Date.now() < plainReady) {
        try {
          const { execFileSync } = require('node:child_process') as typeof import('node:child_process')
          if (execFileSync('ps', ['-w', '-w', '-o', 'args=', '-p', String(plain.pid)], { encoding: 'utf8' }).includes('keepalive.js')) { plainSeen = true; break }
        } catch { /* ps 抖动 */ }
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25)
      }
      expect(plainSeen).toBe(true)
      expect(pidCmdlineIsVetSidecar(plain.pid!, 'darwin')).toBe(false)
      // 不存在的 pid → false；未支持平台 → 恒 false
      expect(pidCmdlineIsVetSidecar(2 ** 30, 'darwin')).toBe(false)
      expect(pidCmdlineIsVetSidecar(marked.pid!, 'win32')).toBe(false)
    } finally {
      try { marked.kill() } catch { /* 已退出 */ }
      try { plain.kill() } catch { /* 已退出 */ }
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('sidecarMain darwin 分派（注入 fake run，端到端）', () => {
  const cfg = (over: Partial<WatchConfig> = {}): WatchConfig => ({
    intervalMs: 60_000, memLimitMb: 1000, forkBurstN: 5, fdLimit: 512, growthMb: 256, growthWindowMs: 600_000, ...over,
  })
  const captureStdout = async (run: CmdRunner, watchCfg: WatchConfig): Promise<string[]> => {
    const lines: string[] = []
    const orig = process.stdout.write.bind(process.stdout)
    let timer: NodeJS.Timeout | undefined
    ;(process.stdout as unknown as { write: (s: string) => boolean }).write = (s: string) => { lines.push(s); return true }
    try {
      timer = sidecarMain(watchCfg, { platform: 'darwin', run })
    } finally {
      process.stdout.write = orig as typeof process.stdout.write
      if (timer) clearInterval(timer)
    }
    return lines
  }
  it('ps 表超内存阈值 → 首拍 stdout 出 t1:mem red JSON 行；lsof 被调用', async () => {
    const host = process.ppid
    let lsofCalls = 0
    const run: CmdRunner = (cmd, args) => {
      if (cmd === 'lsof') { lsofCalls++; return 'p1\nf0r\nf1w\n' }
      if (args.includes('pid=,ppid=,command=')) return ''
      return `${host} 1 3145728\n${process.pid} ${host} 9000\n` // 3GB → mem red
    }
    const lines = await captureStdout(run, cfg())
    const alarms = lines.map(l => JSON.parse(l))
    expect(alarms.some(a => a.source === 't1' && a.kind === 'mem' && a.severity === 'red')).toBe(true)
    expect(lsofCalls).toBe(1)
  })
  it('ps 数据源失败（null）→ 本轮静默降级：无报警、不自杀、定时器可清理', async () => {
    const run: CmdRunner = () => null
    const lines = await captureStdout(run, cfg())
    expect(lines).toEqual([])
  })
  it('fd 超限报警走 lsof 计数（fdCount 合并进样本）', async () => {
    const host = process.ppid
    const run: CmdRunner = (cmd, args) => {
      if (cmd === 'lsof') return 'p1\n' + Array.from({ length: 600 }, (_, k) => `f${k}`).join('\n')
      if (args.includes('pid=,ppid=,command=')) return ''
      return `${host} 1 5000\n${process.pid} ${host} 9000\n`
    }
    const lines = await captureStdout(run, cfg({ fdLimit: 512 }))
    const alarms = lines.map(l => JSON.parse(l))
    expect(alarms.some(a => a.kind === 'fd' && a.severity === 'yellow' && a.target === 'fds=600')).toBe(true)
  })
})
