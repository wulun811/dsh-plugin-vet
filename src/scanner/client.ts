import { spawn, spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { resolveVetFile } from '../pkg-root.js'
import type { ScanRequest, ScanResponse } from './protocol.js'

/**
 * C3（0.1.16 加固）：宿主侧快照缓存目录 + 进程内随机 nonce。
 * vet 模块加载早于第三方插件（M2 同款快照语义），插件此后改动 process.env 无法重定向缓存；
 * nonce 仅经请求 JSON（stdin）传给 scanner 子进程，同进程插件读不到闭包值 → 预写伪造缓存失败。
 */
const CACHE_NONCE = randomBytes(16).toString('hex')
const CACHE_DIR_INJECT = process.env.DSH_PLUGIN_VET_CACHE_DIR ?? undefined

/** 独立进程 scanner-bin 入口（lib/scanner-bin/index.js），按候选目录解析，兼容 bundle/逐文件形态。 */
const SCANNER_BIN = resolveVetFile('scanner-bin/index.js')

/**
 * 扫描并发上限（技术债偿还，NEXT-GEN-PLAN 前置）：scanner 是每请求一子进程（spawn），
 * 大批量插件同时加载（首次启动解析整个 profile 树）并发 spawn 会打爆进程/句柄。
 * 上限 2 并发，超出排队（FIFO）。scanSync（spawnSync 同步路径）不排队——同步调用
 * 无法让出事件循环，且 deny 路径本就是一次一个，注释记录即可。
 */
const MAX_CONCURRENT_SCANS = 2
let activeScans = 0
const scanQueue: (() => void)[] = []

async function withScanSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (activeScans < MAX_CONCURRENT_SCANS) {
    activeScans++
    try {
      return await fn()
    } finally {
      activeScans--
      pumpScanQueue()
    }
  }
  return new Promise<T>((resolve, reject) => {
    scanQueue.push(() => {
      void (async () => {
        try {
          resolve(await fn())
        } catch (error) {
          reject(error)
        }
      })()
    })
  })
}

function pumpScanQueue(): void {
  while (activeScans < MAX_CONCURRENT_SCANS && scanQueue.length > 0) {
    const next = scanQueue.shift()
    if (next === undefined) return
    next()
  }
}

export interface ScanOptions {
  timeoutMs?: number
}

/** 异步扫描：spawn scanner-bin，请求-响应式，超时 kill（不伪造 verdict）。 */
export async function scan(request: ScanRequest, options: ScanOptions = {}): Promise<ScanResponse> {
  return withScanSlot(() => scanInner(request, options))
}

async function scanInner(request: ScanRequest, options: ScanOptions = {}): Promise<ScanResponse> {
  const timeoutMs = options.timeoutMs ?? 15_000
  // P2-1：把宿主计划超时带给 engine——它按 min(files×2s, timeout-余量) 收敛预算，
  // R8-skip 先于本进程的 kill 触发，大包不再报 scan-fail
  const payload: ScanRequest = {
    ...request,
    timeoutMs,
    cacheNonce: CACHE_NONCE,
    ...(CACHE_DIR_INJECT !== undefined && CACHE_DIR_INJECT !== '' ? { cacheDir: CACHE_DIR_INJECT } : {}),
  }
  return new Promise<ScanResponse>(resolve => {
    const child = spawn(process.execPath, [SCANNER_BIN], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    let done = false
    const finish = (value: ScanResponse): void => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve(value)
    }
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      finish({ ok: false, error: `scanner timeout after ${timeoutMs}ms` })
    }, timeoutMs)
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', err => finish({ ok: false, error: String(err) }))
    child.on('close', () => {
      const line = stdout.trim().split('\n').pop()
      if (line === undefined) {
        finish({ ok: false, error: `scanner produced no output; stderr: ${stderr.slice(0, 200)}` })
        return
      }
      try {
        finish(JSON.parse(line) as ScanResponse)
      } catch (err) {
        finish({ ok: false, error: `scanner invalid output: ${String(err)}; stderr: ${stderr.slice(0, 200)}` })
      }
    })
    // scanner-bin 启动失败时 stdin 流可能已销毁：write 抛错/EPIPE 必须兜住，不能崩宿主
    child.stdin.on('error', () => { /* close 事件会走失败分支 */ })
    try {
      child.stdin.write(JSON.stringify(payload))
    } catch (error) {
      // L3: write 抛错（EPIPE/流销毁）时子进程可能还活着——必须 kill，否则成孤儿
      try { child.kill('SIGKILL') } catch { /* 已退出 */ }
      finish({ ok: false, error: `scanner stdin write failed: ${String(error)}` })
      return
    }
    child.stdin.end()
  })
}

/**
 * 同步扫描（spawnSync）：internal/plugin 守卫 deny 路径需要同步判定才能在 observer 内抛错回滚挂载。
 */
export function scanSync(request: ScanRequest, options: ScanOptions = {}): ScanResponse {
  const timeoutMs = options.timeoutMs ?? 15_000
  // P2-1：同 async 路径，把超时带给 engine（deny 同步路径同样受益于 R8-skip 先于 kill）
  const payload: ScanRequest = {
    ...request,
    timeoutMs,
    cacheNonce: CACHE_NONCE,
    ...(CACHE_DIR_INJECT !== undefined && CACHE_DIR_INJECT !== '' ? { cacheDir: CACHE_DIR_INJECT } : {}),
  }
  let result
  try {
    result = spawnSync(process.execPath, [SCANNER_BIN], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
      timeout: timeoutMs,
      maxBuffer: 64 * 1024 * 1024,
    })
  } catch (error) {
    // maxBuffer 超限/参数异常会抛而非返回 → 归为失败，绝不向上抛（deny 守卫同步路径无外层保护）
    return { ok: false, error: `scanner spawnSync failed: ${String(error)}` }
  }
  if (result.status !== 0) {
    return { ok: false, error: `scanner exit ${result.status}: ${String(result.stderr).slice(0, 200)}` }
  }
  try {
    return JSON.parse(result.stdout.trim()) as ScanResponse
  } catch (err) {
    return { ok: false, error: `scanner invalid output: ${String(err)}` }
  }
}
