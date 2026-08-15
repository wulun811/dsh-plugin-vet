import { spawn, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import type { ScanRequest, ScanResponse } from './protocol.js'

/** 独立进程 scanner-bin 入口（lib/scanner-bin/index.js），经 import.meta.url 解析，不依赖 cwd。 */
const SCANNER_BIN = fileURLToPath(new URL('../scanner-bin/index.js', import.meta.url))

export interface ScanOptions {
  timeoutMs?: number
}

/** 异步扫描：spawn scanner-bin，请求-响应式，超时 kill（不伪造 verdict）。 */
export async function scan(request: ScanRequest, options: ScanOptions = {}): Promise<ScanResponse> {
  const timeoutMs = options.timeoutMs ?? 15_000
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
      child.stdin.write(JSON.stringify(request))
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
  let result
  try {
    result = spawnSync(process.execPath, [SCANNER_BIN], {
      input: JSON.stringify(request),
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
