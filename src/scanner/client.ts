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
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      resolve({ ok: false, error: `scanner timeout after ${timeoutMs}ms` })
    }, timeoutMs)
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', err => { clearTimeout(timer); resolve({ ok: false, error: String(err) }) })
    child.on('close', () => {
      clearTimeout(timer)
      const line = stdout.trim().split('\n').pop()
      if (line === undefined) {
        resolve({ ok: false, error: `scanner produced no output; stderr: ${stderr.slice(0, 200)}` })
        return
      }
      try {
        resolve(JSON.parse(line) as ScanResponse)
      } catch (err) {
        resolve({ ok: false, error: `scanner invalid output: ${String(err)}; stderr: ${stderr.slice(0, 200)}` })
      }
    })
    child.stdin.write(JSON.stringify(request))
    child.stdin.end()
  })
}

/**
 * 同步扫描（spawnSync）：internal/plugin 守卫 deny 路径需要同步判定才能在 observer 内抛错回滚挂载。
 */
export function scanSync(request: ScanRequest, options: ScanOptions = {}): ScanResponse {
  const timeoutMs = options.timeoutMs ?? 15_000
  const result = spawnSync(process.execPath, [SCANNER_BIN], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  })
  if (result.status !== 0) {
    return { ok: false, error: `scanner exit ${result.status}: ${String(result.stderr).slice(0, 200)}` }
  }
  try {
    return JSON.parse(result.stdout.trim()) as ScanResponse
  } catch (err) {
    return { ok: false, error: `scanner invalid output: ${String(err)}` }
  }
}
