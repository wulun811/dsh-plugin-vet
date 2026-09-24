#!/usr/bin/env node
/**
 * scanner-bin entry: read one JSON ScanRequest from stdin, write one JSON
 * ScanResponse line to stdout. Runs as an isolated child process; never evals.
 */
import { scanWithOsv } from './engine.js'
import type { ScanResponse } from './protocol.js'

function respond(response: ScanResponse): void {
  // 0.3.14：写完即退出。宿主按子进程 close（退出）判定扫描结束——旧行为靠事件循环自然排空，
  // 残留句柄（半开 socket / 未 settle 的 fetch / 定时器）会让子进程在**报告已写出**之后继续
  // 存活，宿主一直等到 kill 超时 → 报 scan-fail「scanner timeout」（报告白写、verdict 丢失）。
  // 用 stdout 写回调保证数据已刷入管道后再退出（不截断报告）。
  process.stdout.write(JSON.stringify(response) + '\n', () => process.exit(0))
}

let input = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', chunk => { input += chunk })
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(input)
    if (request === null || typeof request !== 'object' || request.kind === undefined) {
      respond({ ok: false, error: 'invalid ScanRequest: missing kind' })
      return
    }
    void scanWithOsv(request).then(respond, error => respond({ ok: false, error: String(error) }))
  } catch (error) {
    respond({ ok: false, error: 'invalid JSON: ' + String(error) })
  }
})
process.stdin.on('error', () => respond({ ok: false, error: 'stdin error' }))
