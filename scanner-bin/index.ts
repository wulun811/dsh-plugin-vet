#!/usr/bin/env node
/**
 * scanner-bin entry: read one JSON ScanRequest from stdin, write one JSON
 * ScanResponse line to stdout. Runs as an isolated child process; never evals.
 */
import { scan } from './engine.js'
import type { ScanResponse } from './protocol.js'

function respond(response: ScanResponse): void {
  process.stdout.write(JSON.stringify(response) + '\n')
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
    respond(scan(request))
  } catch (error) {
    respond({ ok: false, error: `invalid JSON: ${String(error)}` })
  }
})
process.stdin.on('error', () => respond({ ok: false, error: 'stdin error' }))
