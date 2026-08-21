/**
 * T2 钩子台账字节计数与流包装
 * P0-4 结构债拆分自 runtime-hooks.ts（纯函数/无副作用：attachWriteCounter / attachCanaryScanner / attachReadCounter）
 */
/** 数据块字节数（Buffer/string/TypedArray/ArrayBuffer；未知返回 0，绝不抛）。 */
export function chunkBytes(chunk: unknown): number {
  if (typeof chunk === 'string') return Buffer.byteLength(chunk, 'utf8')
  if (Buffer.isBuffer(chunk)) return chunk.length
  if (chunk instanceof Uint8Array) return chunk.byteLength
  if (typeof chunk === 'object' && chunk !== null && 'byteLength' in chunk) {
    const n = (chunk as { byteLength?: unknown }).byteLength
    if (typeof n === 'number') return n
  }
  return 0
}

/** 一次 fs 调用的字节量：读 = 结果长度；写 = 数据参数长度（流操作由流计数器按 chunk 上报）。 */
export function fsOpBytes(opName: string, args: unknown[], result: unknown): number {
  if (opName === 'readFile' || opName === 'readFileSync') return chunkBytes(result)
  if (opName === 'writeFile' || opName === 'writeFileSync' || opName === 'appendFile' || opName === 'appendFileSync') {
    return chunkBytes(args[1])
  }
  return 0
}

const WRITE_COUNTER_FLAG = Symbol('vet-ledger-write-counter')
const END_COUNTER_FLAG = Symbol('vet-ledger-end-counter')
const CANARY_FLAG = Symbol('vet-canary-monitor')
const READ_COUNTER_FLAG = Symbol('vet-ledger-read-counter')
/** 包装可写对象（http.ClientRequest / net.Socket / fs.WriteStream）的 write/end，按 chunk 计数。 */
export function attachWriteCounter(obj: { write?: unknown; end?: unknown }, onBytes: (n: number) => void): void {
  const flagged = obj as { [k: symbol]: unknown }
  const write = obj.write
  if (typeof write === 'function' && flagged[WRITE_COUNTER_FLAG] !== true) {
    flagged[WRITE_COUNTER_FLAG] = true
    const w = write as (...a: unknown[]) => unknown
    obj.write = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      const n = chunkBytes(chunk)
      if (n > 0) onBytes(n)
      return w.apply(this, [chunk, ...rest])
    }
  }
  const end = obj.end
  if (typeof end === 'function' && flagged[END_COUNTER_FLAG] !== true) {
    flagged[END_COUNTER_FLAG] = true
    const e = end as (...a: unknown[]) => unknown
    obj.end = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      const n = chunkBytes(chunk)
      if (n > 0) onBytes(n)
      return e.apply(this, [chunk, ...rest])
    }
  }
}

/**
 * N4 金丝雀出站监控：包装请求对象 write/end，把 body 文本按 chunk 累计（跨 chunk 拼接、
 * 上限 64KB 截尾——canary 每次必然落在尾部窗口内）并调用 onText 回调。幂等（防二次包装）。
 */
export function attachCanaryScanner(obj: { write?: unknown; end?: unknown }, onText: (text: string) => void): void {
  if ((obj as { [k: symbol]: unknown })[CANARY_FLAG] === true) return
  ;(obj as { [k: symbol]: unknown })[CANARY_FLAG] = true
  let buf = ''
  const push = (chunk: unknown): void => {
    if (typeof chunk === 'string') buf += chunk
    else {
      const n = chunkBytes(chunk)
      if (n === 0) return
      buf += typeof chunk === 'object' && chunk !== null && 'toString' in chunk ? String(chunk) : ''
    }
    if (buf.length > 64 * 1024) buf = buf.slice(buf.length - 64 * 1024)
    onText(buf)
  }
  const write = obj.write
  if (typeof write === 'function') {
    const w = write as (...a: unknown[]) => unknown
    obj.write = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      push(chunk)
      return w.apply(this, [chunk, ...rest])
    }
  }
  const end = obj.end
  if (typeof end === 'function') {
    const e = end as (...a: unknown[]) => unknown
    obj.end = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      push(chunk)
      return e.apply(this, [chunk, ...rest])
    }
  }
}

/** 包装可读流（createReadStream）的 data 处理器：只包第一个 data 监听器，计数每个 chunk 一次。 */
export function attachReadCounter(stream: { on?: unknown }, onBytes: (n: number) => void): void {
  const on = stream.on
  if (typeof on !== 'function' || (stream as { [k: symbol]: unknown })[READ_COUNTER_FLAG] === true) return
  ;(stream as { [k: symbol]: unknown })[READ_COUNTER_FLAG] = true
  const orig = on as (event: string, ...rest: unknown[]) => unknown
  let wrappedFirst = false
  stream.on = function (this: unknown, event: string, ...rest: unknown[]): unknown {
    if (event === 'data' && !wrappedFirst && typeof rest[0] === 'function') {
      wrappedFirst = true
      const handler = rest[0] as (chunk: unknown) => unknown
      rest[0] = function (this: unknown, chunk: unknown): unknown {
        const n = chunkBytes(chunk)
        if (n > 0) onBytes(n)
        return handler(chunk)
      }
    }
    return orig.apply(this, [event, ...rest])
  }
}
