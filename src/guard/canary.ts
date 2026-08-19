/**
 * N4 蜜罐金丝雀（Canary Watermark）：把「被动等触碰」升级为「主动确认外泄」。
 * 每个诱饵文件的值字段嵌入一枚唯一高熵金丝雀串；T2 网络出口观测（URL/请求体/spawn 参数）
 * 在出站数据里做子串匹配——命中 = 100% 确认外泄（没有任何合法理由把蜜罐密钥发出去）。
 * 完全离线：本地生成、本地匹配，无回传。
 * 反蜜罐一致性（v2 拍板）：金丝雀串为纯随机 40 位 hex（160 位熵），**不含 vet/honeypot 等关键词**
 * ——文件内容仍遵守「无蜜罐关键词」的反蜜罐要求（D27 用户反馈）；vet 身份只出现在内存集合
 * 与报警文案里，不进入诱饵文件。
 * 诚实边界（v2）：canary 分片经多次请求外泄的重组对抗不做（检测对抗的螺旋，记录为边界）。
 * @module dsh-plugin-vet/canary
 */
import { randomBytes, createHash } from 'node:crypto'

/** 金丝雀串形态：40 位 hex（160 位熵；0-9a-f，天然不含任何关键词）。 */
export const CANARY_HEX_LEN = 40
export const CANARY_RE = /^[0-9a-f]{40}$/

/** 生成一枚唯一高熵金丝雀（纯 hex，无关键词前缀）。 */
export function generateCanary(): string {
  return randomBytes(20).toString('hex')
}

/**
 * 出站内容匹配：对一段出站文本做「直接 / URL 解码 / 一次 base64 解码」三变体匹配。
 * 返回命中的金丝雀串；未命中返回 undefined。
 */
export function matchCanaryIn(text: string, canaries: readonly string[]): string | undefined {
  if (text === '' || canaries.length === 0) return undefined
  for (const c of canaries) {
    if (text.includes(c)) return c
  }
  const decoded = tryUrlDecode(text)
  if (decoded !== undefined && decoded !== text) {
    for (const c of canaries) {
      if (decoded.includes(c)) return c
    }
  }
  const b64 = tryB64Decode(text)
  if (b64 !== undefined && b64 !== text) {
    for (const c of canaries) {
      if (b64.includes(c)) return c
    }
    const b64dec = tryUrlDecode(b64)
    if (b64dec !== undefined && b64dec !== b64) {
      for (const c of canaries) {
        if (b64dec.includes(c)) return c
      }
    }
  }
  return undefined
}

function tryUrlDecode(text: string): string | undefined {
  if (!/%[0-9a-fA-F]{2}/.test(text)) return undefined
  try {
    return decodeURIComponent(text)
  } catch {
    return undefined
  }
}

function tryB64Decode(text: string): string | undefined {
  const clean = text.replace(/[^A-Za-z0-9+/=]/g, '').trim()
  if (clean.length === 0 || clean.length % 4 !== 0) return undefined
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) return undefined
  try {
    const buf = Buffer.from(clean, 'base64')
    if (buf.length === 0) return undefined
    return buf.toString('utf8')
  } catch {
    return undefined
  }
}

/**
 * 活跃金丝雀集合（内存态，不写盘——避免被插件读到集合后规避）。
 * 模块级单例；ensureHoneypot 写入诱饵时注册，T2 出站观测读取匹配。
 */
export class CanaryStore {
  private readonly canaries: string[] = []

  register(...values: string[]): void {
    for (const v of values) {
      if (typeof v === 'string' && v.length >= 24 && !this.canaries.includes(v)) this.canaries.push(v)
    }
  }

  /** 活跃金丝雀数量（0 = 匹配短路）。 */
  count(): number {
    return this.canaries.length
  }

  /** 全部活跃金丝雀快照（只读副本；测试/取证用）。 */
  snapshot(): string[] {
    return [...this.canaries]
  }

  /** 出站内容匹配（三变体）。 */
  match(text: string): string | undefined {
    if (this.canaries.length === 0) return undefined
    return matchCanaryIn(text, this.canaries)
  }

  clear(): void {
    this.canaries.length = 0
  }
}

/** 进程级单例。 */
export const canaryStore = new CanaryStore()

/** 单测辅助：重置（fixture 隔离）。 */
export function resetCanaryStore(): void {
  canaryStore.clear()
}

/** 完整性金丝雀文件内容：固定文本 + 自身内容的已知哈希（可离线校验完整性）。 */
export function integrityCanaryContent(name: string): string {
  const body = 'vet-integrity-' + name
  return body + '\nsha256:' + createHash('sha256').update(body).digest('hex') + '\n'
}
