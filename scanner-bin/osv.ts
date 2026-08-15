/**
 * Google OSV 已知漏洞查询（npm 生态）：https://api.osv.dev/v1/query
 * PLAN.md §14.6 落地：R10 供应链检查的已知漏洞核对层。
 * 只按包名查询（版本级解析超出 v1 范围）；网络失败/超时由调用方静默降级。
 * fetch 可注入，便于测试（不真正联网）。
 */

export interface OsvVuln {
  id: string
  aliases: string[]
  summary?: string
}

export interface OsvQueryOptions {
  timeoutMs?: number
  fetchImpl?: typeof fetch
}

/** 查询某 npm 包的全部已知漏洞（OSV 返回按相关度排序，取前 N 由调用方决定）。 */
export async function queryOsv(name: string, options: OsvQueryOptions = {}): Promise<OsvVuln[]> {
  const { timeoutMs = 4000, fetchImpl = fetch } = options
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem: 'npm' } }),
      signal: controller.signal,
    })
    if (!res.ok) throw new Error('osv http ' + res.status)
    const body = (await res.json()) as {
      vulns?: { id?: string; aliases?: string[]; summary?: string }[]
    }
    const list = body.vulns ?? []
    return list.map(v => ({
      id: v.id ?? 'unknown',
      aliases: Array.isArray(v.aliases) ? v.aliases : [],
      summary: v.summary,
    }))
  } finally {
    clearTimeout(timer)
  }
}
