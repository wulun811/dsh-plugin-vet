/**
 * Google OSV 已知漏洞查询（npm 生态）：https://api.osv.dev/v1/query
 * R10 供应链检查的已知漏洞核对层（OSV 落地）。
 * F15：按 name+version 查询——OSV 服务端按 affected ranges 过滤，已修复版本不再误报
 * （旧注释「只按包名查询」已过期，P3-14 同步）。网络失败/超时由调用方静默降级。
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

/**
 * 查询某 npm 包在指定版本下受影响的已知漏洞（F15：带 version 查询——OSV 服务端按
 * affected ranges 过滤，只返回该版本实际受影响的漏洞；原来只按包名查，已修复版本
 * 也会被报 high → 误判 suspicious）。
 */
export async function queryOsv(name: string, options: OsvQueryOptions & { version?: string } = {}): Promise<OsvVuln[]> {
  const { timeoutMs = 4000, fetchImpl = fetch, version } = options
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        package: { name, ecosystem: 'npm' },
        ...(version !== undefined && version !== '' ? { version } : {}),
      }),
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