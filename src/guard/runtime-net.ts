/**
 * 网络出口观测（P1 特性）
 * P0-4 结构债拆分自 runtime-hooks.ts（出口目标提取 / 敏感主机端口判定 / 网络操作分类，纯函数）
 */
import type { HookAlarm, HookConfig } from './runtime-ops.js'

/**
 * 网络模块的操作名集合。
 * P2-10：必须包含 'get'——http.get/https.get 是独立导出函数，其内部调用的是模块闭包里的
 * request（非 module.exports.request），只包装 request/connect/createConnection 会让
 * https.get('https://webhook.site/...') 这类外泄调用完全绕过出口监控（实测逃逸）。
 * tls/net 没有 get 导出，patchNetworkModule 的 typeof fn==='function' 守卫会跳过，安全。
 */
export const NET_OPS = new Set(['request', 'connect', 'createConnection', 'get'])

/** 敏感主机列表（v5 修订：移除 gist.github.com，合法服务）。 */
const SENSITIVE_HOSTS = [
  'webhook.site', 'requestbin.com', 'ngrok.io', 'localtunnel.me',
  'pastebin.com',
  'api.binance.com', 'api.coinbase.com',
]

/** 敏感端口（v5 修订：移除 8888，Jupyter 默认端口）。 */
const SENSITIVE_PORTS = new Set([4444, 5555, 6666, 7777, 1337, 31337])

/** 白名单主机（不报警）。 */
const EGRESS_ALLOWLIST = [
  'registry.npmjs.org',
  'api.github.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
]

/** 网络主机是否参与台账/外泄观测（回环/白名单/unix socket 不算——本地与受信服务不计数）。 */
export function isTrackedNetHost(hostname: string): boolean {
  const h = hostname.toLowerCase()
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === 'unix-socket') return false
  return !EGRESS_ALLOWLIST.includes(h)
}

/**
 * 从网络模块参数中提取目标（hostname, port, path）。
 * 处理多种参数形态：
 * - http.request(urlString, ...)
 * - http.request(urlObject, ...)
 * - http.request(options, ...)
 * - net.connect({ host, port }, ...)
 * - net.connect(port, host?, ...)
 */
export function extractNetworkTarget(args: unknown[]): { hostname: string; port?: number; path: string } | null {
  if (args.length === 0) return null
  
  const first = args[0]
  
  // 字符串 URL
  if (typeof first === 'string') {
    try {
      const url = new URL(first)
      return {
        hostname: url.hostname,
        port: url.port ? parseInt(url.port, 10) : undefined,
        path: url.pathname + url.search,
      }
    } catch {
      return null
    }
  }
  
  // URL 对象
  if (first instanceof URL) {
    return {
      hostname: first.hostname,
      port: first.port ? parseInt(first.port, 10) : undefined,
      path: first.pathname + first.search,
    }
  }

  // Request 实例（fetch(new Request(url, init))）——目标取自 .url。此前漏分支：实例落到下方
  // options 对象判定全 miss → classify/台账/金丝雀全部失明（网络出口盲点）。body 是流不取读
  // （保持字符串 body 才计字节的既有约定），仅目标必须回到观测面。
  if (typeof first === 'object' && first !== null && typeof (first as { url?: unknown }).url === 'string') {
    try {
      const url = new URL((first as { url: string }).url)
      return {
        hostname: url.hostname,
        port: url.port ? parseInt(url.port, 10) : undefined,
        path: url.pathname + url.search,
      }
    } catch {
      return null
    }
  }
  
  // options 对象
  if (typeof first === 'object' && first !== null) {
    const opts = first as Record<string, unknown>
    
    // net.connect({ port, host }) 形态
    if (typeof opts.port === 'number') {
      const rawHost = typeof opts.host === 'string' ? opts.host : (typeof opts.hostname === 'string' ? opts.hostname : 'localhost')
      return {
        // P2-7 修复：hostname 统一小写（防止 {host:'Webhook.Site'} 逃逸敏感主机匹配）
        hostname: rawHost.toLowerCase(),
        port: opts.port,
        path: typeof opts.path === 'string' ? opts.path : '/',
      }
    }
    
    // http.request({ hostname, port, path }) 形态
    if (typeof opts.hostname === 'string' || typeof opts.host === 'string') {
      const rawHost = (typeof opts.hostname === 'string' ? opts.hostname : opts.host) as string
      return {
        // P2-7 修复：hostname 统一小写
        hostname: rawHost.toLowerCase(),
        port: typeof opts.port === 'number' ? opts.port : (typeof opts.port === 'string' ? parseInt(opts.port, 10) : undefined),
        path: typeof opts.path === 'string' ? opts.path : '/',
      }
    }
    
    // net.connect({ path }) Unix socket 形态
    if (typeof opts.path === 'string' && opts.hostname === undefined && opts.host === undefined) {
      return {
        hostname: 'unix-socket',
        path: opts.path,
      }
    }
  }
  
  // net.connect(port, host?) 形态
  if (typeof first === 'number') {
    const rawHost = typeof args[1] === 'string' ? args[1] as string : 'localhost'
    return {
      // P2-7 修复：hostname 统一小写
      hostname: rawHost.toLowerCase(),
      port: first,
      path: '/',
    }
  }
  
  return null
}

/**
 * 网络操作分类函数。
 */
export function classifyNetworkOp(
  moduleName: string,
  opName: string,
  args: unknown[],
  _cfg: HookConfig
): HookAlarm | null {
  const target = extractNetworkTarget(args)
  if (target === null) return null
  
  // 回环地址不报警
  if (target.hostname === 'localhost' || target.hostname === '127.0.0.1' || target.hostname === '::1') return null
  
  // 白名单主机不报警
  if (EGRESS_ALLOWLIST.includes(target.hostname)) return null
  
  // Unix socket 不报警（本地通信）
  if (target.hostname === 'unix-socket') return null
  
  // 敏感端口 → red（反向 shell 特征）
  if (target.port !== undefined && SENSITIVE_PORTS.has(target.port)) {
    return {
      severity: 'red',
      kind: 'net-egress',
      message: `网络出口：${moduleName}.${opName} → ${target.hostname}:${target.port}（敏感端口）`,
      target: `${target.hostname}:${target.port}`,
    }
  }
  
  // 敏感主机 → yellow
  if (SENSITIVE_HOSTS.some(h => target.hostname === h || target.hostname.endsWith('.' + h))) {
    return {
      severity: 'yellow',
      kind: 'net-egress',
      message: `网络出口：${moduleName}.${opName} → ${target.hostname}${target.path}（敏感主机）`,
      target: target.hostname + target.path,
    }
  }
  
  return null
}
