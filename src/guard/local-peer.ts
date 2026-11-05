/**
 * 控制面对端判定（0.5.13，专家复审 Q4）：`/vet` 的写入口到底该向谁开放。
 *
 * 背景：`sameOrigin()` 比的是请求头里的 `Origin` 与 `Host`——浏览器会替用户带上这两个头，
 * 但**任何非浏览器客户端都可以自己拼**。所以同源校验证明的是「这不是一次跨站表单提交」，
 * 不是「操作者是这台机器的主人」。0.5.12 之前，面板的四个写入口（`/vet/profile`、
 * `/vet/runtime-guard`、`/vet/dismiss`、`/vet/restore`）只靠这一层，等同于：**DSH web 只要
 * 监听在可被别人访问的地址上，局域网里任何人都能改你的安全档位**。
 *
 * 为什么不直接接上游认证：vet 注册的是一条普通 HTTP 路由，拿不到 DSH web 的会话/凭据校验
 * 结果（没有稳定的「这个请求已通过宿主鉴权」接缝）。自建用户体系是越界，伪造一个「看起来
 * 已认证」的开关更糟。所以这里取的是能证明的那一半：**TCP 对端地址**——它由内核填，
 * 伪造成本远高于请求头，且不需要任何秘密。
 *
 * 判定 = 回环（127.0.0.0/8、::1）∪ 本机网卡地址。第二条是为了不误伤真实用法：从本机浏览器
 * 访问 `http://192.168.x.x:3456`（DSH 常这么监听）时，对端地址就是本机网卡地址。真正的
 * 远端请求过不了这一关。
 *
 * 明确的边界（写在这里，也写进 SECURITY.md）：
 * - 反向代理 / 容器端口映射后面，所有请求的对端都是代理（通常是回环）——这一层不提供保护，
 *   需要代理层自己做鉴权。**不读 `X-Forwarded-For`**：那是请求头，正好是这里要防的东西。
 * - 本机上的任意进程都能操作控制面。这是「同权限」假设，与自校验/审计档案的边界一致。
 * - 拿不到对端地址（不是真实 HTTP 连接）→ 按**非本机**处理（失败即拒），不给未知来源开口子。
 */
import { networkInterfaces } from 'node:os'

/** 折叠 IPv4-mapped IPv6 前缀与 zone id：`::ffff:192.168.1.5` → `192.168.1.5`，`fe80::1%en0` → `fe80::1`。 */
function normalize(addr: string): string {
  const cut = addr.indexOf('%')
  const noZone = cut < 0 ? addr : addr.slice(0, cut)
  const lower = noZone.toLowerCase()
  return lower.startsWith('::ffff:') && lower.includes('.') ? lower.slice(7) : lower
}

/** `127.0.0.0/8` 全部是回环（Linux/macOS 都如此，不是只有 127.0.0.1）。 */
function isLoopbackV4(addr: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr)
  if (m === null) return false
  const parts = m.slice(1).map(Number)
  if (parts.some((p) => p > 255)) return false
  return parts[0] === 127
}

/** 本机已配置的网卡地址（归一化后）。每次调用都问内核——频率是「人手点按钮」级别，不值得缓存。 */
export function localInterfaceAddresses(): Set<string> {
  const out = new Set<string>()
  for (const list of Object.values(networkInterfaces())) {
    for (const info of list ?? []) out.add(normalize(info.address))
  }
  return out
}

/**
 * 这个对端是不是本机。
 * @param remoteAddress `req.socket.remoteAddress`（可能带 IPv4-mapped 前缀）；`undefined` → 非本机
 * @param localAddrs 本机网卡地址集合（归一化）；默认现查，测试可注入
 */
export function isLocalPeer(remoteAddress: string | undefined, localAddrs: Set<string> = localInterfaceAddresses()): boolean {
  if (remoteAddress === undefined || remoteAddress.trim() === '') return false
  const addr = normalize(remoteAddress.trim())
  if (addr === '::1' || isLoopbackV4(addr)) return true
  return localAddrs.has(addr)
}
