/**
 * 有界文件读取（单源）：`lstat` 不跟随符号链接 + 必须是普通文件 + 大小上限 + 有界 `read`。
 *
 * 为什么需要它（round-23 审查实测）：`readFileSync` 读一个指向 FIFO 的路径会**永久阻塞**
 * 在 open(2)/read(2) 上——不是抛错、不是超时，是同步系统调用卡死。vet 有多处这样的读
 * 落在 `/vet/status.json` 的同步路径或 T2 报警热路径上，于是「在本机放一个 FIFO」就能
 * 冻住整个 DSH web 事件循环（插件完全做得到：spawn 一次 `mkfifo`，或者把自己的
 * 配置文件换成符号链接）。指向大文件/`/dev/zero` 则是无界读。
 *
 * 写侧早有对应纪律（`writeTmpExclusive` 的 'wx'，见 path-utils）：**只碰普通文件**。
 * 本模块把读侧补齐，并且是唯一实现——同一份判定散成多份就一定会漂移（F27 的教训）。
 *
 * `lstat` 而非 `stat`：跟随符号链接读取等于把「读什么」交给能改链接的一方；配置/存储
 * 文件都没有「必须经链接才可读」的正当用法，安全侧胜出。链接 → null（调用方按「读不到」
 * 退化，不抛异常）。
 */
import { closeSync, lstatSync, openSync, readSync } from 'node:fs'

/**
 * 读普通文件，最多 `maxBytes`；任何异常/非普通文件/超限 → `null`（调用方决定降级语义）。
 *
 * 不抛异常是契约的一部分：调用点遍布报警/状态路径，读取失败必须是「这条读不到」，
 * 不能变成「宿主进程这里崩了」。
 */
export function readSmallRegularFile(path: string, maxBytes: number): string | null {
  try {
    // 上限本身也要合法：非有限/负数会让 Buffer.alloc 抛 RangeError（虽然被 catch 兜住，
    // 但那会把「参数写错」伪装成「文件读不到」——宁可在这里就返回 null）。
    if (!Number.isFinite(maxBytes) || maxBytes <= 0) return null
    const st = lstatSync(path)
    if (!st.isFile() || st.size > maxBytes) return null
    const fd = openSync(path, 'r')
    try {
      // st.size 在 open 前取的：文件可能在两步之间被换成更大的——read 只读 buf.length，
      // 多出来的部分本就不该看（与「只读前 maxBytes」的语义一致）。
      const buf = Buffer.alloc(Math.min(st.size, maxBytes))
      if (buf.length === 0) return ''
      const n = readSync(fd, buf, 0, buf.length, 0)
      return buf.subarray(0, n).toString('utf8')
    } finally {
      closeSync(fd)
    }
  } catch {
    return null
  }
}

/** 配置/补丁文件上限（cordis.patch.yml：用户手写补丁，200KB 已是极端上限）。 */
export const PATCH_FILE_MAX_BYTES = 200 * 1024
/** vet 自有存储上限（忽略列表/扫描摘要：正常 1MB 以内，超限按损坏处理）。 */
export const STORE_FILE_MAX_BYTES = 8 * 1024 * 1024
