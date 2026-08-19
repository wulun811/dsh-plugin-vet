/**
 * P-5 官方包内容哈希基线（v5 方案）：信任内容而非名字。
 * 对 @deepseek-ai/* 在"命名豁免"之外增加"内容哈希校验"层，
 * 防止恶意 tarball 伪造包名骗过豁免。
 */
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync, lstatSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'

/** M7（0.1.16 加固）：基线自写 hash 记录 + 篡改标志（进程内插件改写 baseline.json 的检测）。 */
const writtenBaselineHashes = new Map<string, string>()
let baselineTampered = false
import { homedir } from 'node:os'
import { join, dirname, relative } from 'node:path'
import { withVetSelfIo } from '../guard/runtime-hooks.js'

/** 基线记录。 */
export interface BaselineRecord {
  name: string
  version: string
  hash: string
  recordedAt: number
}

/** 基线存储：key = `${packageName}@${version}`，支持多版本共存。 */
export interface BaselineStore {
  records: Record<string, BaselineRecord>
}

/** 哈希计算选项（v5 修订：防 DoS）。 */
export interface HashOptions {
  maxFiles?: number       // 默认 1000
  maxSizeBytes?: number   // 默认 50MB
  timeoutMs?: number      // 默认 10000
}

const DEFAULT_HASH_OPTIONS: Required<HashOptions> = {
  maxFiles: 1000,
  maxSizeBytes: 50 * 1024 * 1024,
  timeoutMs: 10_000,
}

/** 排除的文件模式（文档文件）。 */
const EXCLUDE_PATTERNS = [
  /\.md$/i,
  /\.txt$/i,
  /LICENSE/i,
  /README/i,
  /^\./,  // 隐藏文件
]

/** C3（0.1.16 加固）：模块加载时快照 env（vet 先于第三方插件加载，进程内改 env 无法重定向基线存储）。 */
const SNAPSHOT_BASELINE_DIR: string | undefined = (() => {
  const v = process.env.DSH_PLUGIN_VET_BASELINE_DIR
  return v !== undefined && v !== '' ? v : undefined
})()

let baselineDirOverride: string | undefined

/** 基线文件路径：~/.dsh/vet/baseline.json（快照 env；测试用 setBaselineDirForTest 覆盖）。 */
export function baselinePath(): string {
  const dir = baselineDirOverride ?? SNAPSHOT_BASELINE_DIR ?? join(homedir(), '.dsh', 'vet')
  return join(dir, 'baseline.json')
}

/** 测试专用：覆盖快照目录（生产路径不调用）。 */
export function setBaselineDirForTest(dir?: string): void {
  baselineDirOverride = dir
}

/**
 * 计算包内容哈希（v5 修订：不跟随符号链接，排除隐藏文件）。
 * @returns 哈希结果，超限/超时时返回 null。
 */
export function computePackageHash(
  packageRoot: string,
  options: HashOptions = {}
): { hash: string } | null {
  const opts = { ...DEFAULT_HASH_OPTIONS, ...options }
  const startTime = Date.now()
  
  return withVetSelfIo(() => {
    try {
      const files: { path: string; content: Buffer }[] = []
      let totalSize = 0
      
      const walk = (dir: string): boolean => {
        // 超时检查
        if (Date.now() - startTime > opts.timeoutMs) return false
        // 文件数检查
        if (files.length >= opts.maxFiles) return false
        
        let entries: string[]
        try {
          entries = readdirSync(dir)
        } catch {
          return true  // 跳过不可读目录
        }
        
        for (const name of entries) {
          // 超时/文件数检查
          if (Date.now() - startTime > opts.timeoutMs) return false
          if (files.length >= opts.maxFiles) return false
          
          // 排除隐藏文件/目录
          if (name.startsWith('.')) continue
          // 排除 node_modules
          if (name === 'node_modules') continue
          
          const fullPath = join(dir, name)
          let stat
          try {
            // v5 修订：使用 lstatSync 不跟随符号链接
            stat = lstatSync(fullPath)
          } catch {
            continue
          }
          
          // 跳过符号链接
          if (stat.isSymbolicLink()) continue
          
          if (stat.isDirectory()) {
            if (!walk(fullPath)) return false
          } else if (stat.isFile()) {
            // 排除文档文件
            if (EXCLUDE_PATTERNS.some(re => re.test(name))) continue
            
            // P1-4 修复：单文件大小预检（避免 readFileSync 加载超大文件后再拒绝）
            if (stat.size > opts.maxSizeBytes) return false
            
            // 使用 Buffer 读取（支持二进制文件）
            const contentBuffer = readFileSync(fullPath)
            totalSize += contentBuffer.length
            // 累计大小检查
            if (totalSize > opts.maxSizeBytes) return false
            
            // 使用相对路径（跨机器一致性）
            const relPath = relative(packageRoot, fullPath)
            // P2-8 修复：直接存 Buffer，hash.update(Buffer) 哈希原始字节
            // （此前 toString('binary') → hash.update(string) 对 bytes 128-255 产生 utf8 扩展，
            // 哈希结果与 sha256sum 不一致）
            files.push({ path: relPath, content: contentBuffer })
          }
        }
        return true
      }
      
      if (!walk(packageRoot)) return null
      
      // 按路径排序，确保跨平台一致（使用字节序而非 locale）
      files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
      
      // 计算哈希
      const hash = createHash('sha256')
      for (const f of files) {
        hash.update(f.path)
        hash.update('\0')
        hash.update(f.content)
        hash.update('\0')
      }
      
      return { hash: hash.digest('hex') }
    } catch {
      return null
    }
  })
}

/**
 * 比对基线。
 * @returns 'match' | 'mismatch' | 'first-seen'
 */
export function checkBaseline(
  name: string,
  version: string,
  hash: string,
  store: BaselineStore
): 'match' | 'mismatch' | 'first-seen' {
  const key = `${name}@${version}`
  const record = store.records[key]
  if (record === undefined) return 'first-seen'
  return record.hash === hash ? 'match' : 'mismatch'
}

/** 记录基线。 */
export function recordBaseline(
  name: string,
  version: string,
  hash: string,
  store: BaselineStore
): void {
  const key = `${name}@${version}`
  store.records[key] = { name, version, hash, recordedAt: Date.now() }
}

/**
 * 加载基线文件（v5 修订：JSON 解析失败时返回空 store）。
 */
export function loadBaseline(): BaselineStore {
  return withVetSelfIo(() => {
    try {
      const path = baselinePath()
      const content = readFileSync(path, 'utf8')
      const recorded = writtenBaselineHashes.get(path)
      if (recorded !== undefined && hashOf(content) !== recorded) baselineTampered = true
      const parsed = JSON.parse(content) as { records?: Record<string, BaselineRecord> }
      if (parsed.records !== undefined && typeof parsed.records === 'object') {
        return { records: parsed.records }
      }
      return { records: {} }
    } catch {
      if (writtenBaselineHashes.has(baselinePath())) baselineTampered = true
      // 文件不存在或损坏：返回空 store，所有包视为首次见到
      return { records: {} }
    }
  })
}

/** 读取并复位篡改标志（internal/plugin 完成时上报 yellow）。 */
export function consumeBaselineTamper(): boolean {
  const t = baselineTampered
  baselineTampered = false
  return t
}

function hashOf(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

/**
 * 保存基线文件（原子写：临时文件 + rename）。
 */
export function saveBaseline(store: BaselineStore): void {
  withVetSelfIo(() => {
    try {
      const path = baselinePath()
      const dir = dirname(path)
      
      // 确保目录存在
      try {
        mkdirSync(dir, { recursive: true, mode: 0o700 })
      } catch {
        // 目录已存在
      }
      
      // 原子写：临时文件 + rename
      const tmpPath = path + '.tmp.' + process.pid
      const serialized = JSON.stringify(store, null, 2)
      writeFileSync(tmpPath, serialized, { mode: 0o600 })
      renameSync(tmpPath, path)
      writtenBaselineHashes.set(path, hashOf(serialized))
    } catch {
      // 保存失败：静默忽略（下次启动会重新计算）
    }
  })
}

// 模块级缓存（避免每次加载官方包都读文件）
let baselineCache: BaselineStore | undefined

/** 获取基线缓存。 */
export function getBaseline(): BaselineStore {
  if (baselineCache === undefined) baselineCache = loadBaseline()
  return baselineCache
}

/** 刷新基线缓存。 */
export function refreshBaseline(): void {
  baselineCache = loadBaseline()
}
