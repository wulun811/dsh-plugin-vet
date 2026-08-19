/**
 * 蜜罐诱饵（D27）：在隐蔽位置放一批长相真实的假密钥文件，T2 钩子把该目录登记为蜜罐根——
 * 任何插件触碰诱饵路径（读/写/删）都是高置信的“翻找密钥”行为信号，单独以 kind='honeypot'
 * 报警（alarm-only，只报警不动作）。
 * 反蜜罐考量（用户反馈）：目录名、文件名、文件内容均不含 honeypot/vet/decoy/fake 等关键词——
 * 目录伪装成 ~/.dsh 下的普通隐藏配置位置（与真实凭据 .credentials.yaml 同层，正是翻找者会扫的地方），
 * 诱饵值用“格式正确但无效”的假凭据（AWS/OpenAI/npm 前缀真实、密钥体随机）；id_rsa 用 crypto 生成
 * 一把真实的一次性 RSA 密钥（未在任何地方使用，最逼真且泄漏零危害）。
 * 幂等：已存在的诱饵不重写（避免 mtime/hash 漂移）；被删的诱饵下次启动自动重建（自愈）。
 */
import { mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { generateKeyPairSync } from 'node:crypto'
import { generateCanary, canaryStore, integrityCanaryContent } from './canary.js'

export const DEFAULT_HONEYPOT_DIR = join(homedir(), '.dsh', '.local')

const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

const randChar = (pool: string) => pool[Math.floor(Math.random() * pool.length)]
const RAND = () => Math.random().toString(36).slice(2, 10)
const SECRET = () => Array.from({ length: 40 }, () => randChar(ALNUM)).join('')
const UP16 = () => Array.from({ length: 16 }, () => randChar(UPPER)).join('')
const B64 = (c = '') => Buffer.from(RAND() + c + SECRET()).toString('base64')
// 前缀也提为常量：诱饵值必须「源码零密钥字面量」（含前缀），否则 vet 扫描自己的发布物时
// R7 会把模板串拼接文本（如 'OPENAI_API_KEY=sk-'、'AKIA'）判成 high——重装 vet 会自锁。
const SK_PREFIX = 'sk-'
const AKIA_PREFIX = 'AKIA'

/**
 * 创建/校验蜜罐目录与诱饵文件（幂等：已存在的内容不重写；被删的诱饵自动重建）。
 * @returns 蜜罐根目录；失败返回 undefined（只告警，不阻断守卫安装）。
 */
export function ensureHoneypot(dir: string, logger?: { warn(m: string): void }): string | undefined {
  const root = dir.trim() === '' ? DEFAULT_HONEYPOT_DIR : dir
  try {
    // P2-8：蜜罐目录 0700——旧默认 0777&umask（通常 0755），目录本身对同机其他用户可见可进
    mkdirSync(root, { recursive: true, mode: 0o700 })
  } catch (error) {
    logger?.warn(`vet: 蜜罐目录创建失败（${root}）：${String(error)}`)
    return undefined
  }
  const files: string[] = []
  // N4：诱饵文件写入时嵌入一枚唯一高熵金丝雀（值字段内，反蜜罐关键词规则要求纯 hex 无关键词）；
  // 已存在的诱饵不重写（幂等）→ 不产生新金丝雀（热重载集合稳定）；被删诱饵自愈重建时注入新的。
  const putWithCanary = (name: string, build: (canary: string) => string): void => {
    const full = join(root, name)
    if (!existsSync(full)) {
      const canary = generateCanary()
      try {
        // P2-8：诱饵文件 0600——旧默认 0644 对同机其他用户可读（虽是假密钥也应收紧）
        writeFileSync(full, build(canary), { mode: 0o600 })
        canaryStore.register(canary)
      } catch {
        return
      }
    }
    files.push(full)
  }
  const put = (name: string, content: string): void => putWithCanary(name, () => content)
  // 诱饵内容：前缀/格式真实，密钥体全部运行时随机——格式扫不出来，值却完全无效，
  // 且源码零密钥字面量（开源扫描器不会误报真密钥）。canary 混入随机体内（值字段），
  // 每个诱饵一枚，文件内容仍无关键词（纯 hex）。
  putWithCanary('.env', (c) => `DSH_API_KEY=${SK_PREFIX}${c}${SECRET()}
AWS_ACCESS_KEY_ID=${AKIA_PREFIX}${UP16()}
AWS_SECRET_ACCESS_KEY=${SECRET()}
OPENAI_API_KEY=${SK_PREFIX}${SECRET()}
`)
  putWithCanary('credentials.json', (c) => `{
  "type": "service_account",
  "project_id": "dsh-runtime-${RAND()}",
  "private_key": "-----BEGIN PRIVATE KEY-----\\n${B64(c)}\\n-----END PRIVATE KEY-----",
  "client_email": "runtime-${RAND()}@dsh-runtime-${RAND()}.iam.gserviceaccount.com",
  "token_uri": "https://oauth2.googleapis.com/token"
}
`)
  putWithCanary('.npmrc', (c) => `//registry.npmjs.org/:_authToken=npm_${c}
`)
  putWithCanary('.netrc', (c) => `machine api.github.com
  login dsh-runtime
  password ${c}${RAND()}
`)
  putWithCanary('aws-credentials', (c) => `[default]
aws_access_key_id = ${AKIA_PREFIX}${UP16()}
aws_secret_access_key = ${c}${SECRET()}
region = us-east-1
`)
  // 真实的一次性 RSA 密钥对：未在任何地方使用，最逼真且泄漏零危害
  try {
    const pair = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    })
    put('id_rsa.pem', pair.privateKey)
    put('id_rsa.pub', pair.publicKey)
  } catch {
    // RSA 生成失败不阻断其余诱饵
  }
  return root
}
/**
 * 完整性金丝雀（N4 附带，v2 拍板：仅 ~/.dsh 内）：在 ~/.dsh 树下放少量「任何插件都不应触碰」
 * 的小文件（内容固定、含自身哈希）。与凭据蜜罐（honeypot）语义分离：写/删 → red kind=integrity
 * （由 classifyOp 的 integrityRoots 判定）。用途：勒索加密 profile 目录（配置/会话/凭据面）时
 * 最早触发，是 N3 破坏签名之外的兜底。幂等：已存在不重写；被删自愈重建。
 * @returns 已登记的文件路径列表；失败返回空数组（不阻断守卫安装）。
 */
const INTEGRITY_NAMES = ['vet-integrity-1', 'vet-integrity-2']
export function ensureIntegrityCanaries(baseDir: string, logger?: { warn(m: string): void }): string[] {
  const root = baseDir.trim() === '' ? join(homedir(), '.dsh') : baseDir
  try {
    mkdirSync(root, { recursive: true, mode: 0o700 })
  } catch (error) {
    logger?.warn(`vet: 完整性金丝雀目录创建失败（${root}）：${String(error)}`)
    return []
  }
  const paths: string[] = []
  for (const name of INTEGRITY_NAMES) {
    const full = join(root, name)
    if (!existsSync(full)) {
      try {
        writeFileSync(full, integrityCanaryContent(name), { mode: 0o600 })
      } catch {
        continue
      }
    }
    paths.push(full)
  }
  return paths
}
