/**
 * N1 静态能力清单提取（声明侧事实，非判定）。
 * 纯 AST 只读遍历：把"代码引用了什么"结构化输出（hosts/fsPaths/spawnCmds/imports/hasNetwork/hasExec）。
 * 提取策略：宁可多列（宽松），避免把"观测到但清单漏了"误判为隐藏能力——差分侧只有
 * "静态完全无足迹（含 imports）且运行时触发敏感操作"才算隐藏能力。
 * @module dsh-plugin-vet/scanner-capability
 */
import ts from "typescript"
import { walk, stringyValue } from "./ast.js"
import type { CapabilityManifest } from "./protocol.js"

/** 网络主机提取：字符串字面量里形如 scheme://host 的目标（host 含端口、去路径）。 */
const URL_HOST_RE = /(?:https?|wss?):\/\/([^/\s'")\]]+)/gi
/** 捕获 host 的收尾清理：剥掉遗留引号/括号/反引号。 */
const TRIM_TAIL_RE = /['"`)\].,;:]+$/

/** 0.1.21 降噪：host 形状校验——拒绝模板拼接残片（如 "["）、纯路径段等非主机名 token。
 * 单标签仅放行 localhost；其余要求含点（域名/IPv4）或为方括号 IPv6。 */
const HOST_SHAPE_RE = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/
const IPV6_SHAPE_RE = /^\[[a-f0-9:]+\](?::\d{1,5})?$/
function looksLikeHost(host: string): boolean {
  const bare = host.replace(/:\d{1,5}$/, "")
  if (bare === "localhost" || bare === "[::1]") return true
  return (HOST_SHAPE_RE.test(host) && host.includes(".")) || IPV6_SHAPE_RE.test(host)
}

/** 经典 realm 探测 shim：Function("return this") / new Function("return this")——无动态执行语义。 */
function isRealmShimArgs(args: readonly ts.Expression[]): boolean {
  if (args.length !== 1) return false
  const t = literalText(args[0])
  return t !== undefined && /^\s*return\s+this\s*$/.test(t)
}

/** 0.1.21 降噪：相对模块引用（./api.ts、../rpc.js）不是文件系统能力足迹。 */
const REL_MODULE_REF_RE = /^\.{1,2}\/.*\.(?:js|mjs|cjs|ts|tsx|jsx|json)$/i

/** 敏感段名（与 T2 sensitiveSegments 对齐的保守子集 + R11 路径正则里有的段）。 */
const SENSITIVE_SEGMENTS = [
  ".ssh", ".aws", ".dsh", ".gnupg", ".npmrc", ".env", ".netrc", ".pgpass",
  "credentials", "credential", "secrets", "secret", "tokens", "token",
  "passwd", "shadow", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
  ".git-credentials", ".kube", "vault", "crontab",
]
const SENSITIVE_RE = new RegExp("(" + SENSITIVE_SEGMENTS.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")", "i")

/** child_process 操作名（spawn 面）。 */
const PROC_OPS = new Set(["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"])
/** fs 操作名（路径实参提取用）。 */
const FS_OPS = new Set([
  "readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync",
  "appendFile", "appendFileSync", "createWriteStream", "unlink", "unlinkSync",
  "rm", "rmSync", "rmdir", "rmdirSync", "rename", "renameSync", "copyFile",
  "copyFileSync", "cp", "cpSync", "truncate", "truncateSync", "open", "openSync",
  "readdir", "readdirSync", "stat", "statSync", "access", "accessSync", "realpath", "realpathSync",
])
/** shell/下载命令词（runtime-hooks shellTokens 同款，整词命中）。 */
const COMMAND_TOKENS = new Set(["sh", "bash", "zsh", "cmd", "powershell", "pwsh", "curl", "wget", "nc", "ncat", "telnet"])
/** 网络能力模块。 */
const NETWORK_MODULES = new Set(["http", "https", "http2", "net", "tls", "dgram", "undici"])
/** C2（0.1.16 加固）：ESM 具名导入走 Node 互操作快照——T2 对这类绑定不生效（运行时守卫盲区）。
 * 需要告警提示的敏感内建模块（具名/命名空间导入都算：import { request } / import * as fs）。 */
const ESM_T2_BLIND_BUILTINS = new Set(["fs", "fs/promises", "child_process", "http", "https", "http2", "net", "tls", "dgram", "worker_threads", "vm"])
/** 动态执行模块。 */
const EXEC_MODULES = new Set(["child_process"])
/** spawn/exec 等动态执行函数标识符。 */
const EXEC_IDENTS = new Set(["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"])

const HOST_CAP = 50
const FS_CAP = 50
const CMD_CAP = 20
const IMPORT_CAP = 50

const PUSH_UNIQ = (arr: string[], item: string, cap: number): void => {
  const v = item.trim()
  if (v === "" || v.length > 512) return
  if (!arr.includes(v) && arr.length < cap) arr.push(v)
}

function literalText(n: ts.Node): string | undefined {
  if (ts.isStringLiteral(n)) return n.text
  if (ts.isNoSubstitutionTemplateLiteral(n)) return n.text
  if (ts.isTemplateExpression(n)) {
    const sv = stringyValue(n, n.getSourceFile())
    if (sv !== undefined) return sv.text
    return n.head.text + n.templateSpans.map(s => s.literal.text).join("")
  }
  return undefined
}

/** 形似路径的字面量：以 / ~/ ./ ../ 开头，或含敏感段。 */
function looksLikePath(text: string): boolean {
  return /^(?:\/|~\/|\.\/|\.\.\/)/.test(text) || SENSITIVE_RE.test(text)
}

/** 模块导入/require 的包名（跳过相对路径与 node: 内建）。 */
function packageName(moduleSpec: string): string | undefined {
  const m = moduleSpec.trim()
  if (m === "") return undefined
  if (m.startsWith("./") || m.startsWith("../") || m.startsWith("/")) return undefined
  if (m.startsWith("node:")) return undefined
  return m.split("/").slice(0, 2).join("/")
}

function isFsModule(spec: string): boolean {
  const s = spec.replace(/^node:/, "")
  return s === "fs" || s === "fs/promises"
}
function isCpModule(spec: string): boolean {
  return spec.replace(/^node:/, "") === "child_process"
}

/**
 * 预扫描模块绑定：把 import/require 绑定到 fs / child_process 的标识符收集起来
 * （含解构绑定），使 fs.readFileSync / require("fs").readFileSync / 解构后的 readFileSync(path)
 * 三种形态都能提取路径/命令实参。宽松：宁可多列。
 */
function moduleBindings(sf: ts.SourceFile): { fsRefs: Set<string>; cpRefs: Set<string> } {
  const fsRefs = new Set<string>()
  const cpRefs = new Set<string>()
  const bind = (name: string, isFs: boolean): void => {
    if (name === "" || name === "require") return
    if (isFs) fsRefs.add(name)
    else cpRefs.add(name)
  }
  walk(sf, n => {
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const spec = n.moduleSpecifier.text
      const isFs = isFsModule(spec)
      const isCp = isCpModule(spec)
      if (!isFs && !isCp) return
      const clause = n.importClause
      if (clause === undefined) return
      if (clause.name !== undefined) bind(clause.name.text, isFs)
      if (clause.namedBindings !== undefined) {
        if (ts.isNamespaceImport(clause.namedBindings)) bind(clause.namedBindings.name.text, isFs)
        else if (ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) bind(el.name.text, isFs)
        }
      }
    }
    if (ts.isVariableDeclaration(n) && n.initializer !== undefined && ts.isCallExpression(n.initializer)) {
      const callee = n.initializer.expression
      if (!(ts.isIdentifier(callee) && callee.text === "require")) return
      const spec = literalText(n.initializer.arguments[0])
      if (spec === undefined) return
      const isFs = isFsModule(spec)
      const isCp = isCpModule(spec)
      if (!isFs && !isCp) return
      const nm = n.name
      if (ts.isIdentifier(nm)) {
        bind(nm.text, isFs)
      } else if (ts.isObjectBindingPattern(nm)) {
        for (const el of nm.elements) {
          if (ts.isIdentifier(el.name)) bind(el.name.text, isFs)
        }
      }
    }
  })
  return { fsRefs, cpRefs }
}

/** 单文件能力提取（宽松、确定性）。 */
export function extractCapabilities(sf: ts.SourceFile): CapabilityManifest {
  const out: CapabilityManifest = { hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, esmNamedBuiltins: false }
  const { fsRefs, cpRefs } = moduleBindings(sf)
  const isFsBase = (base: ts.Expression): boolean => {
    if (ts.isIdentifier(base)) return base.text === "fs" || fsRefs.has(base.text)
    if (ts.isCallExpression(base)) {
      const callee = base.expression
      if (ts.isIdentifier(callee) && callee.text === "require" && base.arguments.length > 0) {
        const spec = literalText(base.arguments[0])
        return spec !== undefined && isFsModule(spec)
      }
    }
    return false
  }
  const isCpBase = (base: ts.Expression): boolean => {
    if (ts.isIdentifier(base)) return base.text === "child_process" || cpRefs.has(base.text)
    if (ts.isCallExpression(base)) {
      const callee = base.expression
      if (ts.isIdentifier(callee) && callee.text === "require" && base.arguments.length > 0) {
        const spec = literalText(base.arguments[0])
        return spec !== undefined && isCpModule(spec)
      }
    }
    return false
  }
  walk(sf, n => {
    const text = literalText(n)
    if (text !== undefined) {
      const re = new RegExp(URL_HOST_RE.source, "gi")
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        let host = m[1].toLowerCase().replace(TRIM_TAIL_RE, "")
        const cut = host.search(/[/?#]/)
        if (cut !== -1) host = host.slice(0, cut)
        if (!looksLikeHost(host)) continue
        PUSH_UNIQ(out.hosts, host, HOST_CAP)
      }
      for (const w of commandWords(text)) {
        PUSH_UNIQ(out.spawnCmds, w, CMD_CAP)
      }
      // 0.1.21 降噪：裸字面量的 fsPath 提取收紧为「路径前缀开头且无空白且非相对模块引用」，
      // 并跳过模板拼接片段——注释样文本（// ...）、报错文案、import 规格符不再入清单。
      // fs 调用实参位仍走结构化提取（isFsBase 分支），保留完整 looksLikePath 语义（含敏感段）。
      if (!ts.isTemplateExpression(n) && !/\s/.test(text)
        && /^(?:\/|~\/|\.\/|\.\.\/)/.test(text) && !REL_MODULE_REF_RE.test(text)) {
        PUSH_UNIQ(out.fsPaths, text, FS_CAP)
      }
    }
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const spec = n.moduleSpecifier.text
      const pkg = packageName(spec)
      if (pkg !== undefined) PUSH_UNIQ(out.imports, pkg, IMPORT_CAP)
      // C2：内建危险模块的具名/命名空间导入 → T2 盲区标记（import fs from 'fs' 默认导入仍可被钩子覆盖，不算）
      const bare = spec.replace(/^node:/, '')
      if (ESM_T2_BLIND_BUILTINS.has(bare) && n.importClause !== undefined
        && (n.importClause.namedBindings !== undefined || n.importClause.name !== undefined)) {
        // 仅具名/命名空间绑定触发（默认导入 name 单独不算——它引用的是可 patch 的对象本身）
        if (n.importClause.namedBindings !== undefined) out.esmNamedBuiltins = true
      }
    }
    if (ts.isCallExpression(n)) {
      const callee = n.expression
      if (ts.isIdentifier(callee) && callee.text === "require" && n.arguments.length > 0) {
        const spec = literalText(n.arguments[0])
        if (spec !== undefined) {
          const pkg = packageName(spec)
          if (pkg !== undefined) PUSH_UNIQ(out.imports, pkg, IMPORT_CAP)
          if (NETWORK_MODULES.has(spec)) out.hasNetwork = true
          if (EXEC_MODULES.has(spec)) out.hasExec = true
          if (looksLikePath(spec)) PUSH_UNIQ(out.fsPaths, spec, FS_CAP)
        }
      }
      if (ts.isIdentifier(callee)) {
        if (callee.text === "fetch" || callee.text === "WebSocket") out.hasNetwork = true
        if (callee.text === "eval") out.hasExec = true
        if (callee.text === "Function" && !isRealmShimArgs(n.arguments)) out.hasExec = true
        // 0.1.21 降噪：裸 spawn/exec/fork 标识符仅在文件确实引用 child_process 时计为执行能力
        // （bundle 内自带同名辅助函数不再误报“执行”、进而误触 upgrade-cold 双高提示）
        if (EXEC_IDENTS.has(callee.text) && cpRefs.size > 0) out.hasExec = true
        if (fsRefs.has(callee.text) && FS_OPS.has(callee.text)) {
          const arg = n.arguments[0]
          if (arg !== undefined) {
            const sv = stringyValue(arg, sf)
            if (sv !== undefined) PUSH_UNIQ(out.fsPaths, sv.text, FS_CAP)
          }
        }
        if (cpRefs.has(callee.text) && PROC_OPS.has(callee.text)) {
          const arg = n.arguments[0]
          if (arg !== undefined) {
            const sv = stringyValue(arg, sf)
            if (sv !== undefined) PUSH_UNIQ(out.spawnCmds, sv.text, CMD_CAP)
          }
        }
      }
      if (ts.isPropertyAccessExpression(callee)) {
        const base = callee.expression
        if (ts.isIdentifier(base) && NETWORK_MODULES.has(base.text)) out.hasNetwork = true
        if (callee.name.text === "fetch" && ts.isIdentifier(base) && base.text === "globalThis") out.hasNetwork = true
        if (isCpBase(base) && PROC_OPS.has(callee.name.text)) out.hasExec = true
      }
      if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
        const base = callee.expression
        const op = callee.name.text
        const arg = n.arguments[0]
        if (arg !== undefined) {
          const sv = stringyValue(arg, sf)
          const argText = sv !== undefined ? sv.text : literalText(arg)
          if (isFsBase(base) && FS_OPS.has(op) && argText !== undefined) {
            PUSH_UNIQ(out.fsPaths, argText, FS_CAP)
          }
          if (isCpBase(base) && PROC_OPS.has(op) && argText !== undefined) {
            PUSH_UNIQ(out.spawnCmds, argText, CMD_CAP)
          }
        }
      }
    }
    if (ts.isNewExpression(n)) {
      const expr = n.expression
      if (ts.isIdentifier(expr)) {
        if (expr.text === "Function" && !(n.arguments !== undefined && isRealmShimArgs(n.arguments))) out.hasExec = true
        if (expr.text === "WebSocket") out.hasNetwork = true
      }
    }
  })
  return out
}

function commandWords(text: string): string[] {
  const out: string[] = []
  const words = text.split(/[^A-Za-z0-9._/-]+/).filter(Boolean)
  for (const w of words) {
    const base = w.slice(w.lastIndexOf("/") + 1)
    if (COMMAND_TOKENS.has(base)) out.push(base)
  }
  return out
}

/** 空清单：没有任何声明足迹（差分侧的"全无足迹"判定基准）。 */
export function isEmptyManifest(m: CapabilityManifest): boolean {
  return m.hosts.length === 0 && m.fsPaths.length === 0 && m.spawnCmds.length === 0
    && m.imports.length === 0 && !m.hasNetwork && !m.hasExec
}

/** 多文件聚合：并集 + OR 旗标（数组去重、按上限截断防膨胀）。
 * 0.1.16：esmNamedBuiltins 任一文件命中即 true（C2）。 */
export function aggregateCapabilities(parts: CapabilityManifest[]): CapabilityManifest {
  const out: CapabilityManifest = { hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, esmNamedBuiltins: false }
  for (const p of parts) {
    for (const h of p.hosts) PUSH_UNIQ(out.hosts, h, HOST_CAP)
    for (const f of p.fsPaths) PUSH_UNIQ(out.fsPaths, f, FS_CAP)
    for (const c of p.spawnCmds) PUSH_UNIQ(out.spawnCmds, c, CMD_CAP)
    for (const i of p.imports) PUSH_UNIQ(out.imports, i, IMPORT_CAP)
    if (p.hasNetwork) out.hasNetwork = true
    if (p.hasExec) out.hasExec = true
    if (p.esmNamedBuiltins === true) out.esmNamedBuiltins = true
  }
  return out
}