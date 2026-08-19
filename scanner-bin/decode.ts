/**
 * N2 字符串解码预处理（Anti-Obfuscation Literal Decoder）。
 * 不做通用反混淆（无底洞、易误伤），只做确定性的窄字面量解码：把 AST 里能静态求值的
 * 字符串表达式（base64/hex/charCode/常量拼接/模板串）解码成明文，喂回现有规则语料。
 * 纯静态求值、绝不执行代码；任何动态参数 → undefined，绝不猜测。
 * 硬性上限（防 DoS）：解码结果 ≤ 4KB、嵌套解码 ≤ 2 层、每文件解码数 ≤ 200。
 * @module dsh-plugin-vet/scanner-decode
 */
import ts from "typescript"
import { walk, stringyValue, numberyValue, lineOf } from "./ast.js"
import type { DecodedLiteral } from "./protocol.js"

export type DecodeMethod = DecodedLiteral["method"]
export interface DecodedNode { text: string; method: DecodeMethod }

const MAX_DECODED_BYTES = 4 * 1024
const MAX_NEST = 2
const MAX_PER_FILE = 200

function isBufferFromCall(n: ts.Expression): n is ts.CallExpression {
  if (!ts.isCallExpression(n)) return false
  const callee = n.expression
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "from") return false
  const base = callee.expression
  return (ts.isIdentifier(base) && base.text === "Buffer")
    || (ts.isPropertyAccessExpression(base) && ts.isIdentifier(base.expression) && base.expression.text === "Buffer")
}

function decodeB64(s: string): string | undefined {
  try {
    const buf = Buffer.from(s, "base64")
    if (buf.length === 0 || buf.length > MAX_DECODED_BYTES) return undefined
    // atob/Buffer base64 无法区分"恰好是合法 base64"与"碰巧"——再编码回比不足 3/4 长度比
    // 可过滤纯噪声（如 "a".repeat(20) 不是有效 b64 内容）。这里只要求解码成功且非空。
    return buf.toString("utf8")
  } catch {
    return undefined
  }
}

function decodeHex(s: string): string | undefined {
  if (s.length % 2 !== 0 || s.length === 0) return undefined
  if (!/^[0-9a-fA-F]+$/.test(s)) return undefined
  const buf = Buffer.from(s, "hex")
  if (buf.length > MAX_DECODED_BYTES) return undefined
  return buf.toString("utf8")
}

/**
 * 对单个表达式节点尝试静态解码。只处理"参数全是字面量"的调用；
 * 任何动态参数 → undefined。嵌套解码 ≤ MAX_NEST 层（内层失败即停）。
 */
export function tryDecodeLiteral(node: ts.Expression, sf: ts.SourceFile, depth = 0): DecodedNode | undefined {
  if (depth > MAX_NEST) return undefined
  // 常量拼接/模板串（无替换或替换全为静态）——stringyValue 已支持，标注为拼接形态
  const sv = stringyValue(node, sf)
  if (sv !== undefined) {
    if (!sv.exact && sv.text.length <= MAX_DECODED_BYTES) return { text: sv.text, method: "template" }
  }
  if (!ts.isCallExpression(node)) return undefined
  const callee = node.expression

  // String.fromCharCode(104,116,116,112,...)
  if (ts.isPropertyAccessExpression(callee) && callee.name.text === "fromCharCode"
    && ts.isIdentifier(callee.expression) && callee.expression.text === "String") {
    const codes: number[] = []
    for (const arg of node.arguments) {
      const v = numberyValue(arg, sf)
      if (v === undefined || !Number.isInteger(v) || v < 0 || v > 0x10ffff) return undefined
      codes.push(v)
    }
    if (codes.length === 0) return undefined
    const text = String.fromCodePoint(...codes)
    if (text.length > MAX_DECODED_BYTES) return undefined
    return { text, method: "charCode" }
  }

  // atob(str) —— 参数可以是字面量，也可以是嵌套的 atob/解码调用（atob(atob(x))，≤2 层）
  if (ts.isIdentifier(callee) && callee.text === "atob" && node.arguments.length >= 1) {
    const arg = node.arguments[0]
    let inner: string | undefined = literalString(arg, sf)
    if (inner === undefined) {
      // 参数是表达式：递归解码（内层失败即 undefined）
      const nested = tryDecodeLiteral(arg, sf, depth + 1)
      inner = nested !== undefined && /^[A-Za-z0-9+/=]+$/.test(nested.text.trim()) ? nested.text.trim() : undefined
    }
    if (inner === undefined || inner.length > MAX_DECODED_BYTES) return undefined
    const text = decodeB64(inner)
    if (text === undefined) return undefined
    // 每层 atob 恰好解码一层：atob(atob(x)) 的外层参数是内层 atob 调用，递归求值出中间层
    // base64 后再解——不做"解码结果仍像 base64 就再解一层"的自动展开（避免过度解码/误判）。
    return { text, method: "base64" }
  }

  // Buffer.from(str, "hex"|"base64"|"base64url")
  if (isBufferFromCall(node) && node.arguments.length >= 1) {
    const arg = node.arguments[0]
    const inner = literalString(arg, sf)
    const enc = node.arguments[1] !== undefined && ts.isStringLiteral(node.arguments[1]) ? node.arguments[1].text : ""
    if (inner === undefined || inner.length > MAX_DECODED_BYTES) return undefined
    if (enc === "hex" || enc === "base64" || enc === "base64url") {
      const text = enc === "hex" ? decodeHex(inner) : decodeB64(inner)
      if (text !== undefined) return { text, method: enc === "hex" ? "hex" : "base64" }
    }
    if (enc === "" || enc === "utf8" || enc === "latin1" || enc === "ascii") {
      return { text: inner, method: "concat" }
    }
    return undefined
  }
  return undefined
}

/** 参数自身的字面量文本（含模板？不——模板是求值对象，只在 tryDecodeLiteral 顶层处理）。 */
function literalString(arg: ts.Expression, sf: ts.SourceFile): string | undefined {
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return arg.text
  if (ts.isTemplateExpression(arg)) {
    const sv = stringyValue(arg, sf)
    return sv?.text
  }
  return undefined
}

/**
 * 全文件解码采集：对文件中每个"可解码调用/静态串"求一次值，产出去重字面量列表。
 * 上限：每文件 200 条、每串 4KB——防 DoS（大文件由 engine 的预检先行拦截）。
 */
export function collectDecodedLiterals(sf: ts.SourceFile, file?: string): DecodedLiteral[] {
  const out: DecodedLiteral[] = []
  const seen = new Set<string>()
  walk(sf, n => {
    if (out.length >= MAX_PER_FILE) return
    if (!ts.isCallExpression(n) && !ts.isBinaryExpression(n) && !ts.isTemplateExpression(n)) return
    const node = n as ts.Expression
    const dec = tryDecodeLiteral(node, sf)
    if (dec === undefined) return
    if (dec.text.length === 0 || dec.text.length > MAX_DECODED_BYTES) return
    const key = dec.method + ":" + dec.text
    if (seen.has(key) || out.some(d => d.text === dec.text && d.method === dec.method)) return
    seen.add(key)
    out.push({ text: dec.text, method: dec.method, line: lineOf(sf, node), ...(file !== undefined ? { file } : {}) })
  })
  return out
}