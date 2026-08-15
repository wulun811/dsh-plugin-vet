/**
 * Read-only TypeScript-compiler helpers: parse, walk, stringy static evaluation,
 * and a pragmatic lexical shadowing check. Never transpiles or type-checks.
 * @module dsh-plugin-vet/scanner-ast
 */
import ts from 'typescript'
import type { Language } from './protocol.js'

export interface StringyValue {
  text: string
  /** false when the string was assembled by concat/template (static but not literal). */
  exact: boolean
}

/** Parse one source string into a SourceFile with parent pointers (read-only). */
export function parseSource(code: string, filename: string, language: Language): ts.SourceFile {
  const scriptKind = language === 'ts' ? ts.ScriptKind.TS : ts.ScriptKind.JS
  return ts.createSourceFile(filename, code, ts.ScriptTarget.Latest, /*setParentNodes*/ true, scriptKind)
}

/** Depth-first traversal; `visit` runs on every node including the root. */
export function walk(node: ts.Node, visit: (n: ts.Node) => void): void {
  visit(node)
  ts.forEachChild(node, child => walk(child, visit))
}

// ---------------------------------------------------------------------------
// Stringy static evaluation (for R1/R2 escape-argument checks)
// ---------------------------------------------------------------------------

const constInitializers = new WeakMap<ts.SourceFile, Map<string, ts.Expression>>()

function initializerMap(sf: ts.SourceFile): Map<string, ts.Expression> {
  let map = constInitializers.get(sf)
  if (map !== undefined) return map
  map = new Map()
  walk(sf, n => {
    if (!ts.isVariableDeclaration(n)) return
    if (n.initializer === undefined) return
    const name = n.name
    if (!ts.isIdentifier(name) || name.text === '') return
    if (!map.has(name.text)) map.set(name.text, n.initializer)
  })
  constInitializers.set(sf, map)
  return map
}

/**
 * Statically evaluate a string-ish expression: string literal, template
 * without substitutions, binary `+` of stringy parts, or an identifier bound
 * to a const/let string initializer (first declaration wins; v1 heuristic).
 */
export function stringyValue(node: ts.Node, sf: ts.SourceFile): StringyValue | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return { text: node.text, exact: true }
  }
  if (ts.isTemplateExpression(node)) {
    const parts: string[] = [node.head.text]
    for (const span of node.templateSpans) {
      const sub = stringyValue(span.expression, sf)
      if (sub === undefined) return undefined
      parts.push(sub.text, span.literal.text)
    }
    return { text: parts.join(''), exact: false }
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = stringyValue(node.left, sf)
    const right = stringyValue(node.right, sf)
    if (left === undefined || right === undefined) return undefined
    return { text: left.text + right.text, exact: false }
  }
  if (ts.isIdentifier(node)) {
    const init = initializerMap(sf).get(node.text)
    if (init === undefined) return undefined
    return stringyValue(init, sf)
  }
  return undefined
}

/**
 * Statically evaluate a numeric-ish expression: numeric literal (1e9/0x/1_000
 * forms), `**`/`<<`/`*`/`+`/`-` binary ops, unary minus, parentheses, or an
 * identifier bound to a numeric const/let initializer (same first-declaration
 * heuristic as {@link stringyValue}). Undefined when not statically numeric.
 * For R9 unbounded-allocation checks.
 */
export function numberyValue(node: ts.Node, sf: ts.SourceFile): number | undefined {
  if (ts.isNumericLiteral(node)) {
    return Number(node.text.replace(/_/g, ''))
  }
  if (ts.isParenthesizedExpression(node)) {
    return numberyValue(node.expression, sf)
  }
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken) {
    const v = numberyValue(node.operand, sf)
    return v === undefined ? undefined : -v
  }
  if (ts.isBinaryExpression(node)) {
    const left = numberyValue(node.left, sf)
    const right = numberyValue(node.right, sf)
    if (left === undefined || right === undefined) return undefined
    switch (node.operatorToken.kind) {
      case ts.SyntaxKind.AsteriskAsteriskToken: return left ** right
      case ts.SyntaxKind.LessThanLessThanToken: return left << right
      case ts.SyntaxKind.AsteriskToken: return left * right
      case ts.SyntaxKind.PlusToken: return left + right
      case ts.SyntaxKind.MinusToken: return left - right
      default: return undefined
    }
  }
  if (ts.isIdentifier(node)) {
    const init = initializerMap(sf).get(node.text)
    if (init === undefined) return undefined
    return numberyValue(init, sf)
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Pragmatic lexical shadowing (for R3/R4 identifier-source checks)
// ---------------------------------------------------------------------------

function declaresInBlock(block: ts.Block | ts.SourceFile | ts.ModuleBlock, name: string): boolean {
  for (const stmt of block.statements) {
    if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (decl.name.getText() === name) return true
      }
    } else if (ts.isFunctionDeclaration(stmt) && stmt.name !== undefined && stmt.name.text === name) {
      return true
    } else if (ts.isClassDeclaration(stmt) && stmt.name !== undefined && stmt.name.text === name) {
      return true
    }
  }
  return false
}

/**
 * Whether `name` is shadowed at the position of `id`: walk the ancestor chain,
 * checking function parameters, catch-clause variables, and block/statement
 * declarations at each scope boundary. Hoisting/order subtleties are ignored
 * (v1 heuristic; false-negatives bias toward "shadowed", i.e. fewer findings).
 */
export function isShadowed(name: string, id: ts.Identifier): boolean {
  let cur: ts.Node | undefined = id.parent
  while (cur !== undefined) {
    if (ts.isFunctionLike(cur)) {
      for (const param of cur.parameters) {
        if (param.name.getText() === name) return true
      }
      const body = (cur as ts.FunctionLikeDeclaration).body
      if (body !== undefined && ts.isBlock(body) && declaresInBlock(body, name)) return true
    } else if (ts.isBlock(cur) || ts.isSourceFile(cur) || ts.isModuleBlock(cur)) {
      if (declaresInBlock(cur, name)) return true
    } else if (ts.isCatchClause(cur)) {
      if (cur.variableDeclaration !== undefined && cur.variableDeclaration.name.getText() === name) {
        return true
      }
    }
    cur = cur.parent
  }
  return false
}

/** 1-based line of a node in its source file. */
export function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
}
