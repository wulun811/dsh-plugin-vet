import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import * as constructorChain from './constructor-chain.js'
import * as dynamicExec from './dynamic-exec.js'
import * as processDirect from './process-direct.js'
import * as hostCapture from './host-capture.js'
import * as ctxVerbs from './ctx-verbs.js'
import * as stringHeuristics from './string-heuristics.js'
import * as secrets from './secrets.js'

export interface Rule {
  id: string
  run: (sf: ts.SourceFile, ctx: RuleContext) => Finding[]
}

/** v1 rule registry, ordered by severity priority. */
export const RULES: Rule[] = [
  { id: 'R1', run: constructorChain.run },
  { id: 'R2', run: dynamicExec.run },
  { id: 'R3', run: processDirect.run },
  { id: 'R4', run: hostCapture.run },
  { id: 'R5', run: ctxVerbs.run },
  { id: 'R6', run: stringHeuristics.run },
  { id: 'R7', run: secrets.run },
]

/** Execute all enabled rules over one source file. */
export function executeRules(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const out: Finding[] = []
  for (const rule of RULES) {
    if (ctx.request.rules !== undefined && ctx.request.rules[rule.id] === false) continue
    out.push(...rule.run(sf, ctx))
  }
  return out
}
