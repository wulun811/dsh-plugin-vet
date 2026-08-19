import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { resolvePkgRoot } from '../pkg-root.js'

/**
 * 审计协议 skill（D30 定稿）：把 AUDIT_PROTOCOL.md 注册进 DSH skill 目录。
 * agent 在"安装/评估插件"类任务时会在会话 skill 目录看到 vet-audit-protocol，
 * 调用 skill 工具加载完整审查步骤——协议从此"长进 agent 能力集"，
 * 新会话的 agent 也能按步骤执行（不再是躺在包里的死文档）。
 */
export const AUDIT_PROTOCOL_SKILL_NAME = 'vet-audit-protocol'

/** 从包根读协议正文（向上搜索 package.json 定位，兼容 bundle/逐文件两种形态）。 */
export function loadAuditProtocolContent(): string {
  return readFileSync(join(resolvePkgRoot(), 'AUDIT_PROTOCOL.md'), 'utf8')
}

/** 注册审计协议 skill（apply 时调用；返回 disposer）。 */
export function registerAuditProtocolSkill(ctx: { skills?: { register?: (reg: unknown) => () => void } }): (() => void) | undefined {
  const skills = ctx.skills
  if (skills === undefined || typeof skills.register !== 'function') return undefined
  return skills.register!({
    name: AUDIT_PROTOCOL_SKILL_NAME,
    description: 'Review a DSH plugin before install: static verdict via scan_plugin, then read sources, verify findings, deep-dive capabilities, and archive a health record. 新插件安装前按 vet 审计协议审查并落盘健康档案。',
    whenToUse: 'User asks to install, evaluate, or review a DSH plugin; a new plugin is about to be added; a suspicious plugin needs investigation.',
    source: 'runtime', // SkillSource 标识（DSH 加载校验必需，index.ts:764）
    content: loadAuditProtocolContent(),
    resourceBase: { kind: 'opaque', description: 'vet audit protocol (AUDIT_PROTOCOL.md)' },
  })
}
