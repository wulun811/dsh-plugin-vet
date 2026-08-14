import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'

/** sessionPersistence 服务的结构化最小类型（避免引入额外依赖）。 */
export interface SessionPersistenceLike {
  append(id: unknown, events: readonly SessionEvent[]): Promise<void>
}

/**
 * append 审计事件（Model-visible ⟺ logged，PLAN.md §5.4）：
 * 走 sessionPersistence.append 完整信封 + ignorable: true——coordinator.ts:1063 对未知
 * 非 ignorable 类型会拒读，session.append 无法置 ignorable，故不能走 live append。
 * best-effort：任何失败不阻塞审计主流程。
 */
export function appendAuditEvent(
  persistence: SessionPersistenceLike | undefined,
  session: Session | undefined,
  type: 'audit-plugin-vet/request' | 'audit-plugin-vet/result',
  data: Record<string, unknown>,
): void {
  if (persistence === undefined || session === undefined) return
  const seq = (session as unknown as { log?: { length: number } }).log?.length ?? 0
  const envelope = {
    type,
    seq,
    time: Date.now(),
    data,
    ignorable: true as const,
  } as unknown as SessionEvent
  void persistence.append(session.id, [envelope]).catch(() => {
    // 审计日志失败不阻断流程
  })
}
