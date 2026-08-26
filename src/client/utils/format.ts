/** 时间/内存格式化（P0 从 Shield.tsx 拆出，逻辑不变）。 */

export function fmtTime(at: number): string {
  const d = new Date(at)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
}

/** 内存：≥1 GB 显示 GB（1 位小数），否则 MB 取整。 */
export function fmtRam(mb: number): string {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + ' GB'
  return Math.round(mb) + ' MB'
}

/** 短日期：MM-DD HH:mm（列表用，跨天不歧义）。 */
export function fmtShort(at: number): string {
  const d = new Date(at)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/**
 * 相对时间（最近插件列表用；i18n 单位由调用方传）。
 * <60s 刚刚/now；<60m N 分前；<24h N 小时前；否则回落 fmtShort。
 */
export function fmtRel(at: number, now: number, units: { now: string; min: string; hour: string }): string {
  const diff = Math.max(0, now - at)
  if (diff < 60_000) return units.now
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + ' ' + units.min
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + ' ' + units.hour
  return fmtShort(at)
}
