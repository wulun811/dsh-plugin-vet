/**
 * 路径归一化共享原语（round-5 review，B-A12）：
 * confirm-block 与 contract 此前各有一份 normPath 且语义不同——前者只替换反斜杠，
 * 后者额外折叠重复分隔符并去尾部斜杠。「/home/u/.ssh//id_rsa」这类双斜杠等价写法
 * （POSIX 系统调用层会折叠）在 confirm-block 侧不命中凭据精确清单、在 contract 侧
 * 命中——同一概念两处行为不一致，且精确判定面（N7 族 1/2 凭据拦截）存在双斜杠
 * 绕过的理论形态。统一为单源实现，两处共用。
 */
/** 反斜杠 → 斜杠、折叠重复分隔符、去尾部斜杠（保留根 '/'）。 */
export function normPath(p: string): string {
  return p.replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/$/, '')
}