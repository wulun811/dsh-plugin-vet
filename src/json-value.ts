/**
 * 本地 JSON 值类型镜像（0.3.13，DSH 0.1.7-rc.1 同步）。
 *
 * 为什么不继续从 @deepseek-ai/dsh-tools 导入：0.1.1-rc.1 的 dsh-tools 有
 * `export type { JsonValue } from '@deepseek-ai/dsh-session'`，0.1.7-rc.1 删掉了这行
 * （类型搬到新包 @deepseek-ai/dsh-util-values）——继续导入会在新家族下 TS2614。
 * 而第三方包无法编译期依赖宿主私有包（与 src/client 的 SlotsLike 镜像同款纪律），
 * 且该类型只作本地转换靶子、不进本包公开签名，故用最小结构镜像：零新增依赖，
 * 也不受宿主包拆分（session → util-values）影响。
 */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }
