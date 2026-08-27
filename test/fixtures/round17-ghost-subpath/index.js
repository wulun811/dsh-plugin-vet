// R16 幽灵依赖（子路径形态，自审 round-17）：父包 ghost-pkg 整体未声明 → 子路径导入
// ghost-pkg/sub 必须仍判幽灵——前缀解析（declared.some(d => i === d || i.startsWith(d + '/')))
// 只洗白「父包已声明」的子路径，不能把未声明子路径一并洗白。
import 'ghost-pkg/sub'

export const value = 1