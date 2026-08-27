// 面板内嵌素材的类型声明：由 build-client.mjs 读文件 → data URI → define 注入
// （__VET_ASSETS__），运行期以 const 形式存在，无 import 解析环节。
declare const __VET_ASSETS__: {
  vetLogo: string
  dshSoLogo: string
}