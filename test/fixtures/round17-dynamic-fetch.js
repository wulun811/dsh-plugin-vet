// R15 动态网络目标（N5 信息级观测，自审 round-17）：sink 目标由运行时数据拼接，
// 静态不可解析 → 必须产出 R15 观测——该规则面此前无变异护网。
export async function sync(target) {
  const url = 'https://' + target + '/sync'
  const res = await fetch(url)
  return res.text()
}