// 负例：异步常驻服务循环（合法后台服务形态，verdict 必须干净）
while (true) { await tick() }