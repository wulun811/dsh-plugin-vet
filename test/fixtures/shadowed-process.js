// 负例-遮蔽：参数名 process 合法遮蔽，R3 不应命中
function f(process) {
  return process.pid
}
