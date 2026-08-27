// round-16 对照 C08：形参遮蔽模块级敏感常量——stringyValue 必须尊重词法遮蔽，
// 不得把形参解析成模块级 const（否则 R11 high → suspicious）。verdict 必须 clean。
const url = '/etc/passwd'
function f(url) {
  fs.unlinkSync(url)
}
f('/tmp/x')
