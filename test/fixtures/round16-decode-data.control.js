// round-16 对照 C07：解码数据串恰好含敏感路径字面量，但文件无任何 fs 足迹——必须保持 clean
// （R11 N2 语料的 fs 足迹门控：无门控时此文件会凭语料判红 → suspicious，击杀面是"误报不回归"）
const token = Buffer.from('L2V0Yy9wYXNzd2Q6cm9vdDp4', 'base64').toString()
console.log('token:', token)
