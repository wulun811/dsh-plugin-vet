// T1 哨兵冒烟：spawn lib/guard/runtime-watch.js --vet-sidecar 监视本进程，
// 制造内存暴涨 + fork 炸弹，观察报警 JSON 行；最后正常退出验证哨兵自杀。
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const sidecar = spawn(process.execPath, [
  fileURLToPath(new URL('../lib/guard/runtime-watch.js', import.meta.url)),
  '--vet-sidecar', '100', '256', '2', '100',
], { stdio: ['ignore', 'pipe', 'inherit'] })

const alarms = []
sidecar.stdout.setEncoding('utf8')
sidecar.stdout.on('data', (chunk) => {
  for (const line of chunk.split('\n')) {
    const t = line.trim()
    if (t === '') continue
    try { alarms.push(JSON.parse(t)) } catch {}
  }
})

const sleep = ms => new Promise(r => setTimeout(r, ms))

// 阶段 1：内存暴涨（分配 400MB 常驻）
const holder = []
for (let i = 0; i < 40; i++) holder.push(Buffer.alloc(10 * 1024 * 1024))
await sleep(400)
console.log('阶段1（内存超限后）报警:', JSON.stringify(alarms.map(a => a.kind)))

// 阶段 2：fork 炸弹（spawn 10 个 sleep 子进程）
for (let i = 0; i < 10; i++) {
  const c = spawn('sleep', ['5'])
  c.unref()
}
await sleep(400)
console.log('阶段2（fork 突增后）报警:', JSON.stringify(alarms.map(a => a.kind)))
console.log('报警总数:', alarms.length)

// 阶段 3：宿主退出 → 哨兵自杀
process.exit(0)
