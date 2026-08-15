// 编译产物集成验证：模拟 webServer 延迟就绪 → installStatusRoute 重试注册
// → GET /vet/status.json（指标）/ POST /vet/runtime-guard（写配置）全链路。
import { createServer } from 'node:http'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { installStatusRoute } from '../lib/guard/status-route.js'
import { VetStatus } from '../lib/guard/status.js'

const baseUrl = mkdtempSync(join(process.cwd(), '.tmp-verify-route-'))
writeFileSync(join(baseUrl, 'cordis.patch.yml'), '- id: settings\n  config:\n    watch: false\n')

let getCalls = 0
let registeredRoute = null
const server = createServer((req, res) => {
  if (registeredRoute) registeredRoute.handler(req, res)
  else { res.writeHead(500); res.end('no route yet') }
})

// 前 2 次 get('webServer') 返回 undefined（模拟未就绪），之后返回真实服务
const fakeCtx = {
  baseUrl,
  logger: { info: console.log, warn: console.warn, error: console.error },
  get(name) {
    getCalls += 1
    if (name !== 'webServer') return undefined
    if (getCalls <= 2) return undefined
    return {
      register(route) {
        registeredRoute = route
        return () => { registeredRoute = null }
      },
    }
  },
  effect(fn) { fn(); return () => {} },
}

const status = new VetStatus()
status.record({ id: 't2:mem:x', severity: 'red', source: 't1', kind: 'mem', message: '内存超限测试', at: Date.now() })
installStatusRoute(fakeCtx, { runtimeGuard: 'off' }, status)

await new Promise(r => server.listen(0, '127.0.0.1', r))
const port = server.address().port
await new Promise(r => setTimeout(r, 1500)) // 等重试注册（400ms 周期 × 3 次尝试）

const get = async (path) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`)
  return { status: res.status, body: await res.text() }
}

const g = await get('/vet/status.json')
console.log('GET /vet/status.json →', g.status)
const json = JSON.parse(g.body)
console.log('  level:', json.level, '| alarmCount:', json.alarmCount, '| runtimeGuard:', json.runtimeGuard)
console.log('  metrics:', JSON.stringify(json.metrics))

const p = await get('/vet/runtime-guard')
console.log('POST /vet/runtime-guard(无 body) →', p.status, p.body)

const p2 = await fetch(`http://127.0.0.1:${port}/vet/runtime-guard`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enable: true }),
})
console.log('POST enable →', p2.status, await p2.text())
const patch = readFileSync(join(baseUrl, 'cordis.patch.yml'), 'utf8')
console.log('cordis.patch.yml 含 runtimeGuard: watch:', patch.includes('runtimeGuard: watch'))

const bad = await fetch(`http://127.0.0.1:${port}/vet/runtime-guard`, {
  method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://evil.example' }, body: JSON.stringify({ enable: true }),
})
console.log('POST 跨源 →', bad.status, await bad.text())

server.close()
rmSync(baseUrl, { recursive: true, force: true })
console.log('验证完成')
