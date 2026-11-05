#!/usr/bin/env node
/**
 * 发布物端到端验收（0.5.17）：把 `npm pack` 的产物装进**全新的 DSH profile**，
 * 启动宿主，真的通过 HTTP 点一次面板开关，再重启验证持久化。
 *
 * 与既有两个脚本的分工（三者不是替代关系，是三个不同的断言）：
 * - `check-pack-integrity.mjs`：发布集够不够（读工作区源码树）；
 * - `check-pack-smoke.mjs`：解包后能不能 import（读解开的 tarball）；
 * - 本脚本：**装进宿主之后能不能用**——这一层上面两个都碰不到。
 *
 * 为什么值得单开一个脚本（0.5.17 的实证）：首次运行时它立刻抓到一个 0.5.16 及以前
 * 全版本都有的缺陷——面板「开启守卫」在**全新 profile** 上必然失败（`[]` 后追加列表项
 * → 非法 YAML → 原子写校验拒绝 → 500）。此前从未有人真的从打包产物装一次：开发机
 * 用 `link:` 挂工作区，profile 里早有配置好的 patch 文件，走不到那条分支。
 *
 * 隔离纪律（三条都要，缺一条就会污染这台机器）：
 * 1. `DSH_HOME` 指向临时目录——profile、node_modules、日志全隔离；
 * 2. `DSH_PLUGIN_VET_STORE_DIR` 指向临时目录——vet 的状态按 `homedir()` 解析，
 *    **不跟随 DSH_HOME**；不设它就会写进真实 `~/.dsh/vet`（首次手测时发生过，
 *    baseline/capabilities/stats 三个文件被写脏）；
 * 3. 宿主绑定 `127.0.0.1` 且随机端口——不碰用户正在用的 3456，也不对外监听。
 *
 * 刻意不做的：不跑扫描器断言（`npm test` 覆盖）、不点「忽略/恢复」（会改 dismissed
 * 状态，与守卫无关）、不验证 UI 渲染（无浏览器，只验 HTTP 契约与磁盘字节）。
 *
 * 用法：node scripts/check-pack-acceptance.mjs [--keep]
 *   --keep  保留临时目录并打印路径（排障用）
 */

import { execFileSync, spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, sep } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

const ROOT = process.cwd()
const KEEP = process.argv.includes('--keep')
// Windows 兼容：npm/dsh 在 win32 是 .cmd shim，Node 22 起 spawn .cmd 必须经 shell；
// 从 npm script 启动时优先用 npm_execpath（`node <npm-cli.js>`）。
const DSH = process.env.DSH_BIN ?? (process.platform === 'win32' ? 'dsh.cmd' : 'dsh')
const WIN_SHELL = { shell: process.platform === 'win32' }
function runNpm(args, opts) {
  if (process.env.npm_execpath !== undefined) {
    return execFileSync(process.execPath, [process.env.npm_execpath, ...args], opts)
  }
  return execFileSync('npm', args, { ...opts, ...WIN_SHELL })
}
const problems = []
const fail = (msg) => { problems.push(msg); console.error('  ✗ ' + msg) }
const ok = (msg) => console.log('  ✓ ' + msg)

/** 从 boot 日志里取 token。dsh web 打印 `dsh web: http://host:port/?token=...`。 */
function readToken(logPath) {
  const log = readFileSync(logPath, 'utf8')
  const m = /[?&]token=([A-Za-z0-9_-]+)/.exec(log)
  return m === null ? undefined : m[1]
}

async function waitForToken(logPath, child, budgetMs = 120_000) {
  const deadline = Date.now() + budgetMs
  while (Date.now() < deadline) {
    if (existsSync(logPath)) {
      const token = readToken(logPath)
      if (token !== undefined) return token
    }
    if (child.exitCode !== null) return undefined
    await sleep(500)
  }
  return undefined
}

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: new URL(url).origin },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  let json
  try {
    json = JSON.parse(text)
  } catch {
    json = undefined
  }
  return { status: res.status, json, text }
}

async function getJson(url) {
  const res = await fetch(url)
  return { status: res.status, json: JSON.parse(await res.text()) }
}

const scratch = mkdtempSync(join(tmpdir(), 'vet-accept-'))
const dshHome = join(scratch, 'home')
const vetStore = join(scratch, 'store')
const profileName = 'accept'
const profileDir = join(dshHome, 'profiles', profileName)
mkdirSync(dshHome, { recursive: true })
mkdirSync(vetStore, { recursive: true })

/** 子进程统一环境：两条隔离变量都必须带。 */
const childEnv = {
  ...process.env,
  DSH_HOME: dshHome,
  DSH_PLUGIN_VET_STORE_DIR: vetStore,
  // 宿主可能继承会话里的 token/端口配置，清掉避免串到这个实例
  DSH_WEB_URL: undefined,
}

let server
const servers = []
async function boot(port) {
  const logPath = join(scratch, `boot-${port}-${servers.length}.log`)
  // 直接用 dsh 可执行文件（不是 `node <js>` 形态）：dsh 的 bin 是带 shebang 的入口脚本，
  // 它的第一个参数就是 `--profile`，用 node 去跑会把 `--profile` 当成 node 自己的选项。
  const child = spawn(DSH, [
    '--profile', profileName,
    '--no-open',
    '--port', String(port),
    '--host', '127.0.0.1',
  ], {
    cwd: scratch,
    env: childEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
    ...WIN_SHELL,
  })
  let buf = ''
  child.stdout.on('data', (d) => { buf += String(d) })
  child.stderr.on('data', (d) => { buf += String(d) })
  // 日志写内存变量也要落盘，waitForToken 只读文件
  const { writeFileSync } = await import('node:fs')
  const timer = setInterval(() => { try { writeFileSync(logPath, buf) } catch { /* 目录尚未就绪 */ } }, 200)
  servers.push({ child, timer })
  server = child
  const token = await waitForToken(logPath, child)
  clearInterval(timer)
  try { writeFileSync(logPath, buf) } catch { /* 忽略 */ }
  return { child, token, logPath, tail: () => buf }
}

async function shutdown() {
  for (const { child, timer } of servers) {
    clearInterval(timer)
    if (child.exitCode === null) {
      child.kill('SIGTERM')
      await sleep(1500)
      if (child.exitCode === null) child.kill('SIGKILL')
    }
  }
  servers.length = 0
}

const PATCH = () => join(profileDir, 'cordis.patch.yml')

try {
  // ── 1) 打包 ────────────────────────────────────────────────────────────
  const raw = runNpm(['pack', '--json', '--pack-destination', scratch], {
    cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
  })
  const info = JSON.parse(raw)[0]
  const tarball = join(scratch, info.filename)
  const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version
  ok(`打包：${info.filename}（${info.files.length} 个文件，${(info.size / 1024).toFixed(0)} KB）`)

  // ── 2) 全新 profile（DSH 下发的 web 模板，不是手搓的目录）────────────────
  execFileSync(DSH, [
    '--profile', profileName, '--from-default-profile', 'web', '--dump-config',
  ], { cwd: scratch, env: childEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...WIN_SHELL })
  if (!existsSync(join(profileDir, 'package.json'))) {
    fail('剖面初始化失败：没有 package.json')
    throw new Error('abort')
  }
  ok(`全新剖面已建（${profileName}，来自 web 模板）`)

  // 全新 profile 的 patch 必须是模板形态（注释头 + []）——这正是 0.5.17 缺陷的输入
  const pristine = readFileSync(PATCH(), 'utf8')
  if (!(pristine.includes('# Your patch layer') && pristine.trim().endsWith('[]'))) {
    fail(`全新 profile 的 patch 不是预期的模板形态：${JSON.stringify(pristine.slice(0, 120))}`)
  } else {
    ok('全新 profile 的 patch 是模板形态（注释头 + []）')
  }

  // ── 3) 真的装进去 ──────────────────────────────────────────────────────
  execFileSync(DSH, ['plugin', '--profile', profileName, 'add', tarball], {
    cwd: scratch, env: childEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...WIN_SHELL,
  })
  const installed = join(profileDir, 'node_modules', '@jieai', 'dsh-plugin-vet', 'package.json')
  if (!existsSync(installed)) {
    fail('安装后 node_modules 里没有 @jieai/dsh-plugin-vet')
    throw new Error('abort')
  }
  const installedVersion = JSON.parse(readFileSync(installed, 'utf8')).version
  if (installedVersion !== version) fail(`装进去的版本是 ${installedVersion}，工作区是 ${version}`)
  else ok(`已装入干净 profile：@jieai/dsh-plugin-vet@${installedVersion}`)

  // 装的是**真实副本**，不是指向工作区的符号链接（否则这次验收没有意义）
  // Windows 兼容：realpath 是 POSIX 外部命令，node:fs 的 realpathSync 全平台等价
  const realInstalled = realpathSync(join(profileDir, 'node_modules', '@jieai', 'dsh-plugin-vet'))
  if (realInstalled === ROOT || realInstalled.startsWith(ROOT + sep)) {
    fail(`装出来仍指向工作区（${realInstalled}）——这次验收没有覆盖发布物`)
  } else {
    ok('装的是 tarball 解出来的副本（不是工作区软链）')
  }

  // ── 4) 启动宿主 ────────────────────────────────────────────────────────
  let booted = await boot(0)
  // --port 0 时实际端口在日志里；解析真实 URL 而不是猜
  if (booted.token === undefined) {
    fail(`宿主未能在预算内启动：\n${booted.tail().slice(-2000)}`)
    throw new Error('abort')
  }
  const url = /dsh web: (http:\/\/[^\s]+)/.exec(booted.tail())?.[1]
  if (url === undefined) {
    fail('启动日志里没有 web URL')
    throw new Error('abort')
  }
  const base = new URL(url).origin
  ok(`宿主已启动：${base}`)

  // ── 5) 面板接口活着 ────────────────────────────────────────────────────
  const before = await getJson(`${base}/vet/status.json?token=${booted.token}`)
  if (before.status !== 200) {
    fail(`/vet/status.json 返回 ${before.status}`)
    throw new Error('abort')
  }
  if (before.json.runtimeGuard !== 'off') {
    fail(`全新 profile 的 runtimeGuard 应为 off，实际 ${String(before.json.runtimeGuard)}`)
  } else {
    ok('全新 profile：守卫默认关闭，/vet/status.json 200')
  }
  // 0.5.20：两块「推导出来但没人读」的数据现在必须在真实产物里出现——数据在、字段在、
  // 面板却不画的形态，测试与 JSON 校验都看不出来（见 docs/FAILURES.md F21）。
  const cfg = before.json.effectiveConfig
  const proj = before.json.domainProjection
  if (cfg === undefined || !Array.isArray(cfg.keys) || typeof cfg.counts?.changed !== 'number') {
    fail('状态报文缺 effectiveConfig（0.5.20 起面板要画它）')
  } else if (proj === undefined || typeof proj.mismatches !== 'number' || typeof proj.mode !== 'string') {
    fail('状态报文缺 domainProjection（0.5.20 起面板要画它）')
  } else {
    ok(`生效配置视图与投影计数在位：changed=${cfg.counts.changed} mode=${proj.mode} mismatches=${proj.mismatches}`)
  }
  const surfaces = (before.json.effectivePosture ?? []).map((p) => `${p.surface}=${p.effective}`)
  if (!surfaces.some((s) => s.startsWith('runtime_fs=') && s.endsWith('off'))) {
    fail(`守卫关闭时 runtime_fs 应为 off，实际 ${surfaces.join(' ') || '（无 posture）'}`)
  } else {
    ok(`守卫关闭时的覆盖面：${surfaces.join(' ')}`)
  }

  // ── 6) 第一次点「开启守卫」——0.5.16 及以前这里必然 500 ─────────────────
  const on = await post(`${base}/vet/runtime-guard?token=${booted.token}`, { enable: true })
  if (on.status !== 200 || on.json?.ok !== true) {
    fail(`首次开启守卫失败（HTTP ${on.status}）：${on.text.slice(0, 400)}`)
    throw new Error('abort')
  }
  ok(`首次开启守卫成功：${on.json.note}`)

  // 磁盘字节必须是合法 YAML 组数，且注释头没被吃掉
  const afterOn = readFileSync(PATCH(), 'utf8')
  if (!afterOn.includes('runtimeGuard: watch')) fail('patch 里没有 runtimeGuard: watch')
  if (!afterOn.includes('profile: hardened')) fail('patch 里没有 profile: hardened')
  if (!afterOn.startsWith('# Your patch layer')) fail('写入吃掉了 DSH 的注释头')
  if (!/^\s*- id:/m.test(afterOn)) fail('patch 里没有列表项')
  if (/^\s*\[\]\s*$/m.test(afterOn) && /^\s*- id:/m.test(afterOn)) {
    fail('patch 同时含有 [] 与列表项（非法 YAML 双根形态）')
  }
  ok('磁盘字节正确：注释头保留、条目已写入、无 [] 与列表项并存')

  // 运行时：四个面必须真的落到 enforced
  await sleep(2500)
  const afterState = await getJson(`${base}/vet/status.json?token=${booted.token}`)
  if (afterState.json.runtimeGuard !== 'watch') fail(`开关后 runtimeGuard=${String(afterState.json.runtimeGuard)}，应为 watch`)
  const enforced = (afterState.json.effectivePosture ?? [])
    .filter((p) => ['runtime_fs', 'runtime_net', 'runtime_spawn', 'confirm_block'].includes(p.surface))
    .filter((p) => p.effective === 'enforced')
    .map((p) => p.surface)
  if (enforced.length !== 4) {
    fail(`开启后只有 ${enforced.length}/4 个运行时面 enforced：${enforced.join(',') || '无'}（posture: ${(afterState.json.effectivePosture ?? []).map((p) => p.surface + '=' + p.effective).join(' ') }）`)
  } else {
    ok('开启后四个运行时面全部 enforced（fs/net/spawn/confirm_block）')
  }

  // ── 7) 重启后仍在（持久化不是「当前进程记住了」）──────────────────────
  const first = booted
  first.child.kill('SIGTERM')
  await sleep(2500)
  booted = await boot(0)
  if (booted.token === undefined) {
    fail(`重启失败：\n${booted.tail().slice(-2000)}`)
    throw new Error('abort')
  }
  const url2 = /dsh web: (http:\/\/[^\s]+)/.exec(booted.tail())?.[1]
  const base2 = new URL(url2).origin
  const restarted = await getJson(`${base2}/vet/status.json?token=${booted.token}`)
  if (restarted.json.runtimeGuard !== 'watch' || restarted.json.profile !== 'hardened') {
    fail(`重启后未保持：runtimeGuard=${String(restarted.json.runtimeGuard)} profile=${String(restarted.json.profile)}`)
  } else {
    ok('重启后保持：守卫仍开、档位仍为 hardened')
  }

  // ── 8) 关掉之后回到干净形态（注释头 + []，不制造 null 文档）────────────
  const off = await post(`${base2}/vet/runtime-guard?token=${booted.token}`, { enable: false })
  if (off.status !== 200 || off.json?.ok !== true) {
    fail(`关闭守卫失败（HTTP ${off.status}）：${off.text.slice(0, 400)}`)
  }
  await sleep(1500)
  const afterOff = readFileSync(PATCH(), 'utf8')
  if (!afterOff.startsWith('# Your patch layer')) fail('关闭后注释头丢了')
  if (!/^\s*\[\]\s*$/m.test(afterOff)) fail(`关闭后没有留下 [] 标记（文件在 YAML 里会解析成 null）：${JSON.stringify(afterOff.slice(-120))}`)
  if (/^\s*- id:\s*plugin-vet/m.test(afterOff)) fail('关闭后仍残留 plugin-vet 条目')
  if (!problems.some((p) => p.includes('关闭守卫失败'))) ok('关闭后回到模板形态：注释头 + []，无残留条目')

  // ── 9) 再开一次（往返不劣化）──────────────────────────────────────────
  const again = await post(`${base2}/vet/runtime-guard?token=${booted.token}`, { enable: true })
  if (again.status !== 200 || again.json?.ok !== true) fail(`二次开启失败：${again.text.slice(0, 300)}`)
  else ok('二次开启成功（开关往返可重复）')
} catch (error) {
  if (error?.message !== 'abort' && problems.length === 0) {
    fail(`验收中断：${error instanceof Error ? error.stack ?? error.message : String(error)}`)
  }
} finally {
  await shutdown()
  if (KEEP) {
    console.log(`\n保留临时目录：${scratch}`)
  } else {
    rmSync(scratch, { recursive: true, force: true })
  }
}

if (problems.length > 0) {
  console.error(`\n✗ 发布物验收失败（${problems.length} 项）`)
  for (const p of problems) console.error('  - ' + p)
  process.exit(1)
}
console.log('\n✓ 发布物验收通过：打包 → 装进全新 profile → 启动 → 面板开关 → 重启保持 → 关闭归位')
