import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  computePackageHash,
  checkBaseline,
  recordBaseline,
  loadBaseline,
  saveBaseline,
  getBaseline,
  refreshBaseline,
  baselinePath,
  type BaselineStore,
} from '../src/guards/content-baseline.js'

describe('content-baseline', () => {
  let testDir: string
  let originalEnv: string | undefined

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-baseline-test-'))
    // 使用临时目录作为基线路径
    originalEnv = process.env.DSH_PLUGIN_VET_BASELINE_DIR
    process.env.DSH_PLUGIN_VET_BASELINE_DIR = testDir
    refreshBaseline()
  })

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.DSH_PLUGIN_VET_BASELINE_DIR = originalEnv
    } else {
      delete process.env.DSH_PLUGIN_VET_BASELINE_DIR
    }
    rmSync(testDir, { recursive: true, force: true })
  })

  describe('computePackageHash', () => {
    it('should compute deterministic hash for same content', () => {
      const pkgDir = join(testDir, 'pkg1')
      mkdirSync(pkgDir, { recursive: true })
      writeFileSync(join(pkgDir, 'package.json'), '{"name":"test","version":"1.0.0"}')
      writeFileSync(join(pkgDir, 'index.js'), 'console.log("hello")')

      const result1 = computePackageHash(pkgDir)
      const result2 = computePackageHash(pkgDir)

      expect(result1).not.toBeNull()
      expect(result2).not.toBeNull()
      expect(result1!.hash).toBe(result2!.hash)
    })

    it('should return different hash for different content', () => {
      const pkgDir1 = join(testDir, 'pkg1')
      const pkgDir2 = join(testDir, 'pkg2')
      mkdirSync(pkgDir1, { recursive: true })
      mkdirSync(pkgDir2, { recursive: true })
      writeFileSync(join(pkgDir1, 'package.json'), '{"name":"test","version":"1.0.0"}')
      writeFileSync(join(pkgDir1, 'index.js'), 'console.log("hello")')
      writeFileSync(join(pkgDir2, 'package.json'), '{"name":"test","version":"1.0.0"}')
      writeFileSync(join(pkgDir2, 'index.js'), 'console.log("world")')

      const result1 = computePackageHash(pkgDir1)
      const result2 = computePackageHash(pkgDir2)

      expect(result1).not.toBeNull()
      expect(result2).not.toBeNull()
      expect(result1!.hash).not.toBe(result2!.hash)
    })

    it('should exclude markdown files', () => {
      const pkgDir = join(testDir, 'pkg')
      mkdirSync(pkgDir, { recursive: true })
      writeFileSync(join(pkgDir, 'package.json'), '{"name":"test"}')
      writeFileSync(join(pkgDir, 'index.js'), 'code')
      writeFileSync(join(pkgDir, 'README.md'), '# Readme')

      const hashWithMd = computePackageHash(pkgDir)

      // 删除 README.md 后哈希应该不变
      rmSync(join(pkgDir, 'README.md'))
      const hashWithoutMd = computePackageHash(pkgDir)

      expect(hashWithMd).not.toBeNull()
      expect(hashWithoutMd).not.toBeNull()
      expect(hashWithMd!.hash).toBe(hashWithoutMd!.hash)
    })

    it('should return null when file count exceeds limit', () => {
      const pkgDir = join(testDir, 'pkg')
      mkdirSync(pkgDir, { recursive: true })
      writeFileSync(join(pkgDir, 'package.json'), '{}')
      // 创建超过限制的文件
      for (let i = 0; i < 5; i++) {
        writeFileSync(join(pkgDir, `file${i}.js`), 'code')
      }

      const result = computePackageHash(pkgDir, { maxFiles: 3 })
      expect(result).toBeNull()
    })

    it('should return null when total size exceeds limit', () => {
      const pkgDir = join(testDir, 'pkg')
      mkdirSync(pkgDir, { recursive: true })
      writeFileSync(join(pkgDir, 'package.json'), '{}')
      writeFileSync(join(pkgDir, 'large.js'), 'x'.repeat(1000))

      const result = computePackageHash(pkgDir, { maxSizeBytes: 500 })
      expect(result).toBeNull()
    })

    it('P1-4: should reject single file exceeding maxSizeBytes before reading', () => {
      const pkgDir = join(testDir, 'pkg-large')
      mkdirSync(pkgDir, { recursive: true })
      writeFileSync(join(pkgDir, 'package.json'), '{"name":"test","version":"1.0.0"}')
      // 创建一个超过 maxSizeBytes 的文件（使用小阈值测试）
      const bigFile = join(pkgDir, 'big.bin')
      const fd = require('fs').openSync(bigFile, 'w')
      require('fs').ftruncateSync(fd, 2 * 1024 * 1024) // 2MB
      require('fs').closeSync(fd)

      // 使用 1MB 阈值，应该被拒绝
      const result = computePackageHash(pkgDir, { maxSizeBytes: 1024 * 1024 })
      expect(result).toBeNull()
    })

    it('P2-8: should hash binary content correctly (bytes 128-255)', () => {
      const pkgDir = join(testDir, 'pkg-binary')
      mkdirSync(pkgDir, { recursive: true })
      writeFileSync(join(pkgDir, 'package.json'), '{"name":"test","version":"1.0.0"}')
      // 创建包含 bytes 128-255 的二进制文件
      const binaryContent = Buffer.from([0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF])
      require('fs').writeFileSync(join(pkgDir, 'binary.bin'), binaryContent)

      const result = computePackageHash(pkgDir)
      expect(result).not.toBeNull()
      // 哈希应该是确定性的
      const result2 = computePackageHash(pkgDir)
      expect(result!.hash).toBe(result2!.hash)
    })
  })

  describe('checkBaseline', () => {
    it('should return first-seen for new package', () => {
      const store: BaselineStore = { records: {} }
      const result = checkBaseline('@deepseek-ai/test', '1.0.0', 'abc123', store)
      expect(result).toBe('first-seen')
    })

    it('should return match for same hash', () => {
      const store: BaselineStore = { records: {} }
      recordBaseline('@deepseek-ai/test', '1.0.0', 'abc123', store)
      const result = checkBaseline('@deepseek-ai/test', '1.0.0', 'abc123', store)
      expect(result).toBe('match')
    })

    it('should return mismatch for different hash', () => {
      const store: BaselineStore = { records: {} }
      recordBaseline('@deepseek-ai/test', '1.0.0', 'abc123', store)
      const result = checkBaseline('@deepseek-ai/test', '1.0.0', 'def456', store)
      expect(result).toBe('mismatch')
    })

    it('should support multiple versions', () => {
      const store: BaselineStore = { records: {} }
      recordBaseline('@deepseek-ai/test', '1.0.0', 'hash1', store)
      recordBaseline('@deepseek-ai/test', '2.0.0', 'hash2', store)
      
      expect(checkBaseline('@deepseek-ai/test', '1.0.0', 'hash1', store)).toBe('match')
      expect(checkBaseline('@deepseek-ai/test', '2.0.0', 'hash2', store)).toBe('match')
      expect(checkBaseline('@deepseek-ai/test', '1.0.0', 'hash2', store)).toBe('mismatch')
    })
  })

  describe('loadBaseline / saveBaseline', () => {
    it('should return empty store when file does not exist', () => {
      const store = loadBaseline()
      expect(store.records).toEqual({})
    })

    it('should persist and load baseline', () => {
      const store = loadBaseline()
      recordBaseline('@deepseek-ai/test', '1.0.0', 'abc123', store)
      saveBaseline(store)

      refreshBaseline()
      const loaded = loadBaseline()
      expect(loaded.records['@deepseek-ai/test@1.0.0']).toBeDefined()
      expect(loaded.records['@deepseek-ai/test@1.0.0'].hash).toBe('abc123')
    })

    it('should return empty store when file is corrupted', () => {
      const path = baselinePath()
      mkdirSync(join(testDir, '.dsh', 'vet'), { recursive: true })
      writeFileSync(path, 'invalid json{{{')
      
      const store = loadBaseline()
      expect(store.records).toEqual({})
    })
  })
})
