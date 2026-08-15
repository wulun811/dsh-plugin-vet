# Contributing

欢迎贡献！本仓库遵循 DSH 插件生态的开发惯例。在提交 PR 前，请先阅读本文。

## 开发环境

- Node.js >= 22.19（ESM 项目）
- 依赖：`npm install`（peerDependencies 需要本地有 DSH 相关包，见 package.json）

```sh
npm run build        # scanner-bin + src 编译到 lib/ + client bundle
npm run typecheck    # tsc --noEmit 全量
npm test             # 构建 + vitest（含覆盖率阈值）
npm run test:watch   # 开发循环
```

## 代码结构

- `scanner-bin/` — 静态扫描引擎（独立子进程，AST 只读、从不 eval）
- `src/` — 插件本体：tools / guards / scanner client / guard（T1/T2/蜜罐）/ audit / report
- `src/client/` — GUI 盾牌（浏览器半区，node 环境不参与测试）
- `test/` — vitest 单元测试 + fixtures + 对抗矩阵
- `docs/ARCHITECTURE.md` — 公开架构文档

## 提交规范

使用 conventional commits 前缀：`feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `chore:`。

```sh
git commit -m 'fix(guard): 修复 T2 钩子在 fs.promises 上的覆盖'
```

## 测试要求

- 修复 bug 必须带回归测试（本项目已踩过多次「修了又回归」的坑）。
- 覆盖率阈值：lines/functions/statements >= 70%，branches >= 50%（vitest.config.ts 强制）。
- 提交前跑 `npm run build && npm test`，全绿再提。

## 安全相关

- 扫描器规则涉及安全判定，改动需谨慎：先在 `test/fixtures` 加正/负例，再改规则。
- 发现安全漏洞请走 SECURITY.md 的流程，不要在 issue 里贴细节。

## 行为准则

见 CODE_OF_CONDUCT.md。