# Contributing

Welcome! This repository follows the development conventions of the DSH plugin ecosystem. Please read this
before opening a PR.

## Development environment

- Node.js >= 22.19 (ESM project)
- Dependencies: `npm install` (peerDependencies need the DSH packages available locally — see package.json)

```sh
npm run build        # scanner-bin + src compiled to lib/ + client bundle
npm run typecheck    # full tsc --noEmit
npm test             # build + vitest (incl. coverage thresholds)
npm run test:watch   # development loop
```

## Code layout

- `scanner-bin/` — static scan engine (separate subprocess; AST read-only, never eval'd)
- `src/` — plugin body: tools / guards / scanner client / guard (T1/T2/honeypot) / audit / report
- `src/client/` — GUI shield (browser half; not exercised by node tests)
- `test/` — vitest unit tests + fixtures + adversarial matrix
- `docs/ARCHITECTURE.md` — public architecture document

## Commit conventions

Use conventional-commit prefixes: `feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `chore:`.

```sh
git commit -m 'fix(guard): cover T2 hooks over fs.promises'
```

## Testing requirements

- Bug fixes must ship a regression test (this project has repeatedly hit "fixed then regressed").
- Coverage thresholds: lines/functions/statements >= 70%, branches >= 50% (enforced by vitest.config.ts).
- Run `npm run build && npm test` before committing — all green or don't submit.

## Security

- Scanner rules involve security judgments; change them carefully: add positive/negative cases in
  `test/fixtures` first, then change the rule.
- Report security vulnerabilities through the SECURITY.md process; don't paste details into issues.

## Code of conduct

See CODE_OF_CONDUCT.md.