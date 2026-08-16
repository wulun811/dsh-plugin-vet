# Security Policy

## Reporting vulnerabilities

vet is the trust layer for DSH plugins: the scanner's judgments, the runtime guard, and the honeypot all
directly touch user-environment security. If you find a security vulnerability, **do not file a public issue**
— report it privately:

- Open a GitHub Security Advisory: https://github.com/wulun811/dsh-plugin-vet/security/advisories/new
- Or message the maintainer directly (GitHub user: wulun811)

Please include: affected versions, reproduction steps, expected vs. actual behavior, and an optional PoC.

## Response commitment

- Acknowledgment: within 2 business days
- Severity assessment + fix plan: within 5 business days
- Fix release: depends on severity; low-severity issues may be folded into the next release

## Known boundaries (by design, not vulnerabilities)

The following are **explicitly declared non-security boundaries** (details in docs/ARCHITECTURE.md and the
README):

1. Static scanning is a "speed bump + forensics layer", not a security boundary — obfuscated/dynamically
   constructed code can bypass the AST rules.
2. The T1/T2 runtime guard does not cover worker_threads' independent realms, native plugins, or
   process.binding.
3. T2 does not cover ESM named-import snapshots.
4. /vet/status.json has no auth (the shield's polling needs anonymous GET) — readable on the LAN when dsh web
   binds to a non-loopback address.
5. vet is alarm-only: reports by default, never blocks; deny interception is an explicit deployer opt-in.

## Dependency vulnerabilities

- Runtime dependencies are minimal (schemastery + typescript); watch `npm audit`.
- The OSV check (`osvCheck`) only queries known vulnerabilities in the plugin's package.json — it does not
  guarantee coverage of the whole supply chain.