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
4. **The `/vet` control-plane routes carry no authentication of their own.** This is a statement about where the
   boundary sits, not a claim that it does not exist:

   - **Authentication is the gateway's job, and it is upstream.** In DSH the plugin-registered routes are served
     by the host webserver, and vet deliberately does not build a second account system: an `authorize(ctx, req)`
     seam belongs in the host. What vet can prove is narrower — the routes are reachable without credentials, so
     *whatever* the gateway does is what protects them. Measured on a live host: `/`, `/api` and `/connect`
     return 401; `/vet/*` does not (it is a bypass of the gateway, not the absence of one).
   - **`GET /vet/status.json` and `GET /vet/plugin` are anonymous by design.** The shield polls them from the page
     with no credential to present. Consequence: when `dsh web` binds to a non-loopback address, LAN clients can
     read scan conclusions, alarm targets and plugin metadata. Keep the loopback binding if that matters.
   - **`POST /vet/*` (dismiss/restore, guard toggle, tier switch) has same-origin protection, not authentication.**
     A state-changing request is accepted only when its `Origin` header is present *and* its host matches the
     request `Host`; a POST with no `Origin` at all is rejected (403). That stops a cross-site page from driving
     the control surface. It does **not** stop a same-origin script, or any local process willing to send
     `Origin: http://<host>` — for both, the gateway above is the only real boundary.
   - **`controlLocalOnly` (opt-in, default off) tightens that to a local peer.** With it on, a write is also
     refused unless the TCP peer is loopback (`127.0.0.0/8`, `::1`) or one of this host's own interface
     addresses. The peer address is filled in by the kernel; `Origin`/`Host` can be typed by any client, so on
     its own the same-origin check says nothing about who is calling — with `dsh web` on a LAN address, any
     machine on that LAN could flip the tier by sending two headers. It is off by default because the cost is
     the owner's actual workflow: 0.5.13 shipped it on, and the first user could not toggle the guard from a
     second machine. It reads no `X-Forwarded-For` — that is a request header, exactly the thing it stops
     trusting — and an unknown peer is refused rather than allowed.
   - **Same-origin is not authorization.** Anyone who can reach the control surface can toggle the guard or the
     tier. What they cannot do is rewrite history: dismissals never delete alarms, and every state change is
     recorded. The panel is a local control surface, not a remotely-authorized one — this is the honest trade,
     and it is written down rather than implied by a green badge.

## Install-time code execution

vet ships **no install-time scripts**: there is no `preinstall`, `install`, `postinstall` or `prepare` hook in its
`package.json`, so `npm i @jieai/dsh-plugin-vet` does not execute any vet code. Vet *reports* those hooks when
another package has them (R10) — that is the check, not a claim about vet itself.

## Dependency vulnerabilities

- Runtime dependencies are minimal (schemastery + typescript); watch `npm audit`.
- The OSV check (`osvCheck`) queries known vulnerabilities for the plugin package itself **and its direct
  dependencies** (exact installed versions only; ranges and version-less packages are skipped, cap 8 deps) —
  it does not guarantee coverage of the whole supply chain (transitive trees only via the opt-in
  `transitiveDeps` upstream-radar scan, default off).