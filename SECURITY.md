# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `master` (rolling) | ✅ Security fixes land on the latest code only |

Security fixes are applied to `master`; fork release tags are produced from
the release workflow (see `RELEASE.md`) and receive fixes through the next
candidate build. There is no separate LTS line.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use the platform's built-in private security reporting tools
(GitHub: *Security* → *Report a vulnerability*) so the report stays
private until a fix ships. If the platform tool is unavailable, contact the
maintainer through the repository owner's public contact method and prefix
the subject with `[SECURITY]`.

Please include:

- A clear description of the issue
- Steps to reproduce
- Affected versions/commits
- Potential impact
- Any known mitigations

### Response expectations

| Stage | SLA |
| --- | --- |
| Initial acknowledgement | within 3 business days |
| Triage / severity assessment | within 7 business days |
| Fix for critical/high severity | as soon as practical; interim mitigations published with the advisory |

### Disclosure

We follow coordinated disclosure: the reporter is credited unless anonymity
is requested; fixes are released with an advisory describing impact, affected
versions, and upgrade path. Embargoed details are shared only with the
reporter until the fix is public.

## Security boundaries (summary)

- The gateway master transport has **no authentication or encryption**; the
  driver rejects external binds (`gateway_external_bind_allowed=false`) and
  only listens on loopback. Do not expose the gateway listener beyond
  loopback without a secured proxy.
- Unauthenticated/unallowlisted LPC and unknown payload types are rejected by
  default. See `docs/multicore-production-gate.md` for the production gate
  contract.
- `testsuite/etc/cert.pem` / `testsuite/etc/key.pem` are **test-only
  fixtures**. They must never be packaged into release artifacts; release
  packaging verifies this.
- `sys_reload_tls()` is a main-thread-only, master-authorized management
  operation: callers must pass `valid_sys_reload_tls()` on the master object
  and the call is rejected before any listener state is touched otherwise.
  A failed reload keeps the old TLS context valid (see
  `docs/runbooks/gateway-security.md`).
- Dependency and supply-chain posture is tracked in `third_party/manifest.yaml`
  and `third_party/sbom.json`; releases verify checksums of external downloads.
