# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tethered, please report it **privately** using [GitHub's private vulnerability reporting](https://github.com/shcherbak-ai/tethered/security/advisories/new).

Please avoid opening public issues for security vulnerabilities.

Confirmed vulnerabilities will be addressed in a patch release.

## Security model

tethered is a defense-in-depth guardrail, not a security sandbox. It intercepts Python-level socket operations. Code that uses `ctypes`, `cffi`, subprocesses, or C extensions with direct syscalls can bypass it, and ordinary libraries do the same without any intent when they resolve names and connect inside a C library of their own. For full process isolation, combine tethered with OS-level controls (containers, seccomp, network namespaces).

The model is described in the documentation, in [docs/security.md](docs/security.md):

- [Threat model](docs/security.md#threat-model): what the protections are scoped to, and what they are not a defense against
- [What tethered protects against](docs/security.md#what-tethered-protects-against)
- [What tethered does NOT protect against](docs/security.md#what-tethered-does-not-protect-against): native code, event loops other than asyncio's own, what the socket events do not cover, child processes, code in the same process
- [Locked mode — what it does and does not do](docs/security.md#locked-mode--what-it-does-and-does-not-do)
- [Recommendations](docs/security.md#recommendations)
