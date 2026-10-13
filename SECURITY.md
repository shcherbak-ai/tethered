# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tethered, please report it **privately** using [GitHub's private vulnerability reporting](https://github.com/shcherbak-ai/tethered/security/advisories/new).

Please avoid opening public issues for security vulnerabilities.

Confirmed vulnerabilities will be addressed in a patch release.

## Security model

tethered is a defense-in-depth guardrail, not a security sandbox. It intercepts Python-level socket operations. Code that uses `ctypes`, `cffi`, subprocesses, or C extensions with direct syscalls can bypass it, and ordinary libraries do the same without any intent when they resolve names and connect inside a C library of their own. For full process isolation, combine tethered with OS-level controls (containers, seccomp, network namespaces).

The model is described in the documentation, on the [security model](https://tethered.shcherbak.ai/security/) page:

- [Threat model](https://tethered.shcherbak.ai/security/#threat-model): what the protections are scoped to, and what they are not a defense against
- [What tethered protects against](https://tethered.shcherbak.ai/security/#what-tethered-protects-against)
- [What tethered does NOT protect against](https://tethered.shcherbak.ai/security/#what-tethered-does-not-protect-against): native code, event loops other than asyncio's own, what the socket events do not cover, child processes, code in the same process
- [Locked mode — what it does and does not do](https://tethered.shcherbak.ai/security/#locked-mode--what-it-does-and-does-not-do)
- [Recommendations](https://tethered.shcherbak.ai/security/#recommendations)
