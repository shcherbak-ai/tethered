# Changelog

All notable changes to this project will be documented in this file.
Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/tethered/).

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.2] — 2026-03-22

### Added

- Context-local `scope()` API for narrowing allowed destinations within a block of code.
  Usable as both a context manager (`with tethered.scope(allow=[...]):`) and a decorator
  (`@tethered.scope(allow=[...])`). Supports `log_only`, `fail_closed`, `allow_localhost`,
  and `on_blocked` options. Scopes use intersection semantics — they can only narrow the
  global policy, never widen it. Safe for concurrent use across threads and async tasks.
- Input validation on `activate()` and `scope()` parameters (type checks for `allow`,
  `on_blocked`, `locked`, `log_only`, `fail_closed`, `allow_localhost`).
- Runnable examples in `examples/`.

## [0.2.0] — 2026-03-15

### Added

- Unicode NFC normalization and fullwidth dot normalization for hostnames and allow rules.
- Hostname validation rejects control characters, null bytes, and invisible Unicode.
- `gethostbyaddr` reverse-DNS lookups are now subject to policy enforcement.

### Changed

- `activate(locked=True)` now requires `lock_token` (raises `ValueError` if omitted).
- `activate()` over a locked policy now requires the correct `lock_token` (raises `TetheredLocked`).
- `getaddrinfo` hook forwards all caller arguments (family, socktype, proto, flags) to C-level resolver.
- Locked mode documentation clarified to better reflect the security model.

### Fixed

- IP-to-hostname map now refreshes existing entries on re-resolution.
- Config and IP map updates are now atomic under nested locks.

### Security

- Documented shared-IP/CDN cache mapping as a known limitation in the security model.
- Documented localhost relay risk with default `allow_localhost=True` in the security model.

[0.3.2]: https://github.com/shcherbak-ai/tethered/compare/v0.2.0...v0.3.2
[0.2.0]: https://github.com/shcherbak-ai/tethered/compare/v0.1.4...v0.2.0
