# Changelog

All notable changes to Claude Guard are documented here.

## v0.2.0 — 2026-07-23

### Security

- **macOS: fixed a silent fail-open.** `pfctl` errors were swallowed, so a failed
  firewall enable could report success while traffic still flowed. Firewall
  commands now surface failures instead of hiding them.
- **Blocklist stays current.** Rules are re-resolved every check cycle, so
  rotating Anthropic/CDN IP addresses are picked up automatically.
- **Least-privilege `sudo`.** The installer now grants passwordless `sudo` only
  for the exact firewall commands used, scoped to the `claude_guard`
  anchor/table/chain — a system-wide firewall flush is no longer permitted.
- Settings are validated against a known key list, and rapid enable/disable
  toggles now resolve in order.

### Added

- **Dedicated menu-bar icon on macOS** — a monochrome template icon that the
  system recolors for the light/dark menu bar.
- **User documentation** in [`docs/`](docs/README.md): installation,
  configuration, VPN modes, and how it works (including limitations).
- Unit tests for country classification, interval clamping, and VPN modes.

### Changed

- Clarified the TLS trust model (bundled Mozilla roots only) and removed a
  misleading no-op TLS call.
- Removed `unwrap()`/`expect()` from production code paths.
- De-duplicated the tray-menu construction.

### Tooling

- Added ESLint, Prettier, rustfmt, and EditorConfig, plus a CI workflow that runs
  linting, formatting checks, and tests on every push and pull request.

## v0.1.0

- Initial release: blocks `api.anthropic.com` and `claude.ai` at the OS firewall
  level when a Russian exit IP is detected, on macOS, Linux, and Windows.
