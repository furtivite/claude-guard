# CLAUDE.md

Guidance for Claude Code (and other AI assistants) working in this repository.

## What this is

Claude Guard is a [Tauri v2](https://tauri.app) desktop app (Rust core + React/TS
UI) that blocks outbound traffic to `api.anthropic.com` and `claude.ai` at the OS
firewall level whenever the machine's public exit IP is Russian. It targets macOS,
Linux, and Windows.

This is a **security tool**. The cost of a bug is asymmetric: failing _open_
(traffic flows when it should be blocked) is far worse than failing _closed_
(blocking when unsure). Keep that in mind for every change to the guard loop or a
firewall backend.

## Architecture

```
src-tauri/src/
  main.rs            Tauri entry, tray menu, IPC commands (cmd_*)
  guard.rs           Check loop + block/unblock decisions (the heart)
  config.rs          Settings: store keys, defaults, validation
  ip_checker.rs      ipinfo.io client + 60s cache
  vpn_detector.rs    VPN mode / interface detection
  firewall/
    mod.rs           `Firewall` trait + platform() selector + BLOCKED_DOMAINS
    macos.rs         pfctl anchor `claude_guard`
    linux.rs         nftables (preferred) / iptables, chain CLAUDE_GUARD
    windows.rs       netsh advfirewall, rules ClaudeGuard_*
  build.rs           Generates placeholder icons if none are committed
src/                 React UI: App.tsx, components/StatusCard.tsx, Settings.tsx
docs/                User-facing documentation
```

Data flow: `guard::run_loop` periodically calls `check()`, which reads `Config`,
optionally checks the VPN, fetches the IP via `ip_checker`, then drives the
platform `Firewall` through `transition()`. Status is pushed to the UI via the
`guard:status` Tauri event; the UI also calls `cmd_*` commands.

## Invariants — do not break these

- **Fail-closed.** On startup block first, unblock only after a _successful_
  non-Russian check. If the IP service or DNS fails, leave existing firewall rules
  untouched. A firewall command that fails must return `Err` and surface in
  status — never a silent `Ok` (this was a real past bug in `macos.rs::pfctl`).
- **Isolated rules.** Only ever touch the `claude_guard` anchor/table/chain. Never
  flush or modify the user's other firewall configuration.
- **Least privilege.** `install.sh` grants passwordless sudo only for the exact
  commands each backend runs. If you change the commands a backend invokes, update
  the matching `sudoers` line in `install.sh` (and `uninstall.sh`) or blocking
  will silently break.
- **`is_blocked()` reflects last successfully-applied state**, and is reconciled
  at startup by re-blocking. The fail-closed path relies on this.

## Conventions

- **Rust:** stable toolchain. `cargo clippy -- -D warnings` must pass clean. No
  `unwrap()` / `expect()` in non-test production paths (`build.rs` and the
  `include_bytes!` icon invariant are the accepted exceptions). Prefer small pure
  helpers that can be unit-tested without a running Tauri app (see
  `IpInfo::classify`, `config::normalize_interval`).
- **TypeScript:** strict mode, no `any`. Types mirror the Rust structs in
  `src/types.ts` (serde `snake_case`).
- **UI:** maintain WCAG 2.2 AA — ARIA roles, focus-visible outlines, contrast in
  both light and dark themes, `prefers-reduced-motion` / `forced-colors` support.
- **Comments:** explain _why_, not _what_. Avoid marketing tone and restating the
  code. Match the density of the surrounding file.

## Commands

```bash
# Frontend
npm install
npm run dev            # vite dev server
npm run build          # tsc + vite build (run this to typecheck)
npm run lint           # ESLint
npm run format         # Prettier (format:check for CI-style verify)

# Rust (from src-tauri/)
cargo test             # unit tests
cargo clippy -- -D warnings
cargo fmt              # format (fmt --check to verify)
cargo build

# Full app
cargo tauri dev        # run the app in dev
cargo tauri build      # produce installers
```

CI (`.github/workflows/ci.yml`) enforces all of the above on push/PR. Before
finishing a change run the checks that apply: `npm run lint`, `npm run format:check`
and `npm run build` for the frontend; `cargo fmt --check`, `cargo clippy -- -D warnings`
and `cargo test` for Rust. Formatting is owned by Prettier and rustfmt — don't fight them.

## Testing notes

Firewall backends touch real system state (`sudo pfctl`/`nft`/`iptables`), so they
aren't unit-tested here — verify those on the actual platform. Cover pure logic
with unit tests instead (country classification, interval clamping, VPN-mode
predicates). Existing tests live in `#[cfg(test)]` modules within each source file.

## Gotchas

- `Config::load` is called fresh each check cycle — settings changes take effect
  without restart (except tray visibility).
- Re-applying `block()` every cycle is intentional: it re-resolves rotating
  Anthropic/CDN IPs. Keep `block()` idempotent.
- Tauri v2 can't relabel a single tray item — the whole menu is rebuilt via
  `build_tray_menu`. Reuse it; don't inline menu construction again.
- The app is menu-bar-only on macOS (`ActivationPolicy::Accessory`); the main
  window starts hidden and toggles from the tray.
