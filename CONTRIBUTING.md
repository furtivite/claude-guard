# Contributing

## Before you start

Open an issue first if you're planning a non-trivial change — saves time for both sides.

## Setup

```bash
git clone https://github.com/your-username/claude-guard
cd claude-guard
cp /path/to/icon.png src-tauri/icons/icon.png
cargo tauri icon src-tauri/icons/icon.png
./install.sh
npm install
cargo tauri dev
```

## Project structure

```
src/                    React UI
src-tauri/src/
  main.rs               Tauri entry, tray, commands
  guard.rs              Main loop, block/unblock logic
  ip_checker.rs         ipinfo.io client + 60s cache
  vpn_detector.rs       VPN interface detection
  firewall/
    macos.rs            pfctl anchor
    linux.rs            nftables / iptables autodetect
    windows.rs          netsh advfirewall
```

## Guidelines

**Rust:** stable toolchain, `cargo clippy` must pass clean, no `unwrap()` in production paths.

**TypeScript:** strict mode, no `any`.

**Firewall changes:** test on the actual platform. A bug here blocks real traffic — treat with care. If you're adding a new firewall backend, implement the `Firewall` trait in `firewall/mod.rs` and add platform detection logic there.

**IP detection:** don't add alternative IP services without a fallback strategy. The current fail-open behaviour (no block if service unreachable) is intentional.

**UI:** keep WCAG 2.2 AA compliance — contrast ratios, focus indicators, ARIA roles. Check both light and dark themes.

## Pull request checklist

- [ ] Tested on the affected platform
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] No new `unwrap()` / `expect()` in non-test code
- [ ] WCAG compliance maintained if UI changed
- [ ] README / TROUBLESHOOTING updated if behaviour changed
