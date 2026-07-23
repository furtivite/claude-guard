# Contributing

## Before you start

Open an issue first if you're planning a non-trivial change — saves time for both sides.

## Setup

```bash
git clone https://github.com/furtivite/claude-guard
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

**IP detection:** don't add alternative IP services without a fallback strategy. The current fail-closed behaviour (existing rules preserved if service unreachable) is intentional.

**`sudo` scope (help wanted):** `install.sh` grants `NOPASSWD` scoped to the exact firewall commands per backend. The nftables path still allows `nft -f -` (arbitrary ruleset via stdin), which is broader than we'd like. The intended fix is a small root-owned helper wrapper (installed to e.g. `/usr/local/bin/claude-guard-fw`) that hardcodes the table/chain names and accepts only IP arguments; `install.sh` would then grant `NOPASSWD` for the wrapper alone, and `firewall/linux.rs` would call it instead of `nft`/`iptables` directly.

**UI:** keep WCAG 2.2 AA compliance — contrast ratios, focus indicators, ARIA roles. Check both light and dark themes.

## Linting & formatting

CI runs these on every push and PR (`.github/workflows/ci.yml`) — run them locally before pushing.

```bash
# Frontend (from repo root)
npm run lint          # ESLint
npm run format:check  # Prettier (use `npm run format` to auto-fix)
npm run build         # tsc typecheck + vite build

# Rust (from repo root)
cargo fmt --manifest-path src-tauri/Cargo.toml            # format
cargo fmt --manifest-path src-tauri/Cargo.toml --check    # CI check
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

Formatting is owned by Prettier (TS/CSS/JSON/Markdown) and rustfmt (Rust) — don't
hand-format against them. Config lives in `.prettierrc.json`, `eslint.config.js`,
`rustfmt.toml`, and `.editorconfig`.

## Pull request checklist

- [ ] Tested on the affected platform
- [ ] `npm run lint` and `npm run format:check` pass
- [ ] `cargo fmt --manifest-path src-tauri/Cargo.toml --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] No new `unwrap()` / `expect()` in non-test code
- [ ] WCAG compliance maintained if UI changed
- [ ] README / TROUBLESHOOTING updated if behaviour changed
