# Claude Guard

[![Release](https://img.shields.io/github/v/release/furtivite/claude-guard?style=flat-square&color=4da6ff)](../../releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

Blocks traffic to `api.anthropic.com` and `claude.ai` when your IP is Russian — regardless of VPN state.

## Features

- 🔴 Blocks Anthropic traffic at OS firewall level when Russian IP detected
- 🟢 Auto-unblocks when non-Russian IP confirmed
- 🌍 Shows IP, country, city, provider (via ipinfo.io)
- 📡 Detects VPN interface (utun*, tun*, wg*)
- 🖥 System tray / menu bar icon (macOS, Windows, GNOME)
- ⚡ ~20MB RAM, ~1KB traffic per check
- 🔧 Configurable: VPN mode, check interval, tray toggle

## Platforms

| Platform | Firewall |
|----------|----------|
| macOS | `pfctl` anchor `claude_guard` |
| Linux | `nftables` (autodetect) or `iptables` |
| Windows | `netsh advfirewall` |

## Install

Go to [Releases](../../releases/latest) and download the file for your platform.

| Platform | File | Notes |
|----------|------|-------|
| macOS | `.dmg` | Universal binary — Apple Silicon + Intel |
| Linux | `.deb` or `.AppImage` | |
| Windows | `.msi` | Run as Administrator |

### macOS
1. Open `.dmg`, drag **Claude Guard** to Applications
2. First launch: right-click → **Open** (Gatekeeper workaround for unsigned app)
3. Run once to set firewall permissions:
```bash
# Download and inspect before running — never pipe curl directly to bash
curl -fsSL https://raw.githubusercontent.com/furtivite/claude-guard/main/install.sh -o install.sh
cat install.sh  # verify contents before running
bash install.sh
```

### Linux
```bash
# Download and verify install.sh before running
curl -fsSL https://raw.githubusercontent.com/furtivite/claude-guard/main/install.sh -o install.sh
cat install.sh

# deb
sudo dpkg -i claude-guard_*.deb && bash install.sh

# AppImage
chmod +x claude-guard_*.AppImage && bash install.sh && ./claude-guard_*.AppImage
```

### Windows
Run `.msi` as Administrator. Firewall rules are configured automatically on first launch.

---

## Build from source

Only needed if you want to modify the code.

```bash
# Prerequisites: Rust, Node.js 18+, Tauri CLI v2
cargo install tauri-cli --version "^2"

git clone https://github.com/furtivite/claude-guard
cd claude-guard
cp /path/to/icon.png src-tauri/icons/icon.png
cargo tauri icon src-tauri/icons/icon.png
./install.sh
npm install
cargo tauri build
```

## Dev mode

```bash
npm install
cargo tauri dev
```

## Uninstall

```bash
./uninstall.sh
```

Removes: firewall rules, sudoers entry, app data. Delete the folder manually after.

## Configuration

Settings are stored in the app UI (Settings tab):

| Setting | Default | Description |
|---------|---------|-------------|
| VPN mode | `ip_only` | How to detect VPN: `ip_only`, `port`, `process` |
| VPN port | `10808` | Port to check (Happ/Xray mode) |
| VPN process | — | Process name to check |
| Check interval | `30s` | How often to check IP |
| Show in tray | `true` | Menu bar / system tray icon |
| Enabled | `true` | Master on/off switch |

## VPN mode guide

| VPN | Recommended mode |
|-----|-----------------|
| Pepper VPN | `ip_only` |
| Harp | `ip_only` |
| Happ / Xray | `port` → 10808 |
| Wireguard (manual) | `ip_only` or `process` |

## Need help?

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues.
Want to contribute? See [CONTRIBUTING.md](CONTRIBUTING.md).

## Logging

Logs go to stderr and are only visible when running from terminal or via Console.app (macOS).

```bash
RUST_LOG=info ./claude-guard      # normal operation
RUST_LOG=debug ./claude-guard     # verbose — includes IP addresses from ipinfo.io
```

Do not use `RUST_LOG=debug` on shared machines — IP addresses appear in output.

## Fail-safe behavior

- If `ipinfo.io` is unreachable → **existing firewall rules are preserved** (fail-closed)
- IP result is cached 60 seconds — no excess traffic
- Firewall anchor is isolated — system rules are never touched
