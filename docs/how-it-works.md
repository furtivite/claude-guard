# How it works

Claude Guard is a small [Tauri](https://tauri.app) app: a Rust core that manages
the firewall and a React UI that shows status and settings. This page explains the
runtime behaviour so you can reason about what the app does — and, just as
importantly, what it does not.

## The check loop

A single background loop drives everything:

1. On startup, if protection is enabled, the app **blocks first** and shows the
   🟡 _Initializing_ state.
2. Every _check interval_ seconds (default 30) it runs a check:
   - In `port` / `process` [VPN mode](vpn-modes.md), if the VPN looks down, it
     blocks immediately and skips the IP lookup.
   - Otherwise it fetches the current exit IP from
     [`ipinfo.io`](https://ipinfo.io) (cached for 60 s) and blocks if the country
     is Russia (`RU`), unblocks otherwise.
3. Whenever the decision changes, it updates the tray tooltip and sends a
   notification (🔴 blocked / 🟢 restored).

Pressing **Check now** invalidates the IP cache and runs a check immediately.

## Fail-closed by design

The app errs on the side of blocking:

- **Startup:** blocked until the first _successful_ non-Russian check.
- **IP service unreachable:** existing firewall rules are left exactly as they are.
  If you were blocked, you stay blocked; if you were allowed, you stay allowed
  until the next successful check. The UI shows _IP check unavailable — rules
  preserved_.
- **DNS resolution fails (Linux/Windows):** the app refuses to install an empty
  blocklist rather than risk a false "allow".
- **Firewall command fails:** the error surfaces in status instead of being
  silently swallowed, so a broken block never looks like a successful one.

## Firewall backends

All rules live in an **isolated** container named `claude_guard`, so the app never
touches your other firewall configuration.

| Platform | Backend                              | Mechanism                                                                                   |
| -------- | ------------------------------------ | ------------------------------------------------------------------------------------------- |
| macOS    | `pfctl`                              | A dedicated PF anchor `claude_guard` with FQDN-based `block drop out` rules                 |
| Linux    | `nftables` (preferred) or `iptables` | A `claude_guard` table / `CLAUDE_GUARD` chain dropping outbound packets to the resolved IPs |
| Windows  | `netsh advfirewall`                  | Outbound block rules named `ClaudeGuard_*` for the resolved IPs                             |

On every block the app re-resolves the target domains, so rotating Anthropic /
Cloudflare IPs are picked up within one check cycle.

## Privacy

- The only network request is to `ipinfo.io` to read your own public IP and
  country. Nothing else leaves your machine.
- The request bypasses any system proxy (`no_proxy`) so the _real_ exit IP is
  checked, and validates TLS against the bundled Mozilla root store only — a
  corporate or antivirus CA installed on the machine cannot MITM the lookup.
- IP details are shown in the UI but only written to logs at `RUST_LOG=debug`.
  Don't use debug logging on shared machines.

## Limitations

Understanding these matters for a security tool — it is defence-in-depth, not an
airtight guarantee.

- **IP-based blocking.** Rules target the IP addresses the Anthropic domains
  resolve to _at block time_. Anthropic sits behind a CDN with a large, rotating
  address pool, so a connection resolving to an edge IP not yet in the blocklist
  can slip through until the next cycle re-resolves it. This is best-effort.
- **Trusts the local DNS resolver.** If your network hijacks DNS for these
  domains, the blocklist targets the wrong IPs.
- **Brief window on rule updates.** On Windows (and to a lesser extent Linux),
  refreshing rules deletes the old ones before adding new ones — a sub-second gap
  where traffic isn't blocked. It only occurs during updates, not steady state.
- **`nft -f -` sudo scope.** The nftables path is granted passwordless `sudo` for
  `nft -f -`, which reads a ruleset from stdin and is therefore broader than the
  tightly-scoped `pfctl` / `iptables` grants. Fully constraining it needs a
  root-owned helper wrapper; this is tracked as a follow-up in
  [CONTRIBUTING.md](../CONTRIBUTING.md).

## Source map

For contributors, the moving parts are:

```
src-tauri/src/
  main.rs            Tauri entry point, tray, IPC commands
  guard.rs           The check loop and block/unblock decisions
  config.rs          Settings: store keys, defaults, validation
  ip_checker.rs      ipinfo.io client + 60 s cache
  vpn_detector.rs    VPN mode / interface detection
  firewall/
    mod.rs           `Firewall` trait + platform selector
    macos.rs         pfctl anchor
    linux.rs         nftables / iptables
    windows.rs       netsh advfirewall
src/                 React UI (status + settings)
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for build and development instructions.
