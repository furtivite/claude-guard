# VPN detection modes

Claude Guard blocks Anthropic traffic based on your **actual public exit IP**, not
on whether a VPN toggle is on. VPN _detection_ is an optional extra layer: in some
modes, if the app can tell your VPN is down, it blocks immediately without even
waiting for an IP check.

There are three modes, set in **Settings → VPN detection**.

## `ip_only` (default, recommended)

The app ignores VPN state entirely and decides purely from your exit IP:

- Russian exit IP → **block**.
- Non-Russian exit IP → **allow**.

This is the most robust mode because it can't be fooled by a VPN that is
"connected" but leaking, split-tunnelling, or routing only some destinations. If
your exit IP is Russian, you are blocked — full stop.

**Use it for:** Pepper VPN, Harp, manually configured WireGuard, or any setup
where the VPN's exit IP reflects the country you want.

## `port`

Before checking the IP, the app checks whether a **local TCP port** is open
(default `10808`). If the port is closed, it treats the VPN as down and blocks
immediately — the IP service is not queried at all.

This suits local-proxy VPN clients (Happ, Xray, v2ray-style tools) that listen on
a fixed loopback port while connected. It gives a faster, offline-friendly block
the instant the client stops listening.

**Use it for:** Happ / Xray. Set **VPN port** to the port your client listens on.

> If the port is open, the app still verifies the exit IP — an open port alone is
> never treated as "safe".

## `process`

Like `port`, but the app checks whether a **named process** is running instead of
a port. If the process isn't found, the VPN is treated as down and traffic is
blocked immediately.

- On macOS/Linux the check uses `pgrep -x <name>` (exact process name).
- On Windows it scans the `tasklist` output for the name.

**Use it for:** clients that don't expose a predictable local port but always run
a recognisable helper process. Leave the field blank and the mode reports "not
running", i.e. it will always block — so only use this mode with a name filled in.

## Which mode should I use?

| VPN / client       | Recommended mode       | Notes                              |
| ------------------ | ---------------------- | ---------------------------------- |
| Pepper VPN         | `ip_only`              | Exit IP is authoritative           |
| Harp               | `ip_only`              |                                    |
| Happ / Xray        | `port` → `10808`       | Faster block when the client stops |
| WireGuard (manual) | `ip_only` or `process` |                                    |
| Anything else      | `ip_only`              | Safe default                       |

## What "VPN interface" in the UI means

The Status tab shows a detected VPN **interface** (e.g. `utun3`, `wg0`, `tun0`).
This is **informational only** — it does not affect blocking decisions. The app
looks for interfaces named `utun*`, `tun*`, `wg*`, or `ppp*` that have an address,
purely so you can see at a glance whether a tunnel is up.
