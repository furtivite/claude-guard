# Configuration

All settings live in the app's **Settings** tab. There is no config file to edit
by hand — changes are saved to the app's store and picked up on the next check
cycle.

## Settings reference

| Setting                     | Default   | Range                          | Description                                                                     |
| --------------------------- | --------- | ------------------------------ | ------------------------------------------------------------------------------- |
| **Enable protection**       | off       | on / off                       | Master switch. When off, the app removes its firewall rules and stops blocking. |
| **Show in menu bar / tray** | on        | on / off                       | Shows the tray / menu-bar icon. Changes take effect after a restart.            |
| **VPN detection mode**      | `ip_only` | `ip_only` / `port` / `process` | How the app decides whether your VPN is up. See [VPN modes](vpn-modes.md).      |
| **VPN port**                | `10808`   | 1–65535                        | Local port checked in `port` mode (e.g. Happ / Xray).                           |
| **VPN process**             | —         | any name                       | Process name checked in `process` mode.                                         |
| **Check interval**          | `30` s    | 10–300 s                       | How often the IP is checked. Values below 10 s are clamped to 10 s.             |

Notes:

- **Enable protection** and **Show in menu bar** apply immediately. The other
  settings apply when you press **Save settings**.
- The **VPN port** and **VPN process** fields only appear when the matching mode
  is selected.
- The interval is enforced at a minimum of **10 seconds** even if a smaller value
  is stored, to avoid hammering the IP service.

## Where settings are stored

Settings persist in a small JSON store managed by the app:

| Platform | Path                                                         |
| -------- | ------------------------------------------------------------ |
| macOS    | `~/Library/Application Support/sh.claudeguard/settings.json` |
| Linux    | `~/.local/share/sh.claudeguard/settings.json`                |
| Windows  | `%APPDATA%\sh.claudeguard\settings.json`                     |

You normally never touch this file — edit settings in the app. The app only reads
a known set of keys (`enabled`, `check_interval`, `show_tray`, `vpn_mode`,
`vpn_port`, `vpn_process`); anything else in the file is ignored.

## Startup behaviour

- If **Enable protection** was on when you last quit, the app blocks immediately
  on launch (state 🟡 _Initializing_) and only unblocks once a successful
  non-Russian IP check completes.
- If it was off, the app starts unblocked and idle until you enable it.

## Recommended settings

- **Most users:** leave everything at defaults. `ip_only` mode plus a 30-second
  interval is the right balance for VPNs whose exit IP reflects your real
  location (Pepper VPN, Harp, most WireGuard setups).
- **Happ / Xray users:** switch to `port` mode and set the port your client
  listens on (10808 by default). See [VPN modes](vpn-modes.md) for why.
- **Battery-sensitive laptops:** raising the interval to 60 s roughly halves the
  background checks at the cost of a slightly slower reaction to IP changes. Use
  **Check now** for an on-demand recheck any time.
