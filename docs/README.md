# Claude Guard — Documentation

Full user guide for Claude Guard, a small desktop app that blocks traffic to
`api.anthropic.com` and `claude.ai` at the OS firewall level whenever your public
IP is Russian — regardless of VPN state.

## Contents

| Guide                                     | What it covers                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------------- |
| [Installation](installation.md)           | Step-by-step install for macOS, Linux and Windows, plus the one-time firewall setup |
| [Configuration](configuration.md)         | Every setting explained, where settings are stored, and sensible defaults           |
| [VPN modes](vpn-modes.md)                 | How VPN detection works and which mode to pick for your VPN                         |
| [How it works](how-it-works.md)           | The check loop, fail-closed behaviour, firewall backends, and known limitations     |
| [Troubleshooting](../TROUBLESHOOTING.md)  | Fixes for the most common problems, per platform                                    |
| [Uninstalling](installation.md#uninstall) | Removing the app, firewall rules, and the sudoers entry                             |

## In one minute

1. **Install** the app for your platform ([details](installation.md)).
2. **Run the one-time firewall setup** (`install.sh` on macOS/Linux, run as
   Administrator on Windows) so the app can manage firewall rules without a
   password prompt on every check.
3. **Open the app** and toggle **Enable protection**.
4. That's it. The app checks your IP every 30 seconds. If it sees a Russian IP,
   Anthropic traffic is blocked at the firewall until a non-Russian IP is
   confirmed.

## Safety model at a glance

- **Fail-closed.** On startup the app blocks first and only unblocks after a
  successful, non-Russian IP check. If the IP service is unreachable, existing
  firewall rules are left untouched.
- **Isolated rules.** All firewall changes live in a dedicated anchor/table/chain
  named `claude_guard`. The app never edits your other firewall rules.
- **Least privilege.** The installer grants passwordless `sudo` only for the exact
  firewall commands the app runs — not blanket firewall access.

See [How it works](how-it-works.md) for the full picture, including limitations.
