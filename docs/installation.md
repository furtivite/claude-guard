# Installation

Claude Guard ships as a native installer per platform. After installing the app
you run a **one-time firewall setup** so it can add and remove firewall rules
without asking for your password on every check.

- [Download](#download)
- [macOS](#macos)
- [Linux](#linux)
- [Windows](#windows)
- [What the setup grants](#what-the-setup-grants)
- [Uninstall](#uninstall)

## Download

Grab the file for your platform from the
[latest release](https://github.com/furtivite/claude-guard/releases/latest):

| Platform | File                  | Notes                                    |
| -------- | --------------------- | ---------------------------------------- |
| macOS    | `.dmg`                | Universal binary — Apple Silicon + Intel |
| Linux    | `.deb` or `.AppImage` |                                          |
| Windows  | `.msi`                | Install as Administrator                 |

> **On the install script.** `install.sh` needs `sudo` to write a `sudoers` entry.
> Never pipe it straight into a shell — download it, read it, then run it. Every
> command below follows that pattern.

## macOS

1. Open the `.dmg` and drag **Claude Guard** to **Applications**.
2. First launch only: the app is unsigned, so right-click it → **Open** →
   **Open** in the Gatekeeper dialog. After the first launch it opens normally.
   (Alternative: `xattr -dr com.apple.quarantine "/Applications/Claude Guard.app"`.)
3. Run the one-time firewall setup:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/furtivite/claude-guard/main/install.sh -o install.sh
   cat install.sh      # read it before running
   bash install.sh     # prompts for your macOS user, writes the sudoers entry
   ```

4. Open the app and toggle **Enable protection**.

Verify the firewall rule is present while blocking is active:

```bash
sudo pfctl -a claude_guard -s rules
# expect lines starting with: block drop out
```

## Linux

1. Install the package:

   ```bash
   # Download and read the setup script first
   curl -fsSL https://raw.githubusercontent.com/furtivite/claude-guard/main/install.sh -o install.sh
   cat install.sh

   # .deb
   sudo dpkg -i claude-guard_*.deb && bash install.sh

   # .AppImage
   chmod +x claude-guard_*.AppImage && bash install.sh && ./claude-guard_*.AppImage
   ```

2. `install.sh` detects your firewall backend (`nftables` preferred, `iptables`
   fallback) and writes a matching `sudoers` entry. On Debian/Ubuntu it also
   offers to install `libayatana-appindicator3-1` for tray support on GNOME.

Verify the `sudoers` entry:

```bash
sudo -l | grep -E 'nft|iptables'   # should show NOPASSWD for the firewall command
```

> **GNOME tray:** GNOME dropped native tray support. Install the
> [AppIndicator extension](https://extensions.gnome.org/extension/615/appindicator-support/)
> if the menu-bar icon does not appear. KDE and most other desktops work as-is.

## Windows

1. Run the `.msi` **as Administrator**. Firewall rules are configured
   automatically on first launch — there is no separate setup script.
2. If you skipped the elevation prompt, right-click the installed app →
   **Run as administrator** once so it can create the firewall rules.

Verify a rule exists while blocking is active:

```powershell
netsh advfirewall firewall show rule name=ClaudeGuard_0
```

## What the setup grants

The setup does **not** hand the app blanket firewall access. It grants
passwordless `sudo` only for the specific commands the app runs, scoped to the
`claude_guard` anchor/table/chain:

| Platform         | Granted commands                                                         |
| ---------------- | ------------------------------------------------------------------------ |
| macOS            | `pfctl -a claude_guard -f -`, `pfctl -e`, `pfctl -a claude_guard -F all` |
| Linux (nftables) | `nft --version`, `nft -f -`, `nft delete table inet claude_guard`        |
| Linux (iptables) | `iptables` operations on the `CLAUDE_GUARD` chain only                   |
| Windows          | None — the app runs firewall commands under its own elevation            |

`sudo pfctl -F all` (flushing the whole system firewall) is **not** granted. The
one broad exception is `nft -f -`, which reads a ruleset from stdin; see
[How it works → Limitations](how-it-works.md#limitations) for the reasoning and
the planned tightening.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/furtivite/claude-guard/main/uninstall.sh -o uninstall.sh
cat uninstall.sh
bash uninstall.sh
```

`uninstall.sh` removes:

- the firewall rules (PF anchor / nftables table / iptables chain),
- the `sudoers` entry (`/etc/sudoers.d/claude-guard`),
- app data (`~/Library/Application Support/sh.claudeguard` on macOS,
  `~/.local/share/sh.claudeguard` on Linux).

Delete the app bundle / binary manually afterwards. On Windows, uninstall via
**Settings → Apps**, then remove any leftover rules:

```powershell
Get-NetFirewallRule -DisplayName 'ClaudeGuard_*' | Remove-NetFirewallRule
```
