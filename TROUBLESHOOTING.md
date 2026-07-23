# Troubleshooting

## macOS

### "Claude Guard" can't be opened because Apple cannot check it for malicious software

App is unsigned. Fix: right-click the app → **Open** → **Open** in the dialog.
After the first time it opens normally.

Alternatively:

```bash
xattr -dr com.apple.quarantine "/Applications/Claude Guard.app"
```

### Firewall rules not applying / "sudo: pfctl: command not found"

Run `./install.sh` — it sets up the required `sudoers` entry for `pfctl`.
Verify it worked:

```bash
sudo pfctl -a claude_guard -s rules
```

Expected output when blocking is active: lines starting with `block drop out`.

### Notifications not showing

macOS may have blocked notifications for the app. Go to **System Settings → Notifications → Claude Guard** and enable them.

### App not appearing in menu bar

Check **Settings → Show in menu bar** is enabled. Tray visibility changes require a restart.
If the toggle is on and tray is still missing, check Console.app for errors from `claude-guard`.

---

## Linux

### Tray icon not showing on GNOME

GNOME dropped native tray support. You need the AppIndicator extension:

```bash
# Ubuntu / Debian
sudo apt install libayatana-appindicator3-1
# Then install the GNOME extension:
# https://extensions.gnome.org/extension/615/appindicator-support/
```

KDE Plasma and most other DEs work out of the box.

### "nft: command not found" / firewall rules not applying

```bash
# Check what's available:
which nft iptables

# Install nftables (Ubuntu/Debian):
sudo apt install nftables

# Or install iptables:
sudo apt install iptables
```

Run `./install.sh` after installing — it configures `sudoers` for the detected backend.

### Permission denied on firewall commands

`install.sh` must be run after installing the app:

```bash
curl -fsSL https://raw.githubusercontent.com/furtivite/claude-guard/main/install.sh | bash
```

Verify:

```bash
sudo -l | grep nft      # or grep iptables
```

Should show `NOPASSWD` for the firewall command.

### AppImage: FUSE error on startup

```bash
sudo apt install libfuse2
```

---

## Windows

### Firewall rules not applying

The app must be run as Administrator at least once, or the `.msi` must be installed as Administrator.

Verify rules exist:

```powershell
netsh advfirewall firewall show rule name=ClaudeGuard_Block_0
```

### Firewall rules briefly open during update

When the guard updates blocked IPs (e.g. after Anthropic changes their IP addresses),
there is a short window (~100ms) between deleting old rules and applying new ones where
traffic is not blocked. This is a known limitation of `netsh advfirewall` which does not
support atomic rule replacement. The window is small and only occurs during rule updates,
not during normal operation.

### Notifications not showing

Check **Settings → System → Notifications → Claude Guard** and enable them.

---

## All platforms

### "Russian IP detected" but VPN is active

Expected — the app blocks based on actual exit IP, not VPN state. If your VPN is on but the exit IP is still Russian (split tunnelling, leak), the block fires correctly.

Fix: ensure your VPN routes all traffic, not just some destinations.

### IP check fails / "IP check unavailable — rules preserved" shown

`ipinfo.io` is unreachable. The app uses **fail-closed**: existing firewall rules stay in place, nothing changes.

- If you were blocked before the failure → you stay blocked (safe)
- If you were not blocked before the failure → you stay unblocked until next successful check

Verify connectivity:

```bash
curl -sf https://ipinfo.io/json
```

If this returns nothing, try a different network. Once connectivity restores, the next check cycle picks up automatically. Use "Check now" to trigger immediately.

### App shows 🟡 yellow on startup

This is the "Initializing" state — traffic is blocked and the first IP check is in progress. Yellow turns green or red within a few seconds after the check completes.

### Block not lifted after VPN connects

The app checks on a fixed interval (default 30s). Use **Check now** in the UI for an immediate recheck, or lower the interval in Settings.

## Uninstall

```bash
./uninstall.sh
```

Removes firewall rules, sudoers entry, app data. Delete the app bundle manually after.
