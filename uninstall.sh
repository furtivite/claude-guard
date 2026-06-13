#!/usr/bin/env bash
# Claude Guard — full uninstall
set -euo pipefail

echo "=== Claude Guard — Uninstall ==="

OS="$(uname -s)"

case "$OS" in
  Darwin)
    # Clear PF rules
    sudo pfctl -a claude_guard -F rules 2>/dev/null && echo "✓ PF rules cleared" || true
    # Remove sudoers entry
    sudo rm -f /etc/sudoers.d/claude-guard && echo "✓ sudoers entry removed"
    # Remove legacy LaunchAgent if present
    rm -f "$HOME/Library/LaunchAgents/sh.claudeguard.plist" 2>/dev/null || true
    # Remove app bundle
    if [[ -d "/Applications/Claude Guard.app" ]]; then
      read -rp "Remove /Applications/Claude Guard.app? [Y/n]: " RM_APP
      RM_APP="${RM_APP:-Y}"
      [[ "$RM_APP" =~ ^[Yy]$ ]] && rm -rf "/Applications/Claude Guard.app" && echo "✓ App removed"
    fi
    # Remove app data
    rm -rf "$HOME/Library/Application Support/sh.claudeguard" 2>/dev/null || true
    ;;

  Linux)
    # Clear nftables rules
    sudo nft delete table inet claude_guard 2>/dev/null && echo "✓ nft table removed" || true
    # Clear iptables rules
    sudo iptables -D OUTPUT -j CLAUDE_GUARD 2>/dev/null || true
    sudo iptables -F CLAUDE_GUARD 2>/dev/null || true
    sudo iptables -X CLAUDE_GUARD 2>/dev/null && echo "✓ iptables chain removed" || true
    # Remove sudoers entry
    sudo rm -f /etc/sudoers.d/claude-guard && echo "✓ sudoers entry removed"
    # Remove app data
    rm -rf "$HOME/.local/share/sh.claudeguard" 2>/dev/null || true
    ;;

  *)
    echo "Windows: remove firewall rules manually or run as Administrator:"
    echo "  netsh advfirewall firewall delete rule name=ClaudeGuard_Block_*"
    ;;
esac

echo ""
echo "=== Uninstall complete. Remove the app folder manually. ==="
