#!/usr/bin/env bash
# Claude Guard — полное удаление
set -euo pipefail

echo "=== Claude Guard — Uninstall ==="

OS="$(uname -s)"

case "$OS" in
  Darwin)
    # Снять PF правила
    sudo pfctl -a claude_guard -F rules 2>/dev/null && echo "✓ PF rules cleared" || true
    # Удалить sudoers
    sudo rm -f /etc/sudoers.d/claude-guard && echo "✓ sudoers entry removed"
    # Удалить LaunchAgent если остался от старой версии
    rm -f "$HOME/Library/LaunchAgents/sh.claudeguard.plist" 2>/dev/null || true
    # Удалить app bundle
    if [[ -d "/Applications/Claude Guard.app" ]]; then
      read -rp "Remove /Applications/Claude Guard.app? [Y/n]: " RM_APP
      RM_APP="${RM_APP:-Y}"
      [[ "$RM_APP" =~ ^[Yy]$ ]] && rm -rf "/Applications/Claude Guard.app" && echo "✓ App removed"
    fi
    # Удалить store данные
    rm -rf "$HOME/Library/Application Support/sh.claudeguard" 2>/dev/null || true
    ;;

  Linux)
    # nftables
    sudo nft delete table inet claude_guard 2>/dev/null && echo "✓ nft table removed" || true
    # iptables
    sudo iptables -D OUTPUT -j CLAUDE_GUARD 2>/dev/null || true
    sudo iptables -F CLAUDE_GUARD 2>/dev/null || true
    sudo iptables -X CLAUDE_GUARD 2>/dev/null && echo "✓ iptables chain removed" || true
    # sudoers
    sudo rm -f /etc/sudoers.d/claude-guard && echo "✓ sudoers entry removed"
    # store
    rm -rf "$HOME/.local/share/sh.claudeguard" 2>/dev/null || true
    ;;

  *)
    echo "Windows: remove firewall rules manually or run as Administrator:"
    echo "  netsh advfirewall firewall delete rule name=ClaudeGuard_Block_*"
    ;;
esac

echo ""
echo "=== Uninstall complete. Remove the app folder manually. ==="
