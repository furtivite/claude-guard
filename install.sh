#!/usr/bin/env bash
# Claude Guard — first-time firewall sudo setup
set -euo pipefail

echo "=== Claude Guard — Setup ==="
echo ""

OS="$(uname -s)"

case "$OS" in
  Darwin)
    echo "Platform: macOS"
    read -rp "Your macOS username (whoami): " USERNAME
    [[ -z "$USERNAME" ]] && { echo "Username required"; exit 1; }
    id "$USERNAME" &>/dev/null || { echo "User '$USERNAME' not found"; exit 1; }

    sudo tee /etc/sudoers.d/claude-guard > /dev/null << EOF
$USERNAME ALL=(root) NOPASSWD: /sbin/pfctl
EOF
    sudo chmod 440 /etc/sudoers.d/claude-guard
    echo "✓ sudoers configured for pfctl"
    ;;

  Linux)
    echo "Platform: Linux"
    read -rp "Your Linux username (whoami): " USERNAME
    [[ -z "$USERNAME" ]] && { echo "Username required"; exit 1; }

    if command -v nft &>/dev/null; then
      FW_CMD="/usr/sbin/nft"
      echo "  Firewall: nftables"
    else
      FW_CMD="/sbin/iptables"
      echo "  Firewall: iptables"
    fi

    sudo tee /etc/sudoers.d/claude-guard > /dev/null << EOF
$USERNAME ALL=(root) NOPASSWD: $FW_CMD
EOF
    sudo chmod 440 /etc/sudoers.d/claude-guard
    echo "✓ sudoers configured for $FW_CMD"

    # AppIndicator for GNOME tray support
    if command -v apt-get &>/dev/null; then
      echo ""
      read -rp "Install libayatana-appindicator3 for GNOME tray? [Y/n]: " INST
      INST="${INST:-Y}"
      if [[ "$INST" =~ ^[Yy]$ ]]; then
        sudo apt-get install -y libayatana-appindicator3-1
        echo "✓ AppIndicator installed"
      fi
    fi
    ;;

  *)
    echo "Windows: run the app as Administrator on first launch."
    echo "Windows Firewall rules are applied via netsh advfirewall."
    ;;
esac

echo ""
echo "=== Setup complete. Launch Claude Guard. ==="
