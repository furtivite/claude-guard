#!/usr/bin/env bash
# Claude Guard — first-time firewall sudo setup
set -euo pipefail

echo "=== Claude Guard — Setup ==="
echo ""

OS="$(uname -s)"

case "$OS" in
  Darwin)
    echo "Platform: macOS"
    DEFAULT_USER="${SUDO_USER:-$(whoami)}"
    read -rp "Grant firewall access to user [$DEFAULT_USER]: " USERNAME
    USERNAME="${USERNAME:-$DEFAULT_USER}"
    id "$USERNAME" &>/dev/null || { echo "User '$USERNAME' not found"; exit 1; }

    # NOPASSWD is scoped to the exact pfctl invocations the app makes on the
    # 'claude_guard' anchor. This deliberately does NOT grant blanket pfctl access:
    # e.g. `sudo pfctl -F all` (flush the whole system firewall) is not permitted.
    sudo tee /etc/sudoers.d/claude-guard > /dev/null << EOF
$USERNAME ALL=(root) NOPASSWD: /sbin/pfctl -a claude_guard -f -, /sbin/pfctl -e, /sbin/pfctl -a claude_guard -F all
EOF
    sudo chmod 440 /etc/sudoers.d/claude-guard
    sudo visudo -cf /etc/sudoers.d/claude-guard >/dev/null \
      || { echo "sudoers validation failed — removing"; sudo rm -f /etc/sudoers.d/claude-guard; exit 1; }
    echo "✓ sudoers configured (pfctl, scoped to the claude_guard anchor)"
    ;;

  Linux)
    echo "Platform: Linux"
    DEFAULT_USER="${SUDO_USER:-$(whoami)}"
    read -rp "Grant firewall access to user [$DEFAULT_USER]: " USERNAME
    USERNAME="${USERNAME:-$DEFAULT_USER}"
    id "$USERNAME" &>/dev/null || { echo "User '$USERNAME' not found"; exit 1; }

    if command -v nft &>/dev/null; then
      echo "  Firewall: nftables"
      # Scoped to the claude_guard table where possible. NOTE: `nft -f -` reads a
      # ruleset from stdin, so this line still allows loading an arbitrary ruleset.
      # Fully constraining it needs a root-owned helper wrapper (see CONTRIBUTING).
      sudo tee /etc/sudoers.d/claude-guard > /dev/null << EOF
$USERNAME ALL=(root) NOPASSWD: /usr/sbin/nft --version, /usr/sbin/nft -f -, /usr/sbin/nft delete table inet claude_guard
EOF
    else
      echo "  Firewall: iptables"
      # Scoped to the CLAUDE_GUARD chain — the system's other chains are untouched.
      sudo tee /etc/sudoers.d/claude-guard > /dev/null << EOF
$USERNAME ALL=(root) NOPASSWD: /sbin/iptables -N CLAUDE_GUARD, /sbin/iptables -I OUTPUT -j CLAUDE_GUARD, /sbin/iptables -A CLAUDE_GUARD *, /sbin/iptables -D OUTPUT -j CLAUDE_GUARD, /sbin/iptables -F CLAUDE_GUARD, /sbin/iptables -X CLAUDE_GUARD
EOF
    fi
    sudo chmod 440 /etc/sudoers.d/claude-guard
    command -v visudo &>/dev/null && { sudo visudo -cf /etc/sudoers.d/claude-guard >/dev/null \
      || { echo "sudoers validation failed — removing"; sudo rm -f /etc/sudoers.d/claude-guard; exit 1; }; }
    echo "✓ sudoers configured (firewall commands scoped to claude_guard)"

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
