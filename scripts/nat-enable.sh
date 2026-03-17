#!/bin/bash
set -e

BACKUP_DIR="$HOME/.mesh-vpn-backup"
INTERFACE="${1:-}"

echo "=== Mesh VPN NAT Setup ==="

mkdir -p "$BACKUP_DIR"

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       echo "unknown" ;;
  esac
}

detect_interface() {
  local os=$1
  if [ "$os" = "linux" ]; then
    ip route | grep default | awk '{print $5}' | head -1
  else
    route -n get default 2>/dev/null | grep interface | awk '{print $2}'
  fi
}

OS=$(detect_os)
echo "Detected OS: $OS"

if [ -z "$INTERFACE" ]; then
  INTERFACE=$(detect_interface "$OS")
fi

if [ -z "$INTERFACE" ]; then
  echo "Error: Could not detect network interface. Please specify: $0 <interface>"
  exit 1
fi

echo "Using network interface: $INTERFACE"

if [ "$OS" = "linux" ]; then
  echo ""
  echo "Saving current settings..."
  
  cat /proc/sys/net/ipv4/ip_forward > "$BACKUP_DIR/ip_forward"
  echo "  - IP forwarding: $(cat $BACKUP_DIR/ip_forward)"
  
  sudo iptables-save > "$BACKUP_DIR/iptables.rules"
  echo "  - iptables rules saved"
  
  echo "$INTERFACE" > "$BACKUP_DIR/interface"
  
  echo ""
  echo "Enabling NAT..."
  
  sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
  echo "  - IP forwarding enabled"
  
  if ! sudo iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -o "$INTERFACE" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o "$INTERFACE" -j MASQUERADE
    echo "  - NAT MASQUERADE rule added"
  else
    echo "  - NAT MASQUERADE rule already exists"
  fi
  
  if ! sudo iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null; then
    sudo iptables -A FORWARD -i tun+ -j ACCEPT
    echo "  - FORWARD tun+ input rule added"
  fi
  
  if ! sudo iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null; then
    sudo iptables -A FORWARD -o tun+ -j ACCEPT
    echo "  - FORWARD tun+ output rule added"
  fi

elif [ "$OS" = "macos" ]; then
  echo ""
  echo "Saving current settings..."
  
  sysctl -n net.inet.ip.forwarding > "$BACKUP_DIR/ip_forward"
  echo "  - IP forwarding: $(cat $BACKUP_DIR/ip_forward)"
  
  sudo pfctl -s nat > "$BACKUP_DIR/pf_nat.rules" 2>/dev/null || echo "" > "$BACKUP_DIR/pf_nat.rules"
  echo "  - pf NAT rules saved"
  
  sudo pfctl -s rules > "$BACKUP_DIR/pf_filter.rules" 2>/dev/null || echo "" > "$BACKUP_DIR/pf_filter.rules"
  echo "  - pf filter rules saved"
  
  if sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    echo "enabled" > "$BACKUP_DIR/pf_status"
  else
    echo "disabled" > "$BACKUP_DIR/pf_status"
  fi
  echo "  - pf status: $(cat $BACKUP_DIR/pf_status)"
  
  echo "$INTERFACE" > "$BACKUP_DIR/interface"
  
  echo ""
  echo "Enabling NAT..."
  
  sudo sysctl -w net.inet.ip.forwarding=1 > /dev/null
  echo "  - IP forwarding enabled"
  
  TEMP_PF=$(mktemp)
  echo "nat on $INTERFACE from 10.200.0.0/16 to any -> ($INTERFACE)" > "$TEMP_PF"
  
  sudo pfctl -a mesh-vpn -f "$TEMP_PF" 2>/dev/null || sudo pfctl -ef "$TEMP_PF" 2>/dev/null
  rm -f "$TEMP_PF"
  echo "  - NAT rule added via pf"
  
  sudo pfctl -e 2>/dev/null || true
  echo "  - pf enabled"

else
  echo "Error: Unsupported OS"
  exit 1
fi

echo ""
echo "=== NAT enabled successfully ==="
echo "Backup saved to: $BACKUP_DIR"
echo ""
echo "To disable NAT and restore settings, run:"
echo "  npm run nat:disable"
