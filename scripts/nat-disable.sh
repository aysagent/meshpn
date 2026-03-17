#!/bin/bash
set -e

BACKUP_DIR="$HOME/.mesh-vpn-backup"

echo "=== Mesh VPN NAT Cleanup ==="

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       echo "unknown" ;;
  esac
}

OS=$(detect_os)
echo "Detected OS: $OS"

if [ ! -d "$BACKUP_DIR" ]; then
  echo "Warning: No backup found at $BACKUP_DIR"
  echo "Will remove mesh-vpn rules without restoring original settings"
fi

INTERFACE=""
if [ -f "$BACKUP_DIR/interface" ]; then
  INTERFACE=$(cat "$BACKUP_DIR/interface")
  echo "Interface from backup: $INTERFACE"
fi

if [ "$OS" = "linux" ]; then
  echo ""
  echo "Removing mesh-vpn rules..."
  
  if [ -n "$INTERFACE" ]; then
    sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -o "$INTERFACE" -j MASQUERADE 2>/dev/null && \
      echo "  - NAT MASQUERADE rule removed" || \
      echo "  - NAT MASQUERADE rule not found (already removed?)"
  else
    for iface in eth0 ens3 ens5 enp0s3 wlan0; do
      sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -o "$iface" -j MASQUERADE 2>/dev/null && \
        echo "  - NAT MASQUERADE rule removed (interface: $iface)"
    done
  fi
  
  sudo iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null && \
    echo "  - FORWARD tun+ input rule removed" || true
  
  sudo iptables -D FORWARD -o tun+ -j ACCEPT 2>/dev/null && \
    echo "  - FORWARD tun+ output rule removed" || true
  
  echo ""
  echo "Restoring original settings..."
  
  if [ -f "$BACKUP_DIR/ip_forward" ]; then
    ORIGINAL=$(cat "$BACKUP_DIR/ip_forward")
    sudo sysctl -w net.ipv4.ip_forward="$ORIGINAL" > /dev/null
    echo "  - IP forwarding restored to: $ORIGINAL"
  else
    echo "  - IP forwarding: no backup found, leaving current value"
  fi

elif [ "$OS" = "macos" ]; then
  echo ""
  echo "Removing mesh-vpn rules..."
  
  sudo pfctl -a mesh-vpn -F all 2>/dev/null && \
    echo "  - pf anchor mesh-vpn flushed" || \
    echo "  - pf anchor mesh-vpn not found"
  
  echo ""
  echo "Restoring original settings..."
  
  if [ -f "$BACKUP_DIR/ip_forward" ]; then
    ORIGINAL=$(cat "$BACKUP_DIR/ip_forward")
    sudo sysctl -w net.inet.ip.forwarding="$ORIGINAL" > /dev/null
    echo "  - IP forwarding restored to: $ORIGINAL"
  else
    echo "  - IP forwarding: no backup found, leaving current value"
  fi
  
  if [ -f "$BACKUP_DIR/pf_status" ]; then
    if [ "$(cat $BACKUP_DIR/pf_status)" = "disabled" ]; then
      sudo pfctl -d 2>/dev/null && \
        echo "  - pf disabled (restored to original state)" || true
    else
      echo "  - pf left enabled (was enabled before)"
    fi
  fi

else
  echo "Error: Unsupported OS"
  exit 1
fi

echo ""
read -p "Remove backup files? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -rf "$BACKUP_DIR"
  echo "Backup files removed"
else
  echo "Backup files kept at: $BACKUP_DIR"
fi

echo ""
echo "=== NAT disabled, original settings restored ==="
