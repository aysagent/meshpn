#!/bin/bash

set -e

echo "=== Mesh VPN macOS Setup ==="

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (sudo)"
    exit 1
fi

ROLE=${1:-client}
INTERFACE=${2:-en0}
VIRTUAL_NETWORK="10.200.0.0/16"

echo "Role: $ROLE"
echo "External interface: $INTERFACE"

echo ""
echo "=== Enabling IP forwarding ==="
sysctl -w net.inet.ip.forwarding=1
sysctl -w net.inet.ip.fw.enable=1 2>/dev/null || true

echo ""
echo "=== Creating pf.conf rules ==="

PF_CONF="/etc/pf.anchors/mesh-vpn"
cat > $PF_CONF << EOF
# Mesh VPN pf rules

# Allow traffic on utun interfaces
pass quick on utun0 all
pass quick on utun1 all
pass quick on utun2 all

EOF

if [ "$ROLE" = "exit" ]; then
    echo "Configuring NAT for exit node..."
    
    cat >> $PF_CONF << EOF
# NAT for exit node
nat on $INTERFACE from $VIRTUAL_NETWORK to any -> ($INTERFACE)

EOF
fi

echo ""
echo "=== Configuring pf ==="

if ! grep -q "mesh-vpn" /etc/pf.conf 2>/dev/null; then
    cat >> /etc/pf.conf << EOF

# Mesh VPN
anchor "mesh-vpn"
load anchor "mesh-vpn" from "/etc/pf.anchors/mesh-vpn"
EOF
fi

echo ""
echo "=== Enabling pf ==="
pfctl -ef /etc/pf.conf 2>/dev/null || pfctl -f /etc/pf.conf

echo ""
echo "=== Setup complete ==="
echo ""
echo "To start the mesh VPN node:"
echo "  sudo node src/index.js --role $ROLE"
echo ""
echo "Note: On macOS, TUN interfaces (utun) are created automatically by the system."
echo "The application will request the creation of a utun interface when it starts."
echo ""
if [ "$ROLE" = "exit" ]; then
    echo "This exit node will NAT traffic from $VIRTUAL_NETWORK through $INTERFACE"
fi

echo ""
echo "=== Additional macOS notes ==="
echo ""
echo "To manually add a route to the VPN network:"
echo "  sudo route add -net 10.200.0.0/16 -interface utun0"
echo ""
echo "To check the utun interfaces:"
echo "  ifconfig | grep utun"
echo ""
echo "To view NAT translations:"
echo "  sudo pfctl -s nat"
