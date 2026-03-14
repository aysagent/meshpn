#!/bin/bash

set -e

echo "=== Mesh VPN Linux Setup ==="

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (sudo)"
    exit 1
fi

ROLE=${1:-client}
INTERFACE=${2:-eth0}
TUN_NAME=${3:-tun0}
VIRTUAL_NETWORK="10.200.0.0/16"

echo "Role: $ROLE"
echo "External interface: $INTERFACE"
echo "TUN interface: $TUN_NAME"

echo ""
echo "=== Enabling IP forwarding ==="
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf 2>/dev/null || true
sysctl -p 2>/dev/null || true

echo ""
echo "=== Installing dependencies ==="
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y iptables iproute2
elif command -v yum &> /dev/null; then
    yum install -y iptables iproute
elif command -v dnf &> /dev/null; then
    dnf install -y iptables iproute
fi

echo ""
echo "=== Creating TUN device ==="
if [ ! -d /dev/net ]; then
    mkdir -p /dev/net
fi

if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
    chmod 0666 /dev/net/tun
fi

echo ""
echo "=== Configuring iptables ==="

iptables -A FORWARD -i $TUN_NAME -j ACCEPT
iptables -A FORWARD -o $TUN_NAME -j ACCEPT

if [ "$ROLE" = "exit" ]; then
    echo "Configuring NAT for exit node..."
    
    iptables -t nat -A POSTROUTING -s $VIRTUAL_NETWORK -o $INTERFACE -j MASQUERADE
    
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    echo "NAT masquerading enabled for $VIRTUAL_NETWORK -> $INTERFACE"
fi

echo ""
echo "=== Saving iptables rules ==="
if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "To start the mesh VPN node:"
echo "  node src/index.js --role $ROLE"
echo ""
if [ "$ROLE" = "exit" ]; then
    echo "This exit node will NAT traffic from $VIRTUAL_NETWORK through $INTERFACE"
fi
