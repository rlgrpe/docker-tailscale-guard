#!/bin/bash
#
# Docker Tailscale Guard Uninstaller
#
set -euo pipefail

echo "=== Docker Tailscale Guard Uninstaller ==="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Stop services
echo "Stopping services..."
systemctl stop docker-tailscale-guard-health.timer 2>/dev/null || true
systemctl stop docker-tailscale-guard.service 2>/dev/null || true

# Disable services
echo "Disabling services..."
systemctl disable docker-tailscale-guard-health.timer 2>/dev/null || true
systemctl disable docker-tailscale-guard.service 2>/dev/null || true

# Remove systemd units
echo "Removing systemd units..."
rm -f /etc/systemd/system/docker-tailscale-guard.service
rm -f /etc/systemd/system/docker-tailscale-guard-health.service
rm -f /etc/systemd/system/docker-tailscale-guard-health.timer

# Reload systemd
systemctl daemon-reload

# Open firewall (restore access) - IPv4 and IPv6
echo "Opening firewall (restoring full access)..."
if iptables -L DOCKER-USER -n &>/dev/null; then
    iptables -F DOCKER-USER
    iptables -A DOCKER-USER -j RETURN
fi
if ip6tables -L DOCKER-USER -n &>/dev/null; then
    ip6tables -F DOCKER-USER
    ip6tables -A DOCKER-USER -j RETURN
fi

# Remove script
echo "Removing main script..."
rm -f /usr/local/sbin/docker-tailscale-guard.sh

echo ""
echo "=== Uninstallation Complete ==="
echo ""
echo "Note: Configuration file preserved at /etc/docker-tailscale-guard.conf"
echo "      Remove manually if no longer needed."