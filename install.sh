#!/bin/bash
#
# Docker Tailscale Guard Installer
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Docker Tailscale Guard Installer ==="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."
missing_critical=0

# iptables is required
if ! command -v iptables &>/dev/null; then
    echo "  ✗ iptables NOT FOUND (required)"
    missing_critical=1
else
    echo "  ✓ iptables found"
fi

# Docker is required
if ! command -v docker &>/dev/null; then
    echo "  ✗ docker NOT FOUND (required)"
    missing_critical=1
elif ! docker info &>/dev/null; then
    echo "  ⚠ docker found but not running"
else
    echo "  ✓ docker found and running"
fi

# Tailscale: check interface first (what actually matters), then command
if ip link show tailscale0 &>/dev/null; then
    echo "  ✓ tailscale0 interface found (Tailscale running)"
elif command -v tailscale &>/dev/null; then
    echo "  ⚠ tailscale installed but not connected (tailscale0 interface missing)"
    echo "    Run 'tailscale up' to connect"
else
    echo "  ⚠ tailscale command not found"
    echo "    The firewall needs the tailscale0 interface to work"
    echo "    Install: https://tailscale.com/download"
fi

echo ""

if [[ $missing_critical -eq 1 ]]; then
    echo "Error: Missing critical dependencies. Please install them first:"
    echo "  - Docker: https://docs.docker.com/engine/install/"
    echo "  - iptables: apt install iptables / yum install iptables"
    exit 1
fi

# Install main script with secure permissions
echo "Installing main script..."
install -m 750 "$SCRIPT_DIR/docker-tailscale-guard.sh" /usr/local/sbin/docker-tailscale-guard.sh
echo "  ✓ Installed to /usr/local/sbin/docker-tailscale-guard.sh (mode 750)"

# Install config with secure permissions (if not exists)
if [[ ! -f /etc/docker-tailscale-guard.conf ]]; then
    echo "Installing default configuration..."
    install -m 640 "$SCRIPT_DIR/docker-tailscale-guard.conf" /etc/docker-tailscale-guard.conf
    echo "  ✓ Installed to /etc/docker-tailscale-guard.conf (mode 640)"
else
    echo "  ⊘ Config already exists at /etc/docker-tailscale-guard.conf (skipped)"
fi

# Install systemd units
echo "Installing systemd units..."
cp "$SCRIPT_DIR/docker-tailscale-guard.service" /etc/systemd/system/
cp "$SCRIPT_DIR/docker-tailscale-guard-health.service" /etc/systemd/system/
cp "$SCRIPT_DIR/docker-tailscale-guard-health.timer" /etc/systemd/system/
echo "  ✓ Installed systemd service and timer"

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Enable services
echo "Enabling services..."
systemctl enable docker-tailscale-guard.service
systemctl enable docker-tailscale-guard-health.timer

# Start services
echo "Starting services..."
systemctl start docker-tailscale-guard.service
systemctl start docker-tailscale-guard-health.timer

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Commands:"
echo "  docker-tailscale-guard.sh status    # Show current status"
echo "  docker-tailscale-guard.sh apply     # Re-apply rules"
echo "  docker-tailscale-guard.sh health    # Run health check"
echo ""
echo "Configuration:"
echo "  /etc/docker-tailscale-guard.conf    # Edit public ports here"
echo ""
echo "Systemd:"
echo "  systemctl status docker-tailscale-guard"
echo "  systemctl restart docker-tailscale-guard"
echo "  journalctl -u docker-tailscale-guard"
echo ""
echo "Current status:"
/usr/local/sbin/docker-tailscale-guard.sh status