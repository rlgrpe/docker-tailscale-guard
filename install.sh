#!/bin/bash
#
# Docker Tailscale Guard Installer
#
set -euo pipefail

REPO_URL="https://raw.githubusercontent.com/rlgrpe/docker-tailscale-guard/main"

echo "=== Docker Tailscale Guard Installer ==="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Determine if running locally or remotely
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" 2>/dev/null)" && pwd 2>/dev/null)" || SCRIPT_DIR=""

# Function to get file (local or remote)
get_file() {
    local filename="$1"
    local dest="$2"

    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/$filename" ]]; then
        # Local install
        cp "$SCRIPT_DIR/$filename" "$dest"
    else
        # Remote install
        echo "  Downloading $filename..."
        curl -fsSL "$REPO_URL/$filename" -o "$dest"
    fi
}

# Check dependencies
echo "Checking dependencies..."
missing_critical=0

# iptables is required
if ! command -v iptables &>/dev/null; then
    echo "  [x] iptables NOT FOUND (required)"
    missing_critical=1
else
    echo "  [ok] iptables found"
fi

# Docker is required
if ! command -v docker &>/dev/null; then
    echo "  [x] docker NOT FOUND (required)"
    missing_critical=1
elif ! docker info &>/dev/null; then
    echo "  [!] docker found but not running"
else
    echo "  [ok] docker found and running"
fi

# Tailscale: check interface first (what actually matters), then command
if ip link show tailscale0 &>/dev/null; then
    echo "  [ok] tailscale0 interface found (Tailscale running)"
elif command -v tailscale &>/dev/null; then
    echo "  [!] tailscale installed but not connected (tailscale0 interface missing)"
    echo "      Run 'tailscale up' to connect"
else
    echo "  [!] tailscale command not found"
    echo "      The firewall needs the tailscale0 interface to work"
    echo "      Install: https://tailscale.com/download"
fi

echo ""

if [[ $missing_critical -eq 1 ]]; then
    echo "Error: Missing critical dependencies. Please install them first:"
    echo "  - Docker: https://docs.docker.com/engine/install/"
    echo "  - iptables: apt install iptables / yum install iptables"
    exit 1
fi

# Create temp directory for downloads if remote install
TEMP_DIR=""
if [[ -z "$SCRIPT_DIR" || ! -f "$SCRIPT_DIR/docker-tailscale-guard.sh" ]]; then
    INSTALL_TMPDIR="${TMPDIR:-/run/docker-tailscale-guard}"
    mkdir -p "$INSTALL_TMPDIR"
    chmod 700 "$INSTALL_TMPDIR"
    TEMP_DIR=$(mktemp -d -p "$INSTALL_TMPDIR")
    trap 'rm -rf "$TEMP_DIR"' EXIT
    SCRIPT_DIR="$TEMP_DIR"

    echo "Downloading files..."
    get_file "docker-tailscale-guard.sh" "$TEMP_DIR/docker-tailscale-guard.sh"
    get_file "docker-tailscale-guard.conf" "$TEMP_DIR/docker-tailscale-guard.conf"
    get_file "docker-tailscale-guard.service" "$TEMP_DIR/docker-tailscale-guard.service"
    get_file "docker-tailscale-guard-health.service" "$TEMP_DIR/docker-tailscale-guard-health.service"
    get_file "docker-tailscale-guard-health.timer" "$TEMP_DIR/docker-tailscale-guard-health.timer"
    echo ""
fi

# Install main script with secure permissions
echo "Installing main script..."
install -m 750 "$SCRIPT_DIR/docker-tailscale-guard.sh" /usr/local/sbin/docker-tailscale-guard.sh
echo "  [ok] Installed to /usr/local/sbin/docker-tailscale-guard.sh (mode 750)"

# Install config with secure permissions (if not exists)
if [[ ! -f /etc/docker-tailscale-guard.conf ]]; then
    echo "Installing default configuration..."
    install -m 640 "$SCRIPT_DIR/docker-tailscale-guard.conf" /etc/docker-tailscale-guard.conf
    echo "  [ok] Installed to /etc/docker-tailscale-guard.conf (mode 640)"
else
    echo "  [skip] Config already exists at /etc/docker-tailscale-guard.conf"
fi

# Install systemd units
echo "Installing systemd units..."
cp "$SCRIPT_DIR/docker-tailscale-guard.service" /etc/systemd/system/
cp "$SCRIPT_DIR/docker-tailscale-guard-health.service" /etc/systemd/system/
cp "$SCRIPT_DIR/docker-tailscale-guard-health.timer" /etc/systemd/system/
echo "  [ok] Installed systemd service and timer"

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
