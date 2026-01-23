# Docker Tailscale Guard

Fault-tolerant firewall for Docker containers with Tailscale integration.

## Features

- **Tailscale-only access by default**: Docker containers accessible only via Tailscale network
- **IPv4 and IPv6 protection**: Blocks unauthorized access on both protocols
- **Localhost preserved**: Containers can access localhost and communicate with each other
- **Configurable public ports**: Expose specific ports to the public internet
- **Multi-interface security**: Allowlist approach blocks ALL interfaces except explicitly allowed
- **Auto-detection**: Automatically detects Tailscale interfaces and Docker networks
- **Fault-tolerant**: Health checks with automatic recovery every 5 minutes
- **Safe service stop**: Firewall rules remain in place if service stops/crashes

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/rlgrpe/docker-tailscale-guard/main/install.sh | sudo bash
```

Configuration: `/etc/docker-tailscale-guard.conf`

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/rlgrpe/docker-tailscale-guard/main/install.sh | sudo bash
```

### Manual Install

```bash
git clone https://github.com/rlgrpe/docker-tailscale-guard.git
cd docker-tailscale-guard
sudo ./install.sh
```

## Quick Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/rlgrpe/docker-tailscale-guard/main/uninstall.sh | sudo bash
```

## Firewall Modes

| Mode      | Tailscale | Localhost | Public Ports | WAN |
|-----------|-----------|-----------|--------------|-----|
| `guarded` | ✓         | ✓         | Configured   | ✗   |
| `locked`  | ✓         | ✓         | ✗            | ✗   |
| `open`    | ✓         | ✓         | ✓            | ✓   |

**Default: Tailscale-only** (no public ports exposed)

## Configuration

Edit `/etc/docker-tailscale-guard.conf` to expose public ports:

```bash
# TCP ports to expose publicly (default: none)
PUBLIC_TCP_PORTS=80,443

# UDP ports to expose publicly (default: none)
PUBLIC_UDP_PORTS=443
```

Then reload:

```bash
sudo systemctl restart docker-tailscale-guard
```

## Commands

```bash
# Show status and current rules
sudo docker-tailscale-guard.sh status

# Apply firewall rules
sudo docker-tailscale-guard.sh apply [guarded|locked|open]

# Run health check
sudo docker-tailscale-guard.sh health
```

## Systemd

```bash
# Check service status
sudo systemctl status docker-tailscale-guard

# Restart (re-apply rules)
sudo systemctl restart docker-tailscale-guard

# View logs
sudo journalctl -u docker-tailscale-guard -f
```

## How It Works

Uses the `DOCKER-USER` iptables chain with an allowlist approach:

1. Allow established connections
2. Allow Tailscale interface
3. Allow loopback (localhost)
4. Allow Docker networks (container-to-container)
5. Allow configured public ports
6. **Drop everything else**

## Troubleshooting

### Tailscale interface not found

```bash
tailscale status
# If needed, manually specify:
export TS_IFACE=tailscale0
sudo docker-tailscale-guard.sh apply
```

### View current rules

```bash
sudo iptables -L DOCKER-USER -n -v
sudo ip6tables -L DOCKER-USER -n -v
```

## License

MIT