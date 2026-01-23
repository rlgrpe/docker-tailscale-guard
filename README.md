# Docker Tailscale Guard

Fault-tolerant firewall for Docker containers with Tailscale integration.

## Features

- **Tailscale-only access by default**: Docker containers accessible only via Tailscale network
- **IPv4 and IPv6 protection**: Blocks unauthorized access on both protocols
- **Localhost preserved**: Containers can access localhost and communicate with each other
- **Configurable public ports**: Expose specific ports to the public internet
- **Multi-interface security**: Allowlist approach blocks ALL interfaces except explicitly allowed (not just primary WAN)
- **Auto-detection**: Automatically detects Tailscale interfaces and Docker networks
- **Fault-tolerant**: Health checks with automatic recovery every 5 minutes
- **Safe service stop**: Firewall rules remain in place if service stops/crashes
- **Atomic rule application**: Uses `iptables-restore` and `ip6tables-restore` for atomic updates

## Quick Start

```bash
# Install
sudo ./install.sh

# Check status
sudo docker-tailscale-guard.sh status

# Configure public ports (edit /etc/docker-tailscale-guard.conf)
# Then reload:
sudo systemctl restart docker-tailscale-guard
```

## Firewall Modes

| Mode                | Tailscale | Localhost | Public Ports | WAN |
|---------------------|-----------|-----------|--------------|-----|
| `guarded` (default) | ✓         | ✓         | Configured   | ✗   |
| `locked`            | ✓         | ✓         | ✗            | ✗   |
| `open`              | ✓         | ✓         | ✓            | ✓   |

## Configuration

Edit `/etc/docker-tailscale-guard.conf`:

```bash
# TCP ports to expose publicly
PUBLIC_TCP_PORTS=80,443,8080

# UDP ports to expose publicly
PUBLIC_UDP_PORTS=443
```

### Tailscale-Only Mode (No Public Ports)

To completely disable public access and allow only Tailscale connections:

**Option 1:** Use the `locked` mode:
```bash
sudo docker-tailscale-guard.sh apply locked
```

**Option 2:** Set ports to `none` in config:
```bash
# /etc/docker-tailscale-guard.conf
PUBLIC_TCP_PORTS=none
PUBLIC_UDP_PORTS=none
```
Then restart: `sudo systemctl restart docker-tailscale-guard`

**Option 3:** Environment variables:
```bash
PUBLIC_TCP_PORTS=none PUBLIC_UDP_PORTS=none sudo docker-tailscale-guard.sh apply
```

## Commands

```bash
# Apply firewall rules
sudo docker-tailscale-guard.sh apply [guarded|locked|open]

# Show status and current rules
sudo docker-tailscale-guard.sh status

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

# Check health timer
sudo systemctl list-timers docker-tailscale-guard-health.timer
```

## How It Works

Uses the `DOCKER-USER` iptables chain (which Docker checks before forwarding traffic to containers). Rules are applied to both IPv4 (`iptables`) and IPv6 (`ip6tables`):

1. **Allow established connections** - Keeps existing connections working
2. **Allow Tailscale interface** - Full access from Tailscale network
3. **Allow loopback** - Localhost access preserved
4. **Allow Docker networks** - Container-to-container communication (IPv4 and IPv6 subnets)
5. **Allow configured public ports** - Only specified TCP/UDP ports (from any interface)
6. **Drop everything else** - Block ALL other traffic to containers (allowlist approach)

### Security Model: Allowlist Approach

Unlike blocklist firewalls that try to block specific interfaces, this uses an **allowlist approach**:
- Only explicitly allowed traffic sources are permitted
- Everything else is dropped by default
- Protects against multi-NIC servers where traffic could bypass a single-interface block
- Works identically for IPv4 and IPv6

## Troubleshooting

### Tailscale interface not found

```bash
# Check if Tailscale is running
tailscale status

# Manually specify interface
export TS_IFACE=tailscale0
sudo docker-tailscale-guard.sh apply
```

### Rules not applied after Docker restart

The systemd service is configured with `PartOf=docker.service`, so it should restart automatically. If not:

```bash
sudo systemctl restart docker-tailscale-guard
```

### View current iptables rules

```bash
# IPv4 rules
sudo iptables -L DOCKER-USER -n -v

# IPv6 rules
sudo ip6tables -L DOCKER-USER -n -v

# Verify DROP is the last rule (allowlist working)
sudo iptables -L DOCKER-USER -n | tail -2
# Should show: DROP all -- anywhere anywhere
```

### Test service stop doesn't open firewall

```bash
sudo systemctl stop docker-tailscale-guard
sudo iptables -L DOCKER-USER -n  # Rules should still exist
sudo ip6tables -L DOCKER-USER -n  # IPv6 rules should still exist
```

## Security

- **IPv4 and IPv6 protection**: Both protocols are secured with matching rules
- **Allowlist model**: Only explicitly allowed sources can reach containers; everything else is dropped
- **Multi-interface protection**: Blocks traffic from ALL network interfaces, not just a single WAN
- **Safe failure mode**: If service stops/crashes, firewall rules remain in place
- **Input validation**: All ports, interface names, and CIDR ranges (IPv4 and IPv6) are validated before use
- **Secure file permissions**: Config (640), script (750), logs (640)
- **Atomic rule application**: Uses `iptables-restore` and `ip6tables-restore` to prevent partial rule sets
- **No shell injection**: All user-provided values are sanitized

## Uninstall

```bash
sudo ./uninstall.sh
```