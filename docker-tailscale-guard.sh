#!/bin/bash
#
# Docker Tailscale Guard - Fault-tolerant firewall for Docker + Tailscale
#
# Features:
# - Docker containers accessible ONLY via Tailscale (by default)
# - Localhost access preserved for containers
# - Configurable public ports
# - Automatic interface detection with fallbacks
# - Health monitoring and auto-recovery
# - Atomic rule application
#
set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

# Ports to expose publicly (TCP)
PUBLIC_TCP_PORTS="${PUBLIC_TCP_PORTS:-80,443}"

# Ports to expose publicly (UDP)
PUBLIC_UDP_PORTS="${PUBLIC_UDP_PORTS:-443}"

# Tailscale interface (auto-detected if empty)
TS_IFACE="${TS_IFACE:-}"

# Docker networks to allow (comma-separated CIDR, auto-detected if empty)
DOCKER_NETWORKS="${DOCKER_NETWORKS:-}"

# Log file
LOG_FILE="/var/log/docker-tailscale-guard.log"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Initialize log file with secure permissions
init_log_file() {
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
    fi
    chmod 640 "$LOG_FILE"
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" | tee -a "$LOG_FILE"
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

die() {
    log_error "$@"
    exit 1
}

# Detect WAN interface with multiple fallback methods
detect_wan_interface() {
    local iface=""

    # Method 1: Default route
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

    # Method 2: First non-loopback, non-docker, non-tailscale interface with IP
    if [[ -z "$iface" || "$iface" == *" "* ]]; then
        iface=$(ip -o link show up 2>/dev/null | \
            awk -F': ' '{print $2}' | \
            grep -v -E '^(lo|docker|br-|veth|tailscale)' | \
            head -1)
    fi

    # Method 3: Common interface names
    if [[ -z "$iface" ]]; then
        for try_iface in eth0 ens3 ens4 enp0s3 enp0s25; do
            if ip link show "$try_iface" &>/dev/null; then
                iface="$try_iface"
                break
            fi
        done
    fi

    echo "$iface"
}

# Detect Tailscale interface
detect_tailscale_interface() {
    local iface=""

    # Method 1: tailscale0 (most common)
    if ip link show tailscale0 &>/dev/null; then
        iface="tailscale0"
    # Method 2: Any interface starting with tailscale
    elif iface=$(ip -o link show 2>/dev/null | grep -oP 'tailscale\w*' | head -1) && [[ -n "$iface" ]]; then
        : # iface already set
    # Method 3: Check for userspace tailscale (tun)
    elif ip link show tun0 &>/dev/null && pgrep -x tailscaled &>/dev/null; then
        iface="tun0"
    fi

    echo "$iface"
}

# Detect Docker bridge networks (IPv4)
detect_docker_networks() {
    local networks=""

    if command -v docker &>/dev/null; then
        networks=$(docker network ls --format '{{.Name}}' 2>/dev/null | \
            xargs -I {} docker network inspect {} --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null | \
            grep -E '^[0-9]+\.' | sort -u | tr '\n' ',' | sed 's/,$//')
    fi

    # Fallback: common Docker default
    if [[ -z "$networks" ]]; then
        networks="172.17.0.0/16,172.18.0.0/16,172.19.0.0/16"
    fi

    echo "$networks"
}

# Detect Docker bridge networks (IPv6)
detect_docker_networks_ipv6() {
    local networks=""

    if command -v docker &>/dev/null; then
        networks=$(docker network ls --format '{{.Name}}' 2>/dev/null | \
            xargs -I {} docker network inspect {} --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null | \
            grep -E '^[0-9a-fA-F:]+/' | sort -u | tr '\n' ',' | sed 's/,$//')
    fi

    # Fallback: common Docker IPv6 defaults (if Docker has IPv6 enabled)
    if [[ -z "$networks" ]]; then
        networks="fd00::/80"
    fi

    echo "$networks"
}

# Check if Tailscale is connected
check_tailscale_status() {
    if command -v tailscale &>/dev/null; then
        tailscale status &>/dev/null
        return $?
    fi
    return 1
}

# Validate interface exists
validate_interface() {
    local iface="$1"
    ip link show "$iface" &>/dev/null
}

# Validate interface name format (security: prevent injection)
validate_interface_name() {
    local iface="$1"
    # Interface names: alphanumeric, underscore, hyphen, max 15 chars
    [[ "$iface" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#iface} -le 15 ]]
}

# Validate port number (security: prevent injection)
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

# Validate CIDR notation (security: prevent injection)
validate_cidr() {
    local cidr="$1"
    # Match IPv4 CIDR: x.x.x.x/y where x is 0-255 and y is 0-32
    if [[ ! "$cidr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$ ]]; then
        return 1
    fi
    local a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}" mask="${BASH_REMATCH[5]}"
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 && mask <= 32 ))
}

# Validate IPv6 CIDR notation (security: prevent injection)
validate_ipv6_cidr() {
    local cidr="$1"
    # Match IPv6 CIDR with stricter validation:
    # - Must have at least one hex group before /prefix
    # - Allows :: compression but not malformed patterns like ::::
    # - Prefix must be 0-128
    if [[ ! "$cidr" =~ ^([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})$ ]] && \
       [[ ! "$cidr" =~ ^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]] && \
       [[ ! "$cidr" =~ ^::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]] && \
       [[ ! "$cidr" =~ ^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}/[0-9]{1,3}$ ]]; then
        return 1
    fi
    # Reject multiple consecutive :: (invalid)
    if [[ "$cidr" =~ :::+ ]]; then
        return 1
    fi
    local prefix="${cidr##*/}"
    (( prefix >= 0 && prefix <= 128 ))
}

# ============================================================================
# IPTABLES FUNCTIONS
# ============================================================================

# Check if Docker is installed
check_docker_installed() {
    if ! command -v docker &>/dev/null; then
        return 1
    fi
    return 0
}

# Wait for Docker to be ready and DOCKER-USER chain to exist
wait_for_docker_ready() {
    local max_attempts=30
    local attempt=1

    # First check if Docker is even installed
    if ! check_docker_installed; then
        die "Docker is not installed. This script requires Docker."
    fi

    log_info "Waiting for Docker to be ready..."

    while [[ $attempt -le $max_attempts ]]; do
        # Check if Docker is responding
        if docker info &>/dev/null; then
            # Check if DOCKER chain exists (Docker creates this)
            if iptables -L DOCKER -n &>/dev/null; then
                log_info "Docker is ready (attempt $attempt)"
                return 0
            fi
        fi

        log_info "Waiting for Docker... (attempt $attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done

    die "Docker is not running or not ready after ${max_attempts}s. Start Docker first: systemctl start docker"
}

# Ensure DOCKER-USER chain exists (IPv4)
ensure_docker_user_chain() {
    if ! iptables -L DOCKER-USER -n &>/dev/null; then
        log_info "Creating DOCKER-USER chain (IPv4)"
        iptables -N DOCKER-USER 2>/dev/null || true

        # Insert jump to DOCKER-USER at the beginning of FORWARD chain if not exists
        if ! iptables -C FORWARD -j DOCKER-USER &>/dev/null; then
            iptables -I FORWARD 1 -j DOCKER-USER 2>/dev/null || true
        fi
    fi
}

# Ensure DOCKER-USER chain exists (IPv6)
ensure_docker_user_chain_ipv6() {
    if ! ip6tables -L DOCKER-USER -n &>/dev/null; then
        log_info "Creating DOCKER-USER chain (IPv6)"
        ip6tables -N DOCKER-USER 2>/dev/null || true

        # Insert jump to DOCKER-USER at the beginning of FORWARD chain if not exists
        if ! ip6tables -C FORWARD -j DOCKER-USER &>/dev/null; then
            ip6tables -I FORWARD 1 -j DOCKER-USER 2>/dev/null || true
        fi
    fi
}

# Flush DOCKER-USER chain safely (IPv4 and IPv6)
flush_docker_user() {
    iptables -F DOCKER-USER 2>/dev/null || true
    ip6tables -F DOCKER-USER 2>/dev/null || true
}

# Apply rules atomically using iptables-restore (allowlist approach)
apply_rules_atomic() {
    local ts_iface="$1"
    local public_tcp="$2"
    local public_udp="$3"
    local docker_nets="$4"

    # Validate Tailscale interface name (security: prevent injection)
    if ! validate_interface_name "$ts_iface"; then
        log_error "Invalid Tailscale interface name: $ts_iface"
        return 1
    fi

    local rules_file
    rules_file=$(mktemp)
    chmod 600 "$rules_file"  # Secure temp file permissions

    # Ensure cleanup on exit/signals (security: prevent temp file leakage)
    trap 'rm -f "$rules_file" 2>/dev/null' EXIT

    # Build DOCKER-USER rules (allowlist approach - allow safe, drop everything else)
    cat > "$rules_file" <<EOF
*filter
:DOCKER-USER - [0:0]

# Allow established connections (critical for container networking)
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

# Allow all traffic from Tailscale interface
-A DOCKER-USER -i ${ts_iface} -j RETURN

# Allow loopback (localhost access)
-A DOCKER-USER -i lo -j RETURN

# Allow Docker internal networks (container-to-container)
EOF

    # Add Docker network rules (with validation)
    IFS=',' read -ra NETS <<< "$docker_nets"
    for net in "${NETS[@]}"; do
        if [[ -n "$net" ]]; then
            if validate_cidr "$net"; then
                echo "-A DOCKER-USER -s ${net} -j RETURN" >> "$rules_file"
            else
                log_warn "Skipping invalid CIDR: $net"
            fi
        fi
    done

    # Add public TCP ports (with validation) - any interface
    # "none" or empty string means no public TCP ports
    if [[ -n "$public_tcp" && "$public_tcp" != "none" ]]; then
        IFS=',' read -ra PORTS <<< "$public_tcp"
        for port in "${PORTS[@]}"; do
            if [[ -n "$port" ]]; then
                if validate_port "$port"; then
                    echo "-A DOCKER-USER -p tcp --dport ${port} -j RETURN" >> "$rules_file"
                else
                    log_warn "Skipping invalid TCP port: $port"
                fi
            fi
        done
    else
        log_info "No public TCP ports configured"
    fi

    # Add public UDP ports (with validation) - any interface
    # "none" or empty string means no public UDP ports
    if [[ -n "$public_udp" && "$public_udp" != "none" ]]; then
        IFS=',' read -ra PORTS <<< "$public_udp"
        for port in "${PORTS[@]}"; do
            if [[ -n "$port" ]]; then
                if validate_port "$port"; then
                    echo "-A DOCKER-USER -p udp --dport ${port} -j RETURN" >> "$rules_file"
                else
                    log_warn "Skipping invalid UDP port: $port"
                fi
            fi
        done
    else
        log_info "No public UDP ports configured"
    fi

    # DROP everything else (allowlist approach - blocks ALL interfaces not explicitly allowed)
    cat >> "$rules_file" <<EOF

# DROP all other traffic to containers (allowlist approach)
# This blocks traffic from ANY interface not explicitly allowed above
-A DOCKER-USER -j DROP

COMMIT
EOF

    # Apply rules atomically
    local result=0
    if iptables-restore -n < "$rules_file"; then
        log_info "IPv4 rules applied successfully"
    else
        log_error "Failed to apply IPv4 rules"
        result=1
    fi

    # Cleanup handled by trap, but clear it to avoid affecting caller
    rm -f "$rules_file" 2>/dev/null
    trap - EXIT
    return $result
}

# Apply IPv6 rules atomically using ip6tables-restore
apply_rules_atomic_ipv6() {
    local ts_iface="$1"
    local public_tcp="$2"
    local public_udp="$3"
    local docker_nets_ipv6="$4"

    # Validate Tailscale interface name (security: prevent injection)
    if ! validate_interface_name "$ts_iface"; then
        log_error "Invalid Tailscale interface name: $ts_iface"
        return 1
    fi

    local rules_file
    rules_file=$(mktemp)
    chmod 600 "$rules_file"  # Secure temp file permissions

    # Ensure cleanup on exit/signals (security: prevent temp file leakage)
    trap 'rm -f "$rules_file" 2>/dev/null' EXIT

    # Build DOCKER-USER rules for IPv6
    cat > "$rules_file" <<EOF
*filter
:DOCKER-USER - [0:0]

# Allow established connections (critical for container networking)
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

# Allow all traffic from Tailscale interface
-A DOCKER-USER -i ${ts_iface} -j RETURN

# Allow loopback (localhost access)
-A DOCKER-USER -i lo -j RETURN

# Allow Docker internal networks (container-to-container)
EOF

    # Add Docker IPv6 network rules (with validation)
    IFS=',' read -ra NETS <<< "$docker_nets_ipv6"
    for net in "${NETS[@]}"; do
        if [[ -n "$net" ]]; then
            if validate_ipv6_cidr "$net"; then
                echo "-A DOCKER-USER -s ${net} -j RETURN" >> "$rules_file"
            else
                log_warn "Skipping invalid IPv6 CIDR: $net"
            fi
        fi
    done

    # Add public TCP ports (with validation) - any interface
    if [[ -n "$public_tcp" && "$public_tcp" != "none" ]]; then
        IFS=',' read -ra PORTS <<< "$public_tcp"
        for port in "${PORTS[@]}"; do
            if [[ -n "$port" ]]; then
                if validate_port "$port"; then
                    echo "-A DOCKER-USER -p tcp --dport ${port} -j RETURN" >> "$rules_file"
                else
                    log_warn "Skipping invalid TCP port: $port"
                fi
            fi
        done
    fi

    # Add public UDP ports (with validation) - any interface
    if [[ -n "$public_udp" && "$public_udp" != "none" ]]; then
        IFS=',' read -ra PORTS <<< "$public_udp"
        for port in "${PORTS[@]}"; do
            if [[ -n "$port" ]]; then
                if validate_port "$port"; then
                    echo "-A DOCKER-USER -p udp --dport ${port} -j RETURN" >> "$rules_file"
                else
                    log_warn "Skipping invalid UDP port: $port"
                fi
            fi
        done
    fi

    # Drop ALL other IPv6 traffic to containers (allowlist approach)
    cat >> "$rules_file" <<EOF

# Drop all other IPv6 traffic to containers
-A DOCKER-USER -j DROP

COMMIT
EOF

    # Apply rules atomically
    local result=0
    if ip6tables-restore -n < "$rules_file"; then
        log_info "IPv6 rules applied successfully"
    else
        log_error "Failed to apply IPv6 rules"
        result=1
    fi

    # Cleanup handled by trap, but clear it to avoid affecting caller
    rm -f "$rules_file" 2>/dev/null
    trap - EXIT
    return $result
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

apply_firewall() {
    local mode="${1:-guarded}"

    log_info "Applying firewall mode: $mode"

    # Wait for Docker to be fully ready (important after Docker restart)
    wait_for_docker_ready

    # Detect Tailscale interface
    local ts_iface="${TS_IFACE:-$(detect_tailscale_interface)}"
    [[ -z "$ts_iface" ]] && die "Cannot detect Tailscale interface (tailscale0). Is Tailscale connected? Run: tailscale up"

    # Validate interface name format (security)
    validate_interface_name "$ts_iface" || die "Invalid Tailscale interface name format: '$ts_iface'"

    # Validate Tailscale interface exists
    validate_interface "$ts_iface" || die "Tailscale interface '$ts_iface' does not exist"

    # Detect Docker networks (IPv4 and IPv6)
    local docker_nets="${DOCKER_NETWORKS:-$(detect_docker_networks)}"
    local docker_nets_ipv6="${DOCKER_NETWORKS_IPV6:-$(detect_docker_networks_ipv6)}"

    # Log WAN interface for informational purposes (no longer used for blocking)
    local wan_iface
    wan_iface=$(detect_wan_interface)
    log_info "WAN interface (detected): ${wan_iface:-NOT DETECTED}"
    log_info "Tailscale interface: $ts_iface"
    log_info "Docker networks (IPv4): $docker_nets"
    log_info "Docker networks (IPv6): $docker_nets_ipv6"

    # Ensure chains exist (IPv4 and IPv6)
    ensure_docker_user_chain
    ensure_docker_user_chain_ipv6

    case "$mode" in
        guarded)
            # Default: Tailscale + specified public ports
            log_info "Public TCP ports: $PUBLIC_TCP_PORTS"
            log_info "Public UDP ports: $PUBLIC_UDP_PORTS"
            apply_rules_atomic "$ts_iface" "$PUBLIC_TCP_PORTS" "$PUBLIC_UDP_PORTS" "$docker_nets"
            apply_rules_atomic_ipv6 "$ts_iface" "$PUBLIC_TCP_PORTS" "$PUBLIC_UDP_PORTS" "$docker_nets_ipv6"
            ;;
        locked)
            # Only Tailscale, no public ports
            apply_rules_atomic "$ts_iface" "none" "none" "$docker_nets"
            apply_rules_atomic_ipv6 "$ts_iface" "none" "none" "$docker_nets_ipv6"
            ;;
        open)
            # Allow everything (bypass firewall)
            flush_docker_user
            iptables -A DOCKER-USER -j RETURN
            ip6tables -A DOCKER-USER -j RETURN
            log_info "Firewall opened - all traffic allowed (IPv4 and IPv6)"
            ;;
        *)
            die "Unknown mode: $mode. Use: guarded, locked, or open"
            ;;
    esac

    log_info "Firewall mode '$mode' applied successfully (IPv4 and IPv6)"
}

show_status() {
    echo "=== Docker Tailscale Guard Status ==="
    echo ""

    # Docker status
    echo "Docker:"
    if ! command -v docker &>/dev/null; then
        echo "  Status: NOT INSTALLED"
        echo ""
        echo "This script requires Docker to be installed."
        return 1
    elif docker info &>/dev/null; then
        echo "  Status: Running"
    else
        echo "  Status: NOT RUNNING"
    fi
    echo ""

    # Interface detection
    local wan_iface ts_iface
    wan_iface=$(detect_wan_interface)
    ts_iface=$(detect_tailscale_interface)

    echo "Interfaces:"
    echo "  WAN: ${wan_iface:-NOT DETECTED}"
    echo "  Tailscale: ${ts_iface:-NOT DETECTED}"
    echo ""

    # Tailscale status
    echo "Tailscale:"
    if ! command -v tailscale &>/dev/null; then
        echo "  Status: NOT INSTALLED"
    elif check_tailscale_status; then
        echo "  Status: Connected"
        tailscale status 2>/dev/null | head -5 | sed 's/^/  /'
    else
        echo "  Status: NOT CONNECTED"
    fi
    echo ""

    # Docker networks
    echo "Docker Networks:"
    if docker info &>/dev/null; then
        docker network ls --format '  {{.Name}}: {{.Driver}}' 2>/dev/null || echo "  (unable to list)"
    else
        echo "  (docker not running)"
    fi
    echo ""

    # Current IPv4 rules
    echo "DOCKER-USER iptables rules (IPv4):"
    if iptables -L DOCKER-USER -n -v 2>/dev/null; then
        :
    else
        echo "  (chain does not exist)"
    fi
    echo ""

    # Current IPv6 rules
    echo "DOCKER-USER ip6tables rules (IPv6):"
    if ip6tables -L DOCKER-USER -n -v 2>/dev/null; then
        :
    else
        echo "  (chain does not exist)"
    fi
}

health_check() {
    local errors=0

    # Check Docker is installed and running
    if ! command -v docker &>/dev/null; then
        log_error "Health check failed: Docker is not installed"
        ((errors++))
    elif ! docker info &>/dev/null; then
        log_error "Health check failed: Docker is not running"
        ((errors++))
    fi

    # Check Tailscale interface (this is what matters, not the tailscale command)
    local ts_iface="${TS_IFACE:-$(detect_tailscale_interface)}"
    if [[ -z "$ts_iface" ]]; then
        log_error "Health check failed: Tailscale interface not found. Run: tailscale up"
        ((errors++))
    elif ! validate_interface "$ts_iface"; then
        log_error "Health check failed: Tailscale interface '$ts_iface' does not exist"
        ((errors++))
    fi

    # Check DOCKER-USER chain exists and has rules (IPv4)
    if ! iptables -L DOCKER-USER -n &>/dev/null; then
        log_error "Health check failed: DOCKER-USER chain missing (IPv4)"
        ((errors++))
    elif ! iptables -L DOCKER-USER -n 2>/dev/null | grep -q "DROP\|tailscale"; then
        log_warn "Health check warning: DOCKER-USER chain may be empty or misconfigured (IPv4)"
    fi

    # Check DOCKER-USER chain exists and has rules (IPv6)
    if ! ip6tables -L DOCKER-USER -n &>/dev/null; then
        log_error "Health check failed: DOCKER-USER chain missing (IPv6)"
        ((errors++))
    elif ! ip6tables -L DOCKER-USER -n 2>/dev/null | grep -q "DROP\|tailscale"; then
        log_warn "Health check warning: DOCKER-USER chain may be empty or misconfigured (IPv6)"
    fi

    # Check Tailscale connectivity
    if ! check_tailscale_status; then
        log_warn "Health check warning: Tailscale not connected"
    fi

    if [[ $errors -eq 0 ]]; then
        log_info "Health check passed (IPv4 and IPv6)"
        return 0
    else
        log_error "Health check failed with $errors errors"
        return 1
    fi
}

# ============================================================================
# USAGE
# ============================================================================

usage() {
    cat <<EOF
Docker Tailscale Guard - Fault-tolerant firewall for Docker + Tailscale

Usage: $0 <command> [options]

Commands:
  apply [mode]    Apply firewall rules (modes: guarded, locked, open)
                  Default mode: guarded
  status          Show current status and rules
  health          Run health check
  help            Show this help

Modes:
  guarded   Allow Tailscale + configured public ports (default)
  locked    Allow Tailscale only, no public access
  open      Disable firewall (allow all traffic)

Environment Variables:
  PUBLIC_TCP_PORTS    TCP ports to expose publicly (default: 80,443)
  PUBLIC_UDP_PORTS    UDP ports to expose publicly (default: 443)
  TS_IFACE            Tailscale interface (auto-detected)
  DOCKER_NETWORKS     Docker networks CIDR (auto-detected)

Examples:
  $0 apply                           # Apply guarded mode with defaults
  $0 apply locked                    # Tailscale-only access
  PUBLIC_TCP_PORTS=80,443,8080 $0 apply   # Custom public ports
  PUBLIC_TCP_PORTS=none $0 apply     # No public TCP ports

EOF
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    # Require root
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root"
    fi

    # Initialize log file with secure permissions
    init_log_file

    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        apply)
            apply_firewall "${1:-guarded}"
            ;;
        status)
            show_status
            ;;
        health)
            health_check
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            usage
            die "Unknown command: $cmd"
            ;;
    esac
}

main "$@"