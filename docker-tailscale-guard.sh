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

# Ports to expose publicly (TCP) - default: none (locked mode)
PUBLIC_TCP_PORTS="${PUBLIC_TCP_PORTS:-none}"

# Ports to expose publicly (UDP) - default: none (locked mode)
PUBLIC_UDP_PORTS="${PUBLIC_UDP_PORTS:-none}"

# Tailscale interface (auto-detected if empty)
TS_IFACE="${TS_IFACE:-}"

# Log file
LOG_FILE="/var/log/docker-tailscale-guard.log"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Initialize log file with secure permissions
init_log_file() {
    # Security: refuse to write to symlinks (prevents symlink attacks)
    if [[ -L "$LOG_FILE" ]]; then
        LOG_FILE="/dev/null"
        echo "[WARN] Log file is a symlink -- refusing to follow. Logging to stderr only." >&2
        return
    fi
    if [[ ! -f "$LOG_FILE" ]]; then
        if ! install -m 640 /dev/null "$LOG_FILE" 2>/dev/null; then
            LOG_FILE="/dev/null"
            echo "[WARN] Cannot create log file. Logging to stderr only." >&2
            return
        fi
    else
        chmod 640 "$LOG_FILE" 2>/dev/null || true
    fi
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
    # Method 3: Check for userspace tailscale (tun) -- verify with Tailscale IP
    elif ip link show tun0 &>/dev/null && pgrep -x tailscaled &>/dev/null; then
        # Confirm tun0 is actually Tailscale by checking for 100.x.x.x address
        if ip addr show tun0 2>/dev/null | grep -q 'inet 100\.'; then
            iface="tun0"
        fi
    fi

    echo "$iface"
}

# Detect Docker bridge interfaces
# Returns comma-separated interface names for iptables -i matching
# Dynamically detects actual Docker-managed bridges instead of wildcards
detect_docker_interfaces() {
    local ifaces=""

    # Include default bridges only if they actually exist on the host
    for default_iface in docker0 docker_gwbridge; do
        if ip link show "$default_iface" &>/dev/null; then
            ifaces="${ifaces:+${ifaces},}${default_iface}"
        fi
    done

    # Detect actual Docker bridge interfaces (br-<network-id-prefix>)
    if command -v docker &>/dev/null; then
        local docker_bridges
        docker_bridges=$(docker network ls --format '{{.ID}}' 2>/dev/null | while read -r id; do
            local short_id="${id:0:12}"
            local br_name="br-${short_id}"
            if ip link show "$br_name" &>/dev/null && validate_interface_name "$br_name"; then
                echo "$br_name"
            fi
        done | sort -u | tr '\n' ',' | sed 's/,$//')

        if [[ -n "$docker_bridges" ]]; then
            ifaces="${ifaces:+${ifaces},}${docker_bridges}"
        fi
    fi

    # Fallback: if nothing detected, use docker0 (iptables ignores non-existent interfaces)
    if [[ -z "$ifaces" ]]; then
        log_warn "No Docker bridge interfaces detected; using docker0 as fallback"
        ifaces="docker0"
    fi

    echo "$ifaces"
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

# Ensure a writable temp directory for mktemp
ensure_tmpdir() {
    local dir="${TMPDIR:-/run/docker-tailscale-guard}"
    if [[ -z "$dir" ]]; then
        dir="/run"
    fi
    if ! mkdir -p "$dir" 2>/dev/null; then
        dir="/tmp"
        if ! mkdir -p "$dir" 2>/dev/null; then
            log_error "Cannot create temporary directory"
            return 1
        fi
    fi
    echo "$dir"
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
        if ! iptables -N DOCKER-USER 2>&1; then
            log_error "Failed to create DOCKER-USER chain (IPv4)"
            return 1
        fi
        if ! iptables -C FORWARD -j DOCKER-USER &>/dev/null; then
            if ! iptables -I FORWARD 1 -j DOCKER-USER 2>&1; then
                log_error "Failed to insert DOCKER-USER jump in FORWARD chain (IPv4)"
                return 1
            fi
        fi
    fi
}

# Ensure DOCKER-USER chain exists (IPv6)
ensure_docker_user_chain_ipv6() {
    if ! ip6tables -L DOCKER-USER -n &>/dev/null; then
        log_info "Creating DOCKER-USER chain (IPv6)"
        if ! ip6tables -N DOCKER-USER 2>&1; then
            log_error "Failed to create DOCKER-USER chain (IPv6)"
            return 1
        fi
        if ! ip6tables -C FORWARD -j DOCKER-USER &>/dev/null; then
            if ! ip6tables -I FORWARD 1 -j DOCKER-USER 2>&1; then
                log_error "Failed to insert DOCKER-USER jump in FORWARD chain (IPv6)"
                return 1
            fi
        fi
    fi
}

# Flush DOCKER-USER chain safely (IPv4 and IPv6)
flush_docker_user() {
    if ! iptables -F DOCKER-USER 2>&1; then
        log_error "Failed to flush DOCKER-USER chain (IPv4)"
        return 1
    fi
    if ! ip6tables -F DOCKER-USER 2>&1; then
        log_error "Failed to flush DOCKER-USER chain (IPv6)"
        return 1
    fi
}

# Apply rules atomically using iptables-restore (allowlist approach)
apply_rules_atomic() {
    local ts_iface="$1"
    local public_tcp="$2"
    local public_udp="$3"
    local docker_ifaces="$4"

    # Validate Tailscale interface name (security: prevent injection)
    if ! validate_interface_name "$ts_iface"; then
        log_error "Invalid Tailscale interface name: $ts_iface"
        return 1
    fi

    local rules_file
    rules_file=$(mktemp -p "$(ensure_tmpdir)")
    chmod 600 "$rules_file"  # Secure temp file permissions

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

# Allow Docker bridge interfaces (traffic FROM containers)
# -i matches the INPUT interface in FORWARD chain:
#   Container -> Internet: enters via docker bridge -> RETURN (allowed)
#   Internet -> Container: enters via WAN (eth0)   -> falls to DROP (blocked)
#   Tailscale -> Container: enters via tailscale0   -> matched above (allowed)
# Security: interface names cannot be spoofed (kernel-determined)
EOF

    # Add Docker bridge interface rules
    IFS=',' read -ra IFACES <<< "$docker_ifaces"
    for iface in "${IFACES[@]}"; do
        if [[ -n "$iface" ]] && validate_interface_name "$iface"; then
            echo "-A DOCKER-USER -i ${iface} -j RETURN" >> "$rules_file"
        else
            log_warn "Skipping invalid Docker interface: ${iface:-empty}"
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

    # Backup current rules before attempting changes
    local backup_file
    backup_file=$(mktemp -p "$(ensure_tmpdir)") || return 1
    chmod 600 "$backup_file"
    iptables-save -t filter 2>/dev/null | grep -A 9999 'DOCKER-USER' > "$backup_file" || true

    # Apply rules atomically
    local result=0
    if iptables-restore -n < "$rules_file"; then
        log_info "IPv4 rules applied successfully"
    else
        log_error "Failed to apply IPv4 rules -- attempting rollback"
        if [[ -s "$backup_file" ]]; then
            if iptables-restore -n < "$backup_file" 2>/dev/null; then
                log_warn "Rolled back to previous IPv4 rules"
            else
                log_error "CRITICAL: IPv4 rollback failed. DOCKER-USER chain may be empty. Run: docker-tailscale-guard.sh apply"
            fi
        else
            log_error "CRITICAL: No backup available. DOCKER-USER chain may be empty."
        fi
        result=1
    fi

    # Explicit cleanup (no trap clobbering)
    rm -f "$rules_file" "$backup_file" 2>/dev/null
    return $result
}

# Apply IPv6 rules atomically using ip6tables-restore
apply_rules_atomic_ipv6() {
    local ts_iface="$1"
    local public_tcp="$2"
    local public_udp="$3"
    local docker_ifaces="$4"

    # Validate Tailscale interface name (security: prevent injection)
    if ! validate_interface_name "$ts_iface"; then
        log_error "Invalid Tailscale interface name: $ts_iface"
        return 1
    fi

    local rules_file
    rules_file=$(mktemp -p "$(ensure_tmpdir)")
    chmod 600 "$rules_file"  # Secure temp file permissions

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

# Allow Docker bridge interfaces (container-to-container and container-to-internet)
EOF

    # Add Docker bridge interface rules
    IFS=',' read -ra IFACES <<< "$docker_ifaces"
    for iface in "${IFACES[@]}"; do
        if [[ -n "$iface" ]] && validate_interface_name "$iface"; then
            echo "-A DOCKER-USER -i ${iface} -j RETURN" >> "$rules_file"
        else
            log_warn "Skipping invalid Docker interface: ${iface:-empty}"
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

    # Backup current rules before attempting changes
    local backup_file
    backup_file=$(mktemp -p "$(ensure_tmpdir)") || return 1
    chmod 600 "$backup_file"
    ip6tables-save -t filter 2>/dev/null | grep -A 9999 'DOCKER-USER' > "$backup_file" || true

    # Apply rules atomically
    local result=0
    if ip6tables-restore -n < "$rules_file"; then
        log_info "IPv6 rules applied successfully"
    else
        log_error "Failed to apply IPv6 rules -- attempting rollback"
        if [[ -s "$backup_file" ]]; then
            if ip6tables-restore -n < "$backup_file" 2>/dev/null; then
                log_warn "Rolled back to previous IPv6 rules"
            else
                log_error "CRITICAL: IPv6 rollback failed. DOCKER-USER chain may be empty. Run: docker-tailscale-guard.sh apply"
            fi
        else
            log_error "CRITICAL: No backup available. DOCKER-USER chain may be empty."
        fi
        result=1
    fi

    # Explicit cleanup (no trap clobbering)
    rm -f "$rules_file" "$backup_file" 2>/dev/null
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

    # Detect Docker bridge interfaces once (avoid race between IPv4 and IPv6 application)
    local docker_ifaces
    docker_ifaces=$(detect_docker_interfaces)

    # Log detected configuration
    local wan_iface
    wan_iface=$(detect_wan_interface)
    log_info "WAN interface (detected): ${wan_iface:-NOT DETECTED}"
    log_info "Tailscale interface: $ts_iface"
    log_info "Docker interfaces: $docker_ifaces"

    # Ensure chains exist (IPv4 and IPv6)
    ensure_docker_user_chain || die "Failed to ensure DOCKER-USER chain (IPv4)"
    ensure_docker_user_chain_ipv6 || die "Failed to ensure DOCKER-USER chain (IPv6)"

    case "$mode" in
        guarded)
            # Default: Tailscale + specified public ports
            log_info "Public TCP ports: $PUBLIC_TCP_PORTS"
            log_info "Public UDP ports: $PUBLIC_UDP_PORTS"
            apply_rules_atomic "$ts_iface" "$PUBLIC_TCP_PORTS" "$PUBLIC_UDP_PORTS" "$docker_ifaces" \
                || die "Failed to apply IPv4 firewall rules"
            apply_rules_atomic_ipv6 "$ts_iface" "$PUBLIC_TCP_PORTS" "$PUBLIC_UDP_PORTS" "$docker_ifaces" \
                || die "Failed to apply IPv6 firewall rules"
            ;;
        locked)
            # Only Tailscale, no public ports
            apply_rules_atomic "$ts_iface" "none" "none" "$docker_ifaces" \
                || die "Failed to apply IPv4 firewall rules"
            apply_rules_atomic_ipv6 "$ts_iface" "none" "none" "$docker_ifaces" \
                || die "Failed to apply IPv6 firewall rules"
            ;;
        open)
            # Allow everything (bypass firewall)
            flush_docker_user || die "Failed to flush firewall rules for open mode"
            iptables -A DOCKER-USER -j RETURN || die "Failed to add IPv4 RETURN rule"
            ip6tables -A DOCKER-USER -j RETURN || die "Failed to add IPv6 RETURN rule"
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

    # Check DOCKER-USER chain exists and has DROP rule (IPv4)
    if ! iptables -L DOCKER-USER -n &>/dev/null; then
        log_error "Health check failed: DOCKER-USER chain missing (IPv4)"
        ((errors++))
    elif ! iptables -L DOCKER-USER -n 2>/dev/null | grep -q "DROP"; then
        log_error "Health check failed: DOCKER-USER chain has no DROP rule (IPv4) -- containers may be exposed"
        ((errors++))
    fi

    # Check DOCKER-USER chain exists and has DROP rule (IPv6)
    if ! ip6tables -L DOCKER-USER -n &>/dev/null; then
        log_error "Health check failed: DOCKER-USER chain missing (IPv6)"
        ((errors++))
    elif ! ip6tables -L DOCKER-USER -n 2>/dev/null | grep -q "DROP"; then
        log_error "Health check failed: DOCKER-USER chain has no DROP rule (IPv6) -- containers may be exposed"
        ((errors++))
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
