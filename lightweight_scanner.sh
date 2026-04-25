#!/usr/bin/env bash

###############################################################################
# lightweight_scanner.sh
#
# Purpose:
#   A lightweight host discovery and TCP port scanner for authorized internal
#   testing when nmap is unavailable, inappropriate, or intentionally avoided.
#
# Design goals:
#   - Runs without root privileges.
#   - Uses Bash built-ins where possible.
#   - Does not call nmap, masscan, arp-scan, or other dedicated scanners.
#   - Supports either a single /24-style subnet range or a target file.
#   - Keeps behavior simple and readable for lab, internal, or constrained hosts.
#
# Important limitations:
#   - TCP checks use Bash's /dev/tcp feature and identify only successful TCP
#     connections. They do not perform service detection, version detection,
#     OS detection, UDP scanning, SYN scanning, or stealth scanning.
#   - ICMP ping discovery can miss hosts that block echo requests.
#   - TCP discovery can identify hosts that respond on one of the selected ports,
#     but closed or filtered hosts may appear offline.
#   - Scan only systems you own or have explicit permission to test.
###############################################################################

set -o pipefail

# Default TCP ports scanned when -p is not provided.
PORTS=(22 23 53 80 443 445 3389)

# Default TCP ports used for TCP-based host discovery when -D tcp or -D both is
# selected and --discovery-ports is not provided.
DISCOVERY_PORTS=(22 80 443 445 3389)

# Input mode values populated by command-line options.
SUBNET=""
START_HOST=""
END_HOST=""
TARGET_FILE=""

# Discovery behavior. "ping" is the default because it is simple and lightweight.
# Use "tcp" or "both" when ICMP is blocked. Use "none" to skip discovery and
# scan every supplied target directly.
DISCOVERY_MODE="ping"

# Connection timeout in seconds for TCP checks.
TIMEOUT_SECONDS=1

# Arrays populated during runtime.
TARGETS=()
LIVE_HOSTS=()

usage() {
    cat <<USAGE
Usage:
  Subnet mode:
    $0 -s <subnet> -a <start_host> -z <end_host> [options]

  File mode:
    $0 -f <target_file> [options]

Required input modes, choose one:
  -s  First three octets of a single subnet, for example: 192.168.1
  -a  Starting host number for subnet mode, for example: 1
  -z  Ending host number for subnet mode, for example: 254
  -f  File containing one IPv4 target per line

Options:
  -p  Comma-separated TCP ports to scan. Default: ${PORTS[*]}
  -D  Discovery mode: ping, tcp, both, or none. Default: ping
      ping = ICMP echo discovery before scanning
      tcp  = TCP connect discovery using discovery ports
      both = host is live if ping or TCP discovery succeeds
      none = skip discovery and scan every supplied target
  -P  Comma-separated TCP discovery ports. Default: ${DISCOVERY_PORTS[*]}
  -t  TCP timeout in seconds. Default: $TIMEOUT_SECONDS
  -h  Show this help message

Examples:
  $0 -s 192.168.1 -a 1 -z 254
  $0 -s 10.10.10 -a 20 -z 50 -p 22,80,443
  $0 -f targets.txt -D none -p 22,445,3389
  $0 -f targets.txt -D both -P 22,80,443 -p 22,80,443,445,3389
USAGE
}

fail() {
    echo "[!] $*" >&2
    exit 1
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: $cmd"
}

is_valid_ipv4() {
    local ip="$1"
    local octet

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        # Reject empty octets and values outside IPv4 range.
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done

    return 0
}

is_valid_subnet_prefix() {
    local subnet="$1"
    local octet

    [[ "$subnet" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]] || return 1

    IFS='.' read -r -a octets <<< "$subnet"
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done

    return 0
}

parse_port_list() {
    local port_string="$1"
    local array_name="$2"
    local port
    local parsed_ports=()

    [[ -n "$port_string" ]] || fail "Port list cannot be empty."

    IFS=',' read -r -a parsed_ports <<< "$port_string"
    for port in "${parsed_ports[@]}"; do
        [[ "$port" =~ ^[0-9]+$ ]] || fail "Invalid port: $port"
        (( port >= 1 && port <= 65535 )) || fail "Invalid port: $port"
    done

    # Bash nameref lets this helper update either PORTS or DISCOVERY_PORTS.
    local -n destination="$array_name"
    destination=("${parsed_ports[@]}")
}

# Bash /dev/tcp performs a standard TCP connect attempt without root privileges.
# The timeout command prevents long delays against filtered ports.
tcp_connect_check() {
    local host="$1"
    local port="$2"

    timeout "$TIMEOUT_SECONDS" bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
}

ping_discovery_check() {
    local host="$1"

    ping -c 1 -W 1 "$host" >/dev/null 2>&1
}

tcp_discovery_check() {
    local host="$1"
    local port

    for port in "${DISCOVERY_PORTS[@]}"; do
        if tcp_connect_check "$host" "$port"; then
            return 0
        fi
    done

    return 1
}

add_live_host_once() {
    local host="$1"
    local existing

    for existing in "${LIVE_HOSTS[@]}"; do
        [[ "$existing" == "$host" ]] && return 0
    done

    LIVE_HOSTS+=("$host")
    echo "[+] Host is up: $host"
}

discover_host() {
    local host="$1"

    case "$DISCOVERY_MODE" in
        ping)
            ping_discovery_check "$host" && add_live_host_once "$host"
            ;;
        tcp)
            tcp_discovery_check "$host" && add_live_host_once "$host"
            ;;
        both)
            if ping_discovery_check "$host" || tcp_discovery_check "$host"; then
                add_live_host_once "$host"
            fi
            ;;
        none)
            add_live_host_once "$host"
            ;;
        *)
            fail "Invalid discovery mode: $DISCOVERY_MODE"
            ;;
    esac
}

load_targets_from_subnet() {
    local i

    is_valid_subnet_prefix "$SUBNET" || fail "Invalid subnet. Use first three octets, such as 192.168.1"
    [[ "$START_HOST" =~ ^[0-9]+$ ]] || fail "Invalid start host: $START_HOST"
    [[ "$END_HOST" =~ ^[0-9]+$ ]] || fail "Invalid end host: $END_HOST"
    (( START_HOST >= 1 && START_HOST <= 254 )) || fail "Start host must be from 1 through 254."
    (( END_HOST >= 1 && END_HOST <= 254 )) || fail "End host must be from 1 through 254."
    (( START_HOST <= END_HOST )) || fail "Start host must be less than or equal to end host."

    for i in $(seq "$START_HOST" "$END_HOST"); do
        TARGETS+=("$SUBNET.$i")
    done
}

load_targets_from_file() {
    local target

    [[ -f "$TARGET_FILE" ]] || fail "Target file not found: $TARGET_FILE"

    while IFS= read -r target || [[ -n "$target" ]]; do
        # Tolerate Windows CRLF files and strip leading/trailing whitespace.
        target="${target//$'\r'/}"
        target="$(echo "$target" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        # Ignore blank lines and comments.
        [[ -z "$target" || "$target" =~ ^# ]] && continue

        if is_valid_ipv4 "$target"; then
            TARGETS+=("$target")
        else
            echo "[!] Skipping invalid IPv4 target: $target"
        fi
    done < "$TARGET_FILE"
}

run_discovery() {
    local target

    echo "Starting host discovery using mode: $DISCOVERY_MODE"
    echo "Targets loaded: ${#TARGETS[@]}"
    echo "----------------------------------------------"

    for target in "${TARGETS[@]}"; do
        discover_host "$target"
    done
}

scan_live_hosts() {
    local host
    local port
    local open_count=0

    echo ""
    echo "Starting TCP port scan..."
    echo "Ports: ${PORTS[*]}"
    echo "----------------------------------------------"

    if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
        echo "[!] No live hosts discovered."
        echo "    Tip: Try -D tcp, -D both, or -D none if ICMP is blocked."
        return 0
    fi

    for host in "${LIVE_HOSTS[@]}"; do
        echo ""
        echo "Scanning $host..."

        for port in "${PORTS[@]}"; do
            if tcp_connect_check "$host" "$port"; then
                echo "  [OPEN] tcp/$port"
                ((open_count++))
            fi
        done
    done

    echo ""
    echo "Open TCP ports found: $open_count"
}

while getopts ":s:a:z:f:p:D:P:t:h" opt; do
    case "$opt" in
        s) SUBNET="$OPTARG" ;;
        a) START_HOST="$OPTARG" ;;
        z) END_HOST="$OPTARG" ;;
        f) TARGET_FILE="$OPTARG" ;;
        p) parse_port_list "$OPTARG" PORTS ;;
        D) DISCOVERY_MODE="$OPTARG" ;;
        P) parse_port_list "$OPTARG" DISCOVERY_PORTS ;;
        t) TIMEOUT_SECONDS="$OPTARG" ;;
        h)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
 done

# Validate the timeout before using it.
[[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || fail "Timeout must be a positive integer."
(( TIMEOUT_SECONDS >= 1 )) || fail "Timeout must be at least 1 second."

# Validate discovery mode early for clearer errors.
case "$DISCOVERY_MODE" in
    ping|tcp|both|none) ;;
    *) fail "Discovery mode must be one of: ping, tcp, both, none" ;;
esac

# This script intentionally avoids requiring root. Warn, but do not fail, when
# launched with elevated privileges because root is unnecessary for this scanner.
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "[i] Root privileges are not required. Continuing anyway."
fi

# Commands used by this script. None require root privileges on typical Linux
# systems. ping may rely on system capabilities or setuid configuration.
require_command bash
require_command timeout
require_command sed
if [[ "$DISCOVERY_MODE" == "ping" || "$DISCOVERY_MODE" == "both" ]]; then
    require_command ping
fi

# Enforce exactly one input mode.
if [[ -n "$TARGET_FILE" && ( -n "$SUBNET" || -n "$START_HOST" || -n "$END_HOST" ) ]]; then
    usage
    fail "Choose either subnet mode or file mode, not both."
fi

if [[ -n "$TARGET_FILE" ]]; then
    load_targets_from_file
elif [[ -n "$SUBNET" || -n "$START_HOST" || -n "$END_HOST" ]]; then
    [[ -n "$SUBNET" && -n "$START_HOST" && -n "$END_HOST" ]] || {
        usage
        fail "Subnet mode requires -s, -a, and -z."
    }
    load_targets_from_subnet
else
    usage
    exit 1
fi

[[ ${#TARGETS[@]} -gt 0 ]] || fail "No valid targets loaded."

run_discovery
scan_live_hosts

echo ""
echo "Scan complete."
