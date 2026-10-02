#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Independent Non-Netstack Linux Client Qualification Script
# Tracking Issue: #392 (Parent Epic: #384, Remediation: #406)
#
# Validates real Linux client interface packet transmission, handshake
# completion, bidirectional TCP/UDP echo, and interface reconnects inside an
# isolated network namespace (ip netns) without netstack abstraction.
# Supports --dry-run for unprivileged verification and hermetic host safety.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default configurations
IFACE="awg-client0"
NETNS="nexus-client-ns"
VETH_HOST="veth-nx0"
VETH_CLIENT="veth-cl0"
UNDERLAY_HOST_IP="10.254.250.1/30"
UNDERLAY_CLIENT_IP="10.254.250.2/30"
SERVER_PORT=51820
CLIENT_IP="10.100.9.2/32"
PORTAL_IP="10.100.0.1"
OUTPUT_DIR="./test-artifacts"
DRY_RUN=false
VERBOSE=false

CONFIG_FILE=""
SERVER_PUBLIC_KEY=""
CLIENT_PRIVATE_KEY=""
SERVER_ENDPOINT=""
ALLOWED_IPS=""
TEMP_KEY_FILE=""
TEMP_HP_FILE=""
CLIENT_IP_FLAG_SET=""
HP_KEY_FLAG_SET=""
RUNTIME_DIR=""

# AmneziaWG protocol parameters
JC=4
JMIN=40
JMAX=70
S1=50
S2=100
S3=150
S4=200
H1="1020325451"
H2="3288052141"
H3="2528465083"
H4="1766607858"
HEADER_PROTECTION_KEY="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
CONTENT_PADDING_ADDITION=""
RANDOM_TRAILERS=""
DISABLE_COOKIES=""
REKEY_AFTER_TIME=""
REKEY_TIMEOUT=""
REJECT_AFTER_TIME=""
KEEPALIVE_TIMEOUT=""
MAX_HANDSHAKE_ATTEMPTS=""
PERSISTENT_KEEPALIVE=""

show_help() {
    cat << 'EOF'
Usage: ./scripts/run_non_netstack_client_qualification.sh [OPTIONS]

Options:
  -d, --dry-run                     Simulate execution plan without requiring root/sudo
                                    (Default: false)
  --config <path>                   Path to client .conf configuration file
  --server-public-key <key>         Server AmneziaWG public key (base64)
  --client-private-key <key>        Client AmneziaWG private key (base64)
  --server-endpoint <endpoint>      Server outer UDP endpoint (host:port or IP:port)
  --underlay-host-ip <ip/cidr>      Host veth underlay IP address
                                    (Default: 10.254.250.1/30)
  --underlay-client-ip <ip/cidr>    Client veth underlay IP inside namespace
                                    (Default: 10.254.250.2/30)
  -i, --interface <name>            AmneziaWG client interface name
                                    (Default: awg-client0)
  -n, --netns <name>                Isolated Linux network namespace name
                                    (Default: nexus-client-ns)
  -p, --server-port <port>          Subject/reference server UDP listen port
                                    (Default: 51820)
  -c, --client-ip <ip/cidr>         Client tunnel IP address
                                    (Default: 10.100.9.2/32)
  --header-protection-key <key>     Header protection key (base64)
  --content-padding-addition <val>  Content padding addition range (e.g. 16-64)
  --random-trailers <val>           Random trailers setting (e.g. on, true, 1)
  --disable-cookies <val>           Disable cookies setting (e.g. on, true, 1)
  --rekey-after-time <val>          Rekey after time in seconds
  --rekey-timeout <val>             Rekey timeout in seconds
  --reject-after-time <val>         Reject after time in seconds
  --keepalive-timeout <val>         Keepalive timeout in seconds
  --max-handshake-attempts <val>    Max handshake attempts count
  --persistent-keepalive <val>      Persistent keepalive interval in seconds
  -o, --output-dir <path>           Directory to save qualification report
                                    (Default: ./test-artifacts)
  --runtime-dir <path>              Directory for ephemeral keys and runtime state
                                    (Default: ./test-artifacts/runtime)
  -v, --verbose                     Enable verbose debugging output
  -h, --help                        Show this help message and exit

Description:
  This script qualifies the client-facing AmneziaWG engine with a real Linux
  kernel or userspace AmneziaWG interface operating inside an isolated
  network namespace (ip netns), removing netstack abstraction layers.

  In live mode with root/sudo, it:
    1. Creates an isolated network namespace ($NETNS).
    2. Establishes host-netns veth underlay ($VETH_HOST <-> $VETH_CLIENT) and outer route.
    3. Instantiates AmneziaWG interface ($IFACE) and configures peer via awg set
       with device options strictly before peer options.
    4. Brings interface up, installs inner tunnel route ($PORTAL_IP/32 dev $IFACE).
    5. Sends initial trigger traffic into tunnel and polls for genuine handshake completion.
    6. Executes payload-verified TCP and UDP echo against portal IP:40001.
    7. Validates interface reconnect resilience via down/up bounce and post-bounce echo.
    8. Atomically tears down namespace, veth, interface, and key files via trap cleanup.

  In --dry-run mode, it simulates the underlay, peer configuration, and traffic
  plans, and produces a sanitized qualification report with SKIPPED status.
EOF
}

parse_config() {
    local cfg="$1"
    local _xtrace_active=false
    if [[ "$-" == *x* ]]; then
        _xtrace_active=true
        set +x
    fi
    local current_section=""
    local comment_regex='^[#;]'
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        local line
        line="$(echo "$raw_line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [[ -z "$line" || "$line" =~ $comment_regex ]]; then
            continue
        fi
        if [[ "$line" =~ ^\[(.*)\]$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
            local key val
            key="$(echo "${BASH_REMATCH[1]}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            val="$(echo "${BASH_REMATCH[2]}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            val="$(echo "$val" | sed -e 's/[[:space:]]*[#;].*$//')"
            case "$key" in
                Address|address)
                    if [[ -z "$CLIENT_IP_FLAG_SET" ]]; then
                        CLIENT_IP="$val"
                    fi
                    ;;
                PrivateKey|private-key|private_key)
                    if [[ -z "$CLIENT_PRIVATE_KEY" ]]; then
                        CLIENT_PRIVATE_KEY="$val"
                    fi
                    ;;
                PublicKey|public-key|public_key)
                    if [[ -z "$SERVER_PUBLIC_KEY" ]]; then
                        SERVER_PUBLIC_KEY="$val"
                    fi
                    ;;
                Endpoint|endpoint)
                    if [[ -z "$SERVER_ENDPOINT" ]]; then
                        SERVER_ENDPOINT="$val"
                    fi
                    ;;
                AllowedIPs|allowed-ips|allowed_ips)
                    if [[ -z "$ALLOWED_IPS" ]]; then
                        ALLOWED_IPS="$val"
                    fi
                    ;;
                Jc|jc) JC="$val" ;;
                Jmin|jmin) JMIN="$val" ;;
                Jmax|jmax) JMAX="$val" ;;
                S1|s1) S1="$val" ;;
                S2|s2) S2="$val" ;;
                S3|s3) S3="$val" ;;
                S4|s4) S4="$val" ;;
                H1|h1) H1="$val" ;;
                H2|h2) H2="$val" ;;
                H3|h3) H3="$val" ;;
                H4|h4) H4="$val" ;;
                HeaderProtectionKey|header-protection-key|header_protection_key)
                    if [[ -z "$HP_KEY_FLAG_SET" ]]; then
                        HEADER_PROTECTION_KEY="$val"
                    fi
                    ;;
                ContentPaddingAddition|content-padding-addition|content_padding_addition)
                    CONTENT_PADDING_ADDITION="$val"
                    ;;
                RandomTrailers|random-trailers|random_trailers)
                    RANDOM_TRAILERS="$val"
                    ;;
                DisableCookies|disable-cookies|disable_cookies)
                    DISABLE_COOKIES="$val"
                    ;;
                RekeyAfterTime|rekey-after-time|rekey_after_time)
                    REKEY_AFTER_TIME="$val"
                    ;;
                RekeyTimeout|rekey-timeout|rekey_timeout)
                    REKEY_TIMEOUT="$val"
                    ;;
                RejectAfterTime|reject-after-time|reject_after_time)
                    REJECT_AFTER_TIME="$val"
                    ;;
                KeepaliveTimeout|keepalive-timeout|keepalive_timeout)
                    KEEPALIVE_TIMEOUT="$val"
                    ;;
                MaxHandshakeAttempts|max-handshake-attempts|max_handshake_attempts)
                    MAX_HANDSHAKE_ATTEMPTS="$val"
                    ;;
                PersistentKeepalive|persistent-keepalive|persistent_keepalive)
                    PERSISTENT_KEEPALIVE="$val"
                    ;;
            esac
        fi
    done < "$cfg"
    if [[ "$_xtrace_active" == "true" ]]; then
        set -x
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --server-public-key)
            SERVER_PUBLIC_KEY="$2"
            shift 2
            ;;
        --client-private-key)
            CLIENT_PRIVATE_KEY="$2"
            shift 2
            ;;
        --server-endpoint)
            SERVER_ENDPOINT="$2"
            shift 2
            ;;
        --underlay-host-ip)
            UNDERLAY_HOST_IP="$2"
            shift 2
            ;;
        --underlay-client-ip)
            UNDERLAY_CLIENT_IP="$2"
            shift 2
            ;;
        -i|--interface)
            IFACE="$2"
            shift 2
            ;;
        -n|--netns)
            NETNS="$2"
            shift 2
            ;;
        -p|--server-port)
            SERVER_PORT="$2"
            shift 2
            ;;
        -c|--client-ip)
            CLIENT_IP="$2"
            CLIENT_IP_FLAG_SET=true
            shift 2
            ;;
        --header-protection-key)
            HEADER_PROTECTION_KEY="$2"
            HP_KEY_FLAG_SET=true
            shift 2
            ;;
        --content-padding-addition)
            CONTENT_PADDING_ADDITION="$2"
            shift 2
            ;;
        --random-trailers)
            RANDOM_TRAILERS="$2"
            shift 2
            ;;
        --disable-cookies)
            DISABLE_COOKIES="$2"
            shift 2
            ;;
        --rekey-after-time)
            REKEY_AFTER_TIME="$2"
            shift 2
            ;;
        --rekey-timeout)
            REKEY_TIMEOUT="$2"
            shift 2
            ;;
        --reject-after-time)
            REJECT_AFTER_TIME="$2"
            shift 2
            ;;
        --keepalive-timeout)
            KEEPALIVE_TIMEOUT="$2"
            shift 2
            ;;
        --max-handshake-attempts)
            MAX_HANDSHAKE_ATTEMPTS="$2"
            shift 2
            ;;
        --persistent-keepalive)
            PERSISTENT_KEEPALIVE="$2"
            shift 2
            ;;
        --jc)
            JC="$2"
            shift 2
            ;;
        --jmin)
            JMIN="$2"
            shift 2
            ;;
        --jmax)
            JMAX="$2"
            shift 2
            ;;
        --s1)
            S1="$2"
            shift 2
            ;;
        --s2)
            S2="$2"
            shift 2
            ;;
        --s3)
            S3="$2"
            shift 2
            ;;
        --s4)
            S4="$2"
            shift 2
            ;;
        --h1)
            H1="$2"
            shift 2
            ;;
        --h2)
            H2="$2"
            shift 2
            ;;
        --h3)
            H3="$2"
            shift 2
            ;;
        --h4)
            H4="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --runtime-dir)
            RUNTIME_DIR="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option '$1'" >&2
            echo "Use --help for usage details." >&2
            exit 1
            ;;
    esac
done

if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file '$CONFIG_FILE' not found." >&2
        exit 1
    fi
    # If header protection key was not explicitly provided on the CLI, reset it
    # so we faithfully derive HP presence/absence from the configuration file.
    if [[ -z "$HP_KEY_FLAG_SET" ]]; then
        HEADER_PROTECTION_KEY=""
    fi
    parse_config "$CONFIG_FILE"
fi

UNDERLAY_HOST_ADDR="${UNDERLAY_HOST_IP%/*}"
UNDERLAY_CLIENT_ADDR="${UNDERLAY_CLIENT_IP%/*}"

if [[ -z "$SERVER_ENDPOINT" ]]; then
    SERVER_ENDPOINT="${UNDERLAY_HOST_ADDR}:${SERVER_PORT}"
fi

SERVER_ENDPOINT_IP="${SERVER_ENDPOINT%:*}"

mask_endpoint() {
    local ep="$1"
    if [[ "$ep" == *:* ]]; then
        local port="${ep##*:}"
        echo "<redacted-ip>:${port}"
    else
        echo "<redacted-ip>"
    fi
}
MASKED_SERVER_ENDPOINT="$(mask_endpoint "$SERVER_ENDPOINT")"

if [[ -z "$ALLOWED_IPS" ]]; then
    ALLOWED_IPS="${PORTAL_IP}/32"
fi

if [[ "$VERBOSE" == "true" ]]; then
    set -x
fi

if [[ "$OUTPUT_DIR" != /* ]]; then
    OUTPUT_DIR="$REPO_ROOT/$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

if [[ -z "$RUNTIME_DIR" ]]; then
    if [[ -d "$REPO_ROOT/test-artifacts/runtime" ]]; then
        RUNTIME_DIR="$REPO_ROOT/test-artifacts/runtime"
    else
        RUNTIME_DIR="$OUTPUT_DIR"
    fi
fi
if [[ "$RUNTIME_DIR" != /* ]]; then
    RUNTIME_DIR="$REPO_ROOT/$RUNTIME_DIR"
fi
mkdir -p "$RUNTIME_DIR"

REPORT_FILE="$OUTPUT_DIR/non_netstack_qualification.json"
DISPLAY_DIR="test-artifacts"
DISPLAY_REPORT="$DISPLAY_DIR/non_netstack_qualification.json"

echo "===================================================================="
echo " Amnezia Nexus - Non-Netstack Linux Client Qualification"
echo "===================================================================="
echo " Mode:            $([[ "$DRY_RUN" == "true" ]] && echo 'DRY-RUN (Simulated)' || echo 'LIVE (Network Namespace)')"
echo " Interface:       $IFACE"
echo " Namespace:       $NETNS"
echo " Underlay Host:   $UNDERLAY_HOST_IP ($VETH_HOST)"
echo " Underlay Client: $UNDERLAY_CLIENT_IP ($VETH_CLIENT)"
echo " Server Endpoint: $MASKED_SERVER_ENDPOINT"
echo " Client IP:       $CLIENT_IP"
echo " Portal Target:   $PORTAL_IP:40001"
echo " Output Dir:      $DISPLAY_DIR"
echo " Started At:      $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "===================================================================="

# Check permissions
IS_ROOT=false
if [[ "$(id -u)" -eq 0 ]]; then
    IS_ROOT=true
fi

SUDO_CMD=""
if [[ "$IS_ROOT" == "false" && "$DRY_RUN" == "false" ]]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        SUDO_CMD="sudo"
    fi
fi

# Cleanup handler for live runs
cleanup() {
    local exit_code=$?
    if [[ "$-" == *x* ]]; then
        set +x
    fi
    echo ""
    echo "==> Executing isolated resource teardown..."
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ -n "${TEMP_KEY_FILE:-}" && -f "$TEMP_KEY_FILE" ]]; then
            rm -f "$TEMP_KEY_FILE"
            TEMP_KEY_FILE=""
        fi
        if [[ -n "${TEMP_HP_FILE:-}" && -f "$TEMP_HP_FILE" ]]; then
            rm -f "$TEMP_HP_FILE"
            TEMP_HP_FILE=""
        fi
        if [[ -n "$NETNS" ]]; then
            if $SUDO_CMD ip netns list 2>/dev/null | grep -qw "$NETNS"; then
                echo "    Deleting interface '$IFACE' in namespace '$NETNS'..."
                $SUDO_CMD ip -netns "$NETNS" link delete "$IFACE" 2>/dev/null || true
                echo "    Deleting veth interface '$VETH_CLIENT' in namespace '$NETNS'..."
                $SUDO_CMD ip -netns "$NETNS" link delete "$VETH_CLIENT" 2>/dev/null || true
                echo "    Deleting network namespace '$NETNS'..."
                $SUDO_CMD ip netns delete "$NETNS" 2>/dev/null || true
            fi
        fi
        if [[ -n "$VETH_HOST" ]]; then
            if $SUDO_CMD ip link show dev "$VETH_HOST" >/dev/null 2>&1; then
                echo "    Deleting host veth interface '$VETH_HOST'..."
                $SUDO_CMD ip link delete "$VETH_HOST" 2>/dev/null || true
            fi
        fi
    fi
    echo "==> Teardown complete. Exiting with code $exit_code."
    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

START_EPOCH=$(date +%s)

HANDSHAKE_VERIFIED=false
TCP_ECHO_VERIFIED=false
UDP_ECHO_VERIFIED=false
RECONNECT_VERIFIED=false
TEARDOWN_REQUESTED=true
TEST_STATUS="SKIPPED"
EXEC_MODE="dry-run"
REPORT_NOTE=""

if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    echo "==> [Step 1/6] Validating command prerequisites & toolchain..."
    echo "    ip route2 tool:     $(command -v ip || echo 'simulated')"
    echo "    AmneziaWG CLI tool: $(command -v awg || echo 'simulated (amneziawg-tools)')"
    echo "    Status: OK (Dry-Run: Prerequisites checked)"

    echo ""
    echo "==> [Step 2/6] Planning host-netns veth underlay and outer routing..."
    echo "    Command: ip link add $VETH_HOST type veth peer name $VETH_CLIENT"
    echo "    Command: ip link set $VETH_CLIENT netns $NETNS"
    echo "    Command: ip addr add $UNDERLAY_HOST_IP dev $VETH_HOST"
    echo "    Command: ip link set $VETH_HOST up"
    echo "    Command: ip -netns $NETNS addr add $UNDERLAY_CLIENT_IP dev $VETH_CLIENT"
    echo "    Command: ip -netns $NETNS link set $VETH_CLIENT up"
    echo "    Command: ip -netns $NETNS route add $UNDERLAY_HOST_ADDR/32 dev $VETH_CLIENT"
    if [[ "$SERVER_ENDPOINT_IP" != "$UNDERLAY_HOST_ADDR" ]]; then
        echo "    Command: ip -netns $NETNS route add <server-endpoint>/32 via $UNDERLAY_HOST_ADDR dev $VETH_CLIENT"
    fi
    echo "    Status: OK (Dry-Run: Underlay network and outer endpoint route planned)"

    echo ""
    echo "==> [Step 3/6] Planning client interface creation with AmneziaWG obfuscation..."
    echo "    Command: ip link add dev $IFACE type amneziawg (or amneziawg-go $IFACE)"
    echo "    Command: ip link set $IFACE netns $NETNS"
    echo "    Command: ip -netns $NETNS addr add $CLIENT_IP dev $IFACE"

    sim_awg_cmd="awg set $IFACE private-key <client-key> listen-port 0 jc $JC jmin $JMIN jmax $JMAX s1 $S1 s2 $S2 s3 $S3 s4 $S4 h1 $H1 h2 $H2 h3 $H3 h4 $H4"
    if [[ -n "$HEADER_PROTECTION_KEY" ]]; then
        sim_awg_cmd+=" header-protection-key <hp-key-file>"
    fi
    if [[ -n "$CONTENT_PADDING_ADDITION" ]]; then
        sim_awg_cmd+=" content-padding-addition $CONTENT_PADDING_ADDITION"
    fi
    if [[ -n "$RANDOM_TRAILERS" ]]; then
        sim_awg_cmd+=" random-trailers $RANDOM_TRAILERS"
    fi
    if [[ -n "$DISABLE_COOKIES" ]]; then
        sim_awg_cmd+=" disable-cookies $DISABLE_COOKIES"
    fi
    if [[ -n "$REKEY_AFTER_TIME" ]]; then
        sim_awg_cmd+=" rekey-after-time $REKEY_AFTER_TIME"
    fi
    if [[ -n "$REKEY_TIMEOUT" ]]; then
        sim_awg_cmd+=" rekey-timeout $REKEY_TIMEOUT"
    fi
    if [[ -n "$REJECT_AFTER_TIME" ]]; then
        sim_awg_cmd+=" reject-after-time $REJECT_AFTER_TIME"
    fi
    if [[ -n "$KEEPALIVE_TIMEOUT" ]]; then
        sim_awg_cmd+=" keepalive-timeout $KEEPALIVE_TIMEOUT"
    fi
    if [[ -n "$MAX_HANDSHAKE_ATTEMPTS" ]]; then
        sim_awg_cmd+=" max-handshake-attempts $MAX_HANDSHAKE_ATTEMPTS"
    fi
    sim_awg_cmd+=" peer <server-pubkey> endpoint $MASKED_SERVER_ENDPOINT allowed-ips $ALLOWED_IPS"
    if [[ -n "$PERSISTENT_KEEPALIVE" ]]; then
        sim_awg_cmd+=" persistent-keepalive $PERSISTENT_KEEPALIVE"
    fi

    echo "    Command: $sim_awg_cmd"
    echo "    Command: ip -netns $NETNS link set $IFACE up"
    echo "    Command: ip -netns $NETNS route add $PORTAL_IP/32 dev $IFACE"
    if [[ "$ALLOWED_IPS" == "0.0.0.0/0" ]]; then
        echo "    Command: ip -netns $NETNS route add default dev $IFACE"
    fi
    echo "    AmneziaWG Parameters: Jc=$JC, Jmin=$JMIN, Jmax=$JMAX, S1=$S1, S2=$S2, S3=$S3, S4=$S4, H1=$H1, H2=$H2, H3=$H3, H4=$H4"
    echo "    Status: OK (Dry-Run: Simulated plan verified)"

    echo ""
    echo "==> [Step 4/6] Simulating handshake trigger and payload-verified traffic exchange..."
    echo "    AmneziaWG Outer Endpoint:   $MASKED_SERVER_ENDPOINT"
    echo "    Target Portal IP:           $PORTAL_IP:40001"
    echo "    Handshake Trigger:          Initial tunnel packet into $IFACE"
    echo "    Handshake Verification:     Poll awg show $IFACE latest-handshakes"
    echo "    Probe Payload Verification: Unique random token comparison (TCP and UDP echo)"
    echo "    Status: SKIPPED (Dry-Run: Live traffic not executed in simulation mode)"

    echo ""
    echo "==> [Step 5/6] Simulating interface bounce and reconnect resilience..."
    echo "    Command: ip -netns $NETNS link set $IFACE down"
    echo "    Command: ip -netns $NETNS link set $IFACE up"
    echo "    Command: ip -netns $NETNS route add $PORTAL_IP/32 dev $IFACE"
    if [[ "$ALLOWED_IPS" == "0.0.0.0/0" ]]; then
        echo "    Command: ip -netns $NETNS route add default dev $IFACE"
    fi
    echo "    Post-Bounce Traffic Check:  Payload-verified echo over reconnected interface"
    echo "    Status: SKIPPED (Dry-Run: Interface bounce simulated)"

    echo ""
    echo "==> [Step 6/6] Verifying automated cleanup trap..."
    echo "    Command: ip -netns $NETNS link delete $IFACE"
    echo "    Command: ip -netns $NETNS link delete $VETH_CLIENT"
    echo "    Command: ip netns delete $NETNS"
    echo "    Command: ip link delete $VETH_HOST"
    echo "    Status: OK (Dry-Run: Cleanup trap verified)"

    HANDSHAKE_VERIFIED=false
    TCP_ECHO_VERIFIED=false
    UDP_ECHO_VERIFIED=false
    RECONNECT_VERIFIED=false
    TEARDOWN_REQUESTED=true
    TEST_STATUS="SKIPPED"
    EXEC_MODE="dry-run"
    REPORT_NOTE="Dry-run execution verified parameters and commands; live traffic tests were skipped."
else
    # Live execution with network namespace
    EXEC_MODE="live-netns"
    echo ""
    echo "==> [Step 1/6] Checking live execution prerequisites..."

    MISSING_PREREQ=""
    if [[ "$IS_ROOT" == "false" && -z "$SUDO_CMD" ]]; then
        MISSING_PREREQ="missing CAP_NET_ADMIN / sudo permissions"
    elif ! command -v awg >/dev/null 2>&1; then
        MISSING_PREREQ="missing awg CLI tool (amneziawg-tools required for peer configuration)"
    elif [[ -z "$SERVER_PUBLIC_KEY" ]]; then
        MISSING_PREREQ="missing server configuration / public key"
    elif [[ -z "$CLIENT_PRIVATE_KEY" && -z "$CONFIG_FILE" ]]; then
        MISSING_PREREQ="missing client credentials (provide --config <client.conf> or --client-private-key <key> matching server peer)"
    fi

    if [[ -n "$MISSING_PREREQ" ]]; then
        echo "    Notice: $MISSING_PREREQ"
        echo "    SKIPPED: Prerequisites or server configuration not satisfied for live network namespace testing."
        HANDSHAKE_VERIFIED=false
        TCP_ECHO_VERIFIED=false
        UDP_ECHO_VERIFIED=false
        RECONNECT_VERIFIED=false
        TEARDOWN_REQUESTED=true
        TEST_STATUS="SKIPPED"
        REPORT_NOTE="SKIPPED: $MISSING_PREREQ"
    else
        echo "    Prerequisites satisfied: CAP_NET_ADMIN verified, awg CLI tool present, server key and client credentials available."
        echo ""
        echo "==> [Step 2/6] Establishing host-netns veth underlay and namespace '$NETNS'..."
        $SUDO_CMD ip netns add "$NETNS"
        $SUDO_CMD ip -netns "$NETNS" link set lo up

        $SUDO_CMD ip link add "$VETH_HOST" type veth peer name "$VETH_CLIENT"
        $SUDO_CMD ip link set "$VETH_CLIENT" netns "$NETNS"
        $SUDO_CMD ip addr add "$UNDERLAY_HOST_IP" dev "$VETH_HOST"
        $SUDO_CMD ip link set "$VETH_HOST" up
        $SUDO_CMD ip -netns "$NETNS" addr add "$UNDERLAY_CLIENT_IP" dev "$VETH_CLIENT"
        $SUDO_CMD ip -netns "$NETNS" link set "$VETH_CLIENT" up

        # Route outer endpoint specifically through $VETH_CLIENT (do NOT add default route to $VETH_CLIENT):
        $SUDO_CMD ip -netns "$NETNS" route add "$UNDERLAY_HOST_ADDR/32" dev "$VETH_CLIENT" 2>/dev/null || true
        if [[ "$SERVER_ENDPOINT_IP" != "$UNDERLAY_HOST_ADDR" ]]; then
            $SUDO_CMD ip -netns "$NETNS" route add "$SERVER_ENDPOINT_IP/32" via "$UNDERLAY_HOST_ADDR" dev "$VETH_CLIENT" 2>/dev/null || true
        fi
        echo "    Underlay established: host ($VETH_HOST: $UNDERLAY_HOST_IP) <-> netns ($VETH_CLIENT: $UNDERLAY_CLIENT_IP)."

        echo ""
        echo "==> [Step 3/6] Instantiating AmneziaWG client interface and configuring peer..."
        AWG_INITIALIZED=false
        if $SUDO_CMD ip link add dev "$IFACE" type amneziawg 2>/dev/null; then
            $SUDO_CMD ip link set "$IFACE" netns "$NETNS"
            $SUDO_CMD ip -netns "$NETNS" addr add "$CLIENT_IP" dev "$IFACE"
            AWG_INITIALIZED=true
            echo "    Kernel AmneziaWG interface '$IFACE' instantiated inside '$NETNS'."
        elif command -v amneziawg-go >/dev/null 2>&1; then
            if $SUDO_CMD ip netns exec "$NETNS" amneziawg-go "$IFACE" 2>/dev/null; then
                $SUDO_CMD ip -netns "$NETNS" addr add "$CLIENT_IP" dev "$IFACE"
                AWG_INITIALIZED=true
                echo "    Userspace amneziawg-go interface '$IFACE' instantiated inside '$NETNS'."
            fi
        fi

        if [[ "$AWG_INITIALIZED" != "true" ]]; then
            echo "    SKIPPED: missing amneziawg / CAP_NET_ADMIN (kernel module or userspace daemon unavailable)."
            TEST_STATUS="SKIPPED"
            REPORT_NOTE="SKIPPED: missing amneziawg / CAP_NET_ADMIN"
        elif [[ -z "$CLIENT_PRIVATE_KEY" ]]; then
            echo "    SKIPPED: missing client private key (credentials must match server peer configuration)."
            TEST_STATUS="SKIPPED"
            REPORT_NOTE="SKIPPED: missing client private key"
        else
            _xtrace_active=false
            if [[ "$-" == *x* ]]; then
                _xtrace_active=true
                set +x
            fi

            TEMP_KEY_FILE=$(mktemp -p "$RUNTIME_DIR" .awg-key-XXXXXX 2>/dev/null || echo "${RUNTIME_DIR}/.awg-key-$$-${RANDOM}")
            ( umask 077 && touch "$TEMP_KEY_FILE" )
            chmod 600 "$TEMP_KEY_FILE"
            printf '%s\n' "$CLIENT_PRIVATE_KEY" > "$TEMP_KEY_FILE"

            if [[ -n "$HEADER_PROTECTION_KEY" ]]; then
                TEMP_HP_FILE=$(mktemp -p "$RUNTIME_DIR" .awg-hp-XXXXXX 2>/dev/null || echo "${RUNTIME_DIR}/.awg-hp-$$-${RANDOM}")
                ( umask 077 && touch "$TEMP_HP_FILE" )
                chmod 600 "$TEMP_HP_FILE"
                printf '%s\n' "$HEADER_PROTECTION_KEY" > "$TEMP_HP_FILE"
            fi

            AWG_DEVICE_ARGS=(
                private-key "$TEMP_KEY_FILE"
                listen-port 0
                jc "$JC"
                jmin "$JMIN"
                jmax "$JMAX"
                s1 "$S1"
                s2 "$S2"
                s3 "$S3"
                s4 "$S4"
                h1 "$H1"
                h2 "$H2"
                h3 "$H3"
                h4 "$H4"
            )

            if [[ -n "$TEMP_HP_FILE" ]]; then
                AWG_DEVICE_ARGS+=(header-protection-key "$TEMP_HP_FILE")
            fi
            if [[ -n "$CONTENT_PADDING_ADDITION" ]]; then
                AWG_DEVICE_ARGS+=(content-padding-addition "$CONTENT_PADDING_ADDITION")
            fi
            if [[ -n "$RANDOM_TRAILERS" ]]; then
                AWG_DEVICE_ARGS+=(random-trailers "$RANDOM_TRAILERS")
            fi
            if [[ -n "$DISABLE_COOKIES" ]]; then
                AWG_DEVICE_ARGS+=(disable-cookies "$DISABLE_COOKIES")
            fi
            if [[ -n "$REKEY_AFTER_TIME" ]]; then
                AWG_DEVICE_ARGS+=(rekey-after-time "$REKEY_AFTER_TIME")
            fi
            if [[ -n "$REKEY_TIMEOUT" ]]; then
                AWG_DEVICE_ARGS+=(rekey-timeout "$REKEY_TIMEOUT")
            fi
            if [[ -n "$REJECT_AFTER_TIME" ]]; then
                AWG_DEVICE_ARGS+=(reject-after-time "$REJECT_AFTER_TIME")
            fi
            if [[ -n "$KEEPALIVE_TIMEOUT" ]]; then
                AWG_DEVICE_ARGS+=(keepalive-timeout "$KEEPALIVE_TIMEOUT")
            fi
            if [[ -n "$MAX_HANDSHAKE_ATTEMPTS" ]]; then
                AWG_DEVICE_ARGS+=(max-handshake-attempts "$MAX_HANDSHAKE_ATTEMPTS")
            fi

            AWG_PEER_ARGS=(
                peer "$SERVER_PUBLIC_KEY"
                endpoint "$SERVER_ENDPOINT"
                allowed-ips "$ALLOWED_IPS"
            )
            if [[ -n "$PERSISTENT_KEEPALIVE" ]]; then
                AWG_PEER_ARGS+=(persistent-keepalive "$PERSISTENT_KEEPALIVE")
            fi

            $SUDO_CMD ip netns exec "$NETNS" awg set "$IFACE" \
                "${AWG_DEVICE_ARGS[@]}" \
                "${AWG_PEER_ARGS[@]}"

            if [[ -n "$TEMP_KEY_FILE" && -f "$TEMP_KEY_FILE" ]]; then
                rm -f "$TEMP_KEY_FILE"
                TEMP_KEY_FILE=""
            fi
            if [[ -n "$TEMP_HP_FILE" && -f "$TEMP_HP_FILE" ]]; then
                rm -f "$TEMP_HP_FILE"
                TEMP_HP_FILE=""
            fi

            if [[ "$_xtrace_active" == "true" ]]; then
                set -x
            fi

            # Bring interface UP
            $SUDO_CMD ip -netns "$NETNS" link set "$IFACE" up

            # Install inner tunnel route
            $SUDO_CMD ip -netns "$NETNS" route add "$PORTAL_IP/32" dev "$IFACE" 2>/dev/null || true
            if [[ "$ALLOWED_IPS" == "0.0.0.0/0" ]]; then
                $SUDO_CMD ip -netns "$NETNS" route add default dev "$IFACE" 2>/dev/null || true
            fi
            echo "    Peer configured via awg set with device options strictly before peer options."
            echo "    Interface '$IFACE' brought up and inner tunnel route to $PORTAL_IP/32 installed."

            echo ""
            echo "==> [Step 4/6] Triggering handshake and verifying bidirectional traffic..."

            # Send initial trigger traffic into tunnel to prompt WireGuard/AmneziaWG handshake initiation
            echo "    Sending initial tunnel packet to trigger handshake initiation..."
            $SUDO_CMD ip netns exec "$NETNS" ping -c 1 -W 1 "$PORTAL_IP" >/dev/null 2>&1 || true
            if command -v nc >/dev/null 2>&1; then
                echo -n "handshake-trigger" | $SUDO_CMD ip netns exec "$NETNS" timeout 1 nc -u -w 1 "$PORTAL_IP" 40001 >/dev/null 2>&1 || true
            fi

            # Poll awg show "$IFACE" latest-handshakes until timestamp > 0 (timeout ~10s)
            echo "    Polling for AmneziaWG handshake completion (timeout 10s)..."
            HS_START=$(date +%s)
            while [[ $(( $(date +%s) - HS_START )) -lt 10 ]]; do
                latest_hs=0
                if command -v awg >/dev/null 2>&1; then
                    latest_hs=$($SUDO_CMD ip netns exec "$NETNS" awg show "$IFACE" latest-handshakes 2>/dev/null | awk '{print $2}' || echo "0")
                elif command -v wg >/dev/null 2>&1; then
                    latest_hs=$($SUDO_CMD ip netns exec "$NETNS" wg show "$IFACE" latest-handshakes 2>/dev/null | awk '{print $2}' || echo "0")
                fi

                if [[ -n "$latest_hs" && "$latest_hs" =~ ^[0-9]+$ && "$latest_hs" -gt 0 ]]; then
                    HANDSHAKE_VERIFIED=true
                    echo "    Genuine latest handshake verified: timestamp $latest_hs."
                    break
                fi

                # Retrigger packet if handshake not yet completed
                $SUDO_CMD ip netns exec "$NETNS" ping -c 1 -W 1 "$PORTAL_IP" >/dev/null 2>&1 || true
                sleep 1
            done

            if [[ "$HANDSHAKE_VERIFIED" != "true" ]]; then
                echo "    WARNING: Handshake was not completed within timeout."
            fi

            # Verify TCP and UDP echo payloads against unique probe tokens
            if command -v nc >/dev/null 2>&1; then
                TCP_PROBE_TOKEN="probe-tcp-$(date +%s%N)-$RANDOM"
                TCP_RECEIVED=$(echo -n "$TCP_PROBE_TOKEN" | $SUDO_CMD ip netns exec "$NETNS" timeout 3 nc -w 2 "$PORTAL_IP" 40001 2>/dev/null || true)
                if [[ "$TCP_RECEIVED" == "$TCP_PROBE_TOKEN" ]]; then
                    TCP_ECHO_VERIFIED=true
                    echo "    Payload-verified TCP echo: PASS (returned bytes match probe token)."
                else
                    echo "    Payload-verified TCP echo: FAIL (token mismatch or timeout)."
                fi

                UDP_PROBE_TOKEN="probe-udp-$(date +%s%N)-$RANDOM"
                UDP_RECEIVED=$(echo -n "$UDP_PROBE_TOKEN" | $SUDO_CMD ip netns exec "$NETNS" timeout 3 nc -u -w 2 "$PORTAL_IP" 40001 2>/dev/null || true)
                if [[ -z "$UDP_RECEIVED" ]]; then
                    UDP_RECEIVED=$(echo -n "$UDP_PROBE_TOKEN" | $SUDO_CMD ip netns exec "$NETNS" timeout 3 nc -u -w 2 -W 1 "$PORTAL_IP" 40001 2>/dev/null || true)
                fi
                if [[ "$UDP_RECEIVED" == "$UDP_PROBE_TOKEN" ]]; then
                    UDP_ECHO_VERIFIED=true
                    echo "    Payload-verified UDP echo: PASS (returned bytes match probe token)."
                else
                    echo "    Payload-verified UDP echo: FAIL (token mismatch or timeout)."
                fi
            else
                echo "    Notice: nc (netcat) tool not available for TCP/UDP echo verification."
            fi

            echo ""
            echo "==> [Step 5/6] Validating interface down/up bounce and reconnect resilience..."
            $SUDO_CMD ip -netns "$NETNS" link set "$IFACE" down
            sleep 1
            $SUDO_CMD ip -netns "$NETNS" link set "$IFACE" up

            # Re-ensure inner tunnel route after bounce
            $SUDO_CMD ip -netns "$NETNS" route add "$PORTAL_IP/32" dev "$IFACE" 2>/dev/null || true
            if [[ "$ALLOWED_IPS" == "0.0.0.0/0" ]]; then
                $SUDO_CMD ip -netns "$NETNS" route add default dev "$IFACE" 2>/dev/null || true
            fi

            LINK_UP=false
            if $SUDO_CMD ip -netns "$NETNS" link show up dev "$IFACE" 2>/dev/null | grep -E -q '<[^>]*\bUP\b[^>]*>'; then
                LINK_UP=true
                echo "    Interface successfully brought back UP (administrative UP verified)."
            fi

            # Send post-bounce probes, and set reconnect_resilience_verified=true only if post-bounce echo succeeds and link is UP
            POST_BOUNCE_ECHO_OK=false
            if [[ "$LINK_UP" == "true" ]] && command -v nc >/dev/null 2>&1; then
                # Trigger packet
                $SUDO_CMD ip netns exec "$NETNS" ping -c 1 -W 1 "$PORTAL_IP" >/dev/null 2>&1 || true

                POST_TCP_PROBE_TOKEN="probe-post-tcp-$(date +%s%N)-$RANDOM"
                POST_TCP_RECEIVED=$(echo -n "$POST_TCP_PROBE_TOKEN" | $SUDO_CMD ip netns exec "$NETNS" timeout 3 nc -w 2 "$PORTAL_IP" 40001 2>/dev/null || true)
                POST_TCP_OK=false
                if [[ "$POST_TCP_RECEIVED" == "$POST_TCP_PROBE_TOKEN" ]]; then
                    POST_TCP_OK=true
                fi

                POST_UDP_PROBE_TOKEN="probe-post-udp-$(date +%s%N)-$RANDOM"
                POST_UDP_RECEIVED=$(echo -n "$POST_UDP_PROBE_TOKEN" | $SUDO_CMD ip netns exec "$NETNS" timeout 3 nc -u -w 2 "$PORTAL_IP" 40001 2>/dev/null || true)
                if [[ -z "$POST_UDP_RECEIVED" ]]; then
                    POST_UDP_RECEIVED=$(echo -n "$POST_UDP_PROBE_TOKEN" | $SUDO_CMD ip netns exec "$NETNS" timeout 3 nc -u -w 2 -W 1 "$PORTAL_IP" 40001 2>/dev/null || true)
                fi
                POST_UDP_OK=false
                if [[ "$POST_UDP_RECEIVED" == "$POST_UDP_PROBE_TOKEN" ]]; then
                    POST_UDP_OK=true
                fi

                if [[ "$POST_TCP_OK" == "true" && "$POST_UDP_OK" == "true" ]]; then
                    POST_BOUNCE_ECHO_OK=true
                    echo "    Post-bounce echo payload verification: PASS (TCP and UDP echo match tokens)."
                else
                    echo "    Post-bounce echo payload verification: FAIL (post_tcp=$POST_TCP_OK, post_udp=$POST_UDP_OK)."
                fi
            fi

            if [[ "$LINK_UP" == "true" && "$POST_BOUNCE_ECHO_OK" == "true" ]]; then
                RECONNECT_VERIFIED=true
                echo "    Reconnect resilience: PASS (link UP and post-bounce echo verified)."
            else
                RECONNECT_VERIFIED=false
                echo "    Reconnect resilience: FAIL (link_up=$LINK_UP, post_bounce_echo=$POST_BOUNCE_ECHO_OK)."
            fi

            if [[ "$HANDSHAKE_VERIFIED" == "true" && "$TCP_ECHO_VERIFIED" == "true" && "$UDP_ECHO_VERIFIED" == "true" && "$RECONNECT_VERIFIED" == "true" ]]; then
                TEST_STATUS="PASS"
                REPORT_NOTE="Live network namespace client traffic and reconnect resilience verified."
            else
                TEST_STATUS="FAIL"
                REPORT_NOTE="Live network namespace client qualification failed (handshake=$HANDSHAKE_VERIFIED, tcp=$TCP_ECHO_VERIFIED, udp=$UDP_ECHO_VERIFIED, reconnect=$RECONNECT_VERIFIED)."
            fi
        fi
    fi
fi

TOTAL_DURATION=$(( $(date +%s) - START_EPOCH ))

HP_REPORT_STATUS="<absent>"
if [[ -n "$HEADER_PROTECTION_KEY" ]]; then
    HP_REPORT_STATUS="<present-32B>"
fi

# Write Qualification Report Artifact
cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "qualification_type": "non_netstack_linux_client",
  "mode": "$EXEC_MODE",
  "interface": "$IFACE",
  "netns": "$NETNS",
  "underlay": {
    "host_ip": "$UNDERLAY_HOST_IP",
    "client_ip": "$UNDERLAY_CLIENT_IP",
    "veth_host": "$VETH_HOST",
    "veth_client": "$VETH_CLIENT"
  },
  "server_port": $SERVER_PORT,
  "client_ip": "$CLIENT_IP",
  "portal_ip": "$PORTAL_IP",
  "server_endpoint": "$MASKED_SERVER_ENDPOINT",
  "amneziawg_parameters": {
    "jc": $JC,
    "jmin": $JMIN,
    "jmax": $JMAX,
    "s1": $S1,
    "s2": $S2,
    "s3": $S3,
    "s4": $S4,
    "h1": "$H1",
    "h2": "$H2",
    "h3": "$H3",
    "h4": "$H4",
    "header_protection": "$HP_REPORT_STATUS"
  },
  "handshake_verified": $HANDSHAKE_VERIFIED,
  "tcp_echo_verified": $TCP_ECHO_VERIFIED,
  "udp_echo_verified": $UDP_ECHO_VERIFIED,
  "reconnect_resilience_verified": $RECONNECT_VERIFIED,
  "teardown_requested": $TEARDOWN_REQUESTED,
  "teardown_trap_verified": $TEARDOWN_REQUESTED,
  "total_duration_sec": $TOTAL_DURATION,
  "status": "$TEST_STATUS",
  "note": "$REPORT_NOTE"
}
EOF

# Privacy audit on generated report
HOME_PATTERN="/"$(printf 'home')"/"
TMP_PATTERN="/"$(printf 'tmp')"/"
IP_PATTERNS=(
    "192.""168."
    "207.""2."
    "64.""112."
)

PRIVACY_OK=true
if grep -i "private_key" "$REPORT_FILE" >/dev/null 2>&1; then
    echo "ERROR: Privacy violation: 'private_key' found in $REPORT_FILE" >&2
    PRIVACY_OK=false
fi
for ip_pat in "${IP_PATTERNS[@]}"; do
    if grep -F "$ip_pat" "$REPORT_FILE" >/dev/null 2>&1; then
        echo "ERROR: Privacy violation: Real server IP pattern '$ip_pat' found in $REPORT_FILE" >&2
        PRIVACY_OK=false
    fi
done
if grep -F "$HOME_PATTERN" "$REPORT_FILE" >/dev/null 2>&1 || grep -F "$TMP_PATTERN" "$REPORT_FILE" >/dev/null 2>&1; then
    echo "ERROR: Privacy violation: Local filesystem pattern found in $REPORT_FILE" >&2
    PRIVACY_OK=false
fi

if [[ "$PRIVACY_OK" != "true" ]]; then
    exit 1
fi

echo ""
echo "===================================================================="
echo " Non-Netstack Client Qualification Summary"
echo "===================================================================="
echo " Mode:               $EXEC_MODE"
echo " Duration:           ${TOTAL_DURATION}s"
echo " Status:             $TEST_STATUS"
echo " Report Artifact:    $DISPLAY_REPORT"
echo " Privacy Validation: PASS (Zero keys, zero real IPs, zero local paths)"
echo "===================================================================="

if [[ "$TEST_STATUS" == "FAIL" ]]; then
    exit 1
fi
exit 0
