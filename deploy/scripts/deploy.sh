#!/usr/bin/env bash
set -euo pipefail

# NOX Testnet Deployment Script
# Deploys Docker image + configs to all EC2 instances

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEPLOY_DIR")"
PEM="$PROJECT_ROOT/no-commit/pems/nox-latest-kp.pem"
SECRETS="$PROJECT_ROOT/no-commit/secrets/testnet-keys.json"
IMAGE_NAME="ghcr.io/hisoka-io/nox:latest"
IMAGE_TAR="/tmp/nox-image.tar.gz"
SSH_OPTS="-i $PEM -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes"
SSH_USER="ubuntu"

# Node definitions: name:ip:role
# Load from deploy/nodes.env (gitignored) or fail with instructions.
NODES_FILE="$DEPLOY_DIR/nodes.env"
if [ ! -f "$NODES_FILE" ]; then
    echo "ERROR: $NODES_FILE not found."
    echo "Copy deploy/nodes.env.example and fill in your node IPs."
    exit 1
fi
# shellcheck source=/dev/null
source "$NODES_FILE"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
ssh_cmd() { ssh $SSH_OPTS "$SSH_USER@$1" "$2"; }
scp_cmd() { scp $SSH_OPTS "$2" "$SSH_USER@$1:$3"; }

# Parse secrets file for keys
get_routing_key() {
    python3 -c "import json; d=json.load(open('$SECRETS')); print(d['nodes']['$1']['routing_private_key'])"
}
get_eth_key() {
    python3 -c "import json; d=json.load(open('$SECRETS')); k=d['nodes']['$1']['eth_wallet_private_key']; print(k if k else '')"
}
get_p2p_key() {
    python3 -c "import json; d=json.load(open('$SECRETS')); k=d['nodes']['$1'].get('p2p_private_key',''); print(k if k else '')"
}

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  save-image    Save Docker image to tar.gz"
    echo "  setup-all     Install Docker on all nodes"
    echo "  push-all      Push image + configs to all nodes"
    echo "  start-all     Start all nodes"
    echo "  stop-all      Stop all nodes"
    echo "  status        Check status of all nodes"
    echo "  logs <node>   Tail logs for a specific node"
    echo "  push <node>   Push to a specific node"
    echo "  start <node>  Start a specific node"
    echo "  stop <node>   Stop a specific node"
    exit 1
}

save_image() {
    log "Saving Docker image to $IMAGE_TAR..."
    docker save "$IMAGE_NAME" | gzip > "$IMAGE_TAR"
    local size=$(du -h "$IMAGE_TAR" | cut -f1)
    log "Image saved: $size"
}

setup_node() {
    local name="$1" ip="$2"
    log "[$name] Installing Docker on $ip..."
    ssh_cmd "$ip" "
        if ! command -v docker &>/dev/null; then
            sudo apt-get update -qq && \
            sudo apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1 && \
            sudo usermod -aG docker ubuntu && \
            sudo systemctl enable docker && \
            sudo systemctl start docker
            echo 'Docker installed'
        else
            echo 'Docker already installed'
        fi
    "
}

push_node() {
    local name="$1" ip="$2" role="$3"

    log "[$name] Creating deployment directory..."
    ssh_cmd "$ip" "mkdir -p ~/nox-deploy"

    log "[$name] Pushing Docker image (~80MB)..."
    scp_cmd "$ip" "$IMAGE_TAR" "~/nox-deploy/nox-image.tar.gz"

    log "[$name] Loading Docker image..."
    ssh_cmd "$ip" "sudo docker load < ~/nox-deploy/nox-image.tar.gz"

    log "[$name] Pushing config..."
    scp_cmd "$ip" "$DEPLOY_DIR/configs/${name}.toml" "~/nox-deploy/config.toml"
    scp_cmd "$ip" "$DEPLOY_DIR/docker-compose.yml" "~/nox-deploy/docker-compose.yml"

    # Generate .env with secrets
    local routing_key=$(get_routing_key "$name")
    local eth_key=$(get_eth_key "$name")

    local p2p_key=$(get_p2p_key "$name")

    # config-rs uses __ separator for NOX prefix
    local env_content="NOX__ROUTING_PRIVATE_KEY=$routing_key"
    if [ -n "$p2p_key" ]; then
        env_content="$env_content
NOX__P2P_PRIVATE_KEY=$p2p_key"
    fi
    if [ -n "$eth_key" ]; then
        env_content="$env_content
NOX__ETH_WALLET_PRIVATE_KEY=$eth_key"
    fi

    echo "$env_content" | ssh_cmd "$ip" "cat > ~/nox-deploy/.env && chmod 600 ~/nox-deploy/.env"

    log "[$name] Deployed successfully"
}

start_node() {
    local name="$1" ip="$2"
    log "[$name] Starting services..."
    ssh_cmd "$ip" "cd ~/nox-deploy && sudo docker compose up -d"
    log "[$name] Started"
}

stop_node() {
    local name="$1" ip="$2"
    log "[$name] Stopping services..."
    ssh_cmd "$ip" "cd ~/nox-deploy && sudo docker compose down"
    log "[$name] Stopped"
}

status_all() {
    log "Checking all nodes..."
    printf "%-8s %-16s %-6s %-12s %-12s %-10s\n" "NAME" "IP" "ROLE" "NOX" "ORACLE" "PRICES"
    printf "%-8s %-16s %-6s %-12s %-12s %-10s\n" "----" "----" "----" "----" "------" "------"

    for entry in "${NODES[@]}"; do
        IFS=':' read -r name ip role <<< "$entry"

        # Check if containers are running
        nox_status=$(ssh_cmd "$ip" "sudo docker ps --format '{{.Status}}' --filter name=nox-node 2>/dev/null" 2>/dev/null || echo "DOWN")
        oracle_status=$(ssh_cmd "$ip" "sudo docker ps --format '{{.Status}}' --filter name=nox-price-server 2>/dev/null" 2>/dev/null || echo "DOWN")

        # Check price feed
        prices=$(ssh_cmd "$ip" "curl -sf http://127.0.0.1:15004/health 2>/dev/null" 2>/dev/null || echo "N/A")

        # Trim status
        nox_short=$(echo "$nox_status" | head -1 | cut -c1-10)
        oracle_short=$(echo "$oracle_status" | head -1 | cut -c1-10)

        printf "%-8s %-16s %-6s %-12s %-12s %-10s\n" "$name" "$ip" "$role" "$nox_short" "$oracle_short" "$prices"
    done
}

# Parallel operations
for_all_nodes() {
    local cmd="$1"
    local pids=()

    for entry in "${NODES[@]}"; do
        IFS=':' read -r name ip role <<< "$entry"
        $cmd "$name" "$ip" "$role" &
        pids+=($!)
    done

    local failed=0
    for pid in "${pids[@]}"; do
        wait "$pid" || ((failed++))
    done

    if [ "$failed" -gt 0 ]; then
        log "WARNING: $failed node(s) had errors"
    else
        log "All nodes completed successfully"
    fi
}

find_node() {
    local target="$1"
    for entry in "${NODES[@]}"; do
        IFS=':' read -r name ip role <<< "$entry"
        if [ "$name" = "$target" ]; then
            echo "$name:$ip:$role"
            return 0
        fi
    done
    echo "Node '$target' not found" >&2
    return 1
}

case "${1:-}" in
    save-image)
        save_image
        ;;
    setup-all)
        for_all_nodes setup_node
        ;;
    push-all)
        if [ ! -f "$IMAGE_TAR" ]; then
            log "Image tar not found, saving first..."
            save_image
        fi
        for_all_nodes push_node
        ;;
    start-all)
        for_all_nodes start_node
        ;;
    stop-all)
        for_all_nodes stop_node
        ;;
    status)
        status_all
        ;;
    logs)
        [ -z "${2:-}" ] && { echo "Usage: $0 logs <node-name>"; exit 1; }
        entry=$(find_node "$2")
        IFS=':' read -r name ip role <<< "$entry"
        ssh_cmd "$ip" "cd ~/nox-deploy && sudo docker compose logs -f --tail 100"
        ;;
    push)
        [ -z "${2:-}" ] && { echo "Usage: $0 push <node-name>"; exit 1; }
        entry=$(find_node "$2")
        IFS=':' read -r name ip role <<< "$entry"
        if [ ! -f "$IMAGE_TAR" ]; then save_image; fi
        push_node "$name" "$ip" "$role"
        ;;
    start)
        [ -z "${2:-}" ] && { echo "Usage: $0 start <node-name>"; exit 1; }
        entry=$(find_node "$2")
        IFS=':' read -r name ip role <<< "$entry"
        start_node "$name" "$ip"
        ;;
    stop)
        [ -z "${2:-}" ] && { echo "Usage: $0 stop <node-name>"; exit 1; }
        entry=$(find_node "$2")
        IFS=':' read -r name ip role <<< "$entry"
        stop_node "$name" "$ip"
        ;;
    *)
        usage
        ;;
esac
