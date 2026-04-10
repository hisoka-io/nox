#!/bin/bash
# scripts/local-mesh.sh

# Ensure binaries are built
echo " Building..."
cargo build

# Cleanup old data
rm -rf /tmp/nox_node_a /tmp/nox_node_b

# Start Node A (Port 9000, Metrics 9090)
echo "Starting Node A..."
NOX_P2P_PORT=9000 \
NOX_METRICS_PORT=9090 \
NOX_DB_PATH=/tmp/nox_node_a/db \
NOX_P2P_IDENTITY_PATH=/tmp/nox_node_a/id.key \
./target/debug/nox &
PID_A=$!

sleep 2

# Start Node B (Port 9001, Metrics 9091)
echo " Starting Node B..."
NOX_P2P_PORT=9001 \
NOX_METRICS_PORT=9091 \
NOX_DB_PATH=/tmp/nox_node_b/db \
NOX_P2P_IDENTITY_PATH=/tmp/nox_node_b/id.key \
./target/debug/nox &
PID_B=$!

echo " Waiting for boot..."
sleep 5

echo " Interconnecting via Manual Injection (Simulating Registry)..."

echo " Nodes running. Check logs above. Press Ctrl+C to stop."
wait $PID_A $PID_B