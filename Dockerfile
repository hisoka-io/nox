# ==============================================================================
# NOX Mixnet Node - Multi-stage Docker Build
# ==============================================================================
# Stage 1: Cache dependencies via stub sources
# Stage 2: Build actual source (incremental, ~2 min with cached deps)
# Stage 3: Minimal runtime image
# ==============================================================================

FROM rust:1.82-bookworm AS builder

WORKDIR /build

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Only copy Cargo.toml for crates we actually build (nox, nox-node, nox-oracle
# and their transitive workspace deps). Skip nox-prover and nox-sim which pull
# noir_rs/acvm git dependencies not needed for the node binary.
COPY crates/nox-core/Cargo.toml crates/nox-core/Cargo.toml
COPY crates/nox-crypto/Cargo.toml crates/nox-crypto/Cargo.toml
COPY crates/nox-node/Cargo.toml crates/nox-node/Cargo.toml
COPY crates/nox-oracle/Cargo.toml crates/nox-oracle/Cargo.toml
COPY crates/nox-client/Cargo.toml crates/nox-client/Cargo.toml
COPY crates/darkpool-crypto/Cargo.toml crates/darkpool-crypto/Cargo.toml
COPY crates/darkpool-client/Cargo.toml crates/darkpool-client/Cargo.toml
COPY crates/nox-prover/Cargo.toml crates/nox-prover/Cargo.toml
COPY crates/nox-test-infra/Cargo.toml crates/nox-test-infra/Cargo.toml
COPY crates/nox-sim/Cargo.toml crates/nox-sim/Cargo.toml

# Create stubs for all workspace members (cargo needs parseable src for each)
RUN for dir in nox-core nox-crypto nox-node nox-oracle nox-client \
    darkpool-crypto darkpool-client nox-prover nox-test-infra nox-sim; do \
    mkdir -p "crates/$dir/src" && echo "// stub" > "crates/$dir/src/lib.rs"; \
    done && \
    mkdir -p src && echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && echo "fn main() {}" > src/bin/price_server.rs && \
    mkdir -p benches && \
    echo "fn main() {}" > benches/replay_bench.rs && \
    echo "fn main() {}" > benches/exit_bench.rs && \
    echo "fn main() {}" > benches/pipeline_bench.rs

# nox-sim bin stubs
RUN mkdir -p crates/nox-sim/src/bin && \
    for bin in micro_mainnet_sim nox_multi_sim stress_test nox_bench \
    nox_multiprocess_bench nox_realworld_bench nox_privacy_analytics \
    nox_economics nox_mesh_server nox_dashboard_sim; do \
    echo "fn main() {}" > "crates/nox-sim/src/bin/${bin}.rs"; \
    done

# Cache dependency compilation (this layer is cached by Docker/buildx)
# The || true handles expected partial failures from stub sources
RUN cargo build --release --bin nox --bin price_server 2>&1 || true

# Copy actual source and force rebuild of our code only
COPY . .
RUN touch src/main.rs src/bin/price_server.rs && \
    find crates/ -name "*.rs" -newer Cargo.lock -exec touch {} + 2>/dev/null || true

# Inject git commit hash for X-Nox-Version header
ARG NOX_BUILD_HASH=""
ENV NOX_BUILD_HASH=${NOX_BUILD_HASH}

# Final build - deps cached, only our source recompiles
RUN cargo build --release --bin nox --bin price_server

# ==============================================================================
# Runtime image
# ==============================================================================
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/hisoka-io/nox"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.url="https://hisoka.io"
LABEL org.opencontainers.image.title="nox"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/nox /usr/local/bin/nox
COPY --from=builder /build/target/release/price_server /usr/local/bin/price_server

RUN mkdir -p /etc/nox /var/lib/nox

EXPOSE 15000 15001 15002 15003 15004

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:15001/topology || exit 1

CMD ["nox", "--config", "/etc/nox/config.toml"]
