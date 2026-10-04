# ==============================================================================
# NOX Mixnet Node - Multi-stage Docker Build
# ==============================================================================
# Stage 1: Cache dependencies via stub sources
# Stage 2: Build actual source (incremental, ~2 min with cached deps)
# Stage 3: Minimal runtime image
#
# The image ships three binaries: nox (the node), price_server (exits) and
# nox-kps (the KPS entry sidecar, run as its own container as uid 10002).
# Base images are pinned by digest (looked up 2026-10-04); bump them together
# with rust-toolchain.toml.
# ==============================================================================

FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

WORKDIR /build

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Copy each active workspace manifest so Cargo can resolve the graph.
COPY crates/nox-core/Cargo.toml crates/nox-core/Cargo.toml
COPY crates/nox-crypto/Cargo.toml crates/nox-crypto/Cargo.toml
COPY crates/nox-node/Cargo.toml crates/nox-node/Cargo.toml
COPY crates/nox-oracle/Cargo.toml crates/nox-oracle/Cargo.toml
COPY crates/nox-client/Cargo.toml crates/nox-client/Cargo.toml
COPY crates/nox-test-infra/Cargo.toml crates/nox-test-infra/Cargo.toml
COPY crates/nox-sim/Cargo.toml crates/nox-sim/Cargo.toml
COPY crates/nox-kps/Cargo.toml crates/nox-kps/Cargo.toml

# Create stubs for all workspace members (cargo needs parseable src for each)
RUN for dir in nox-core nox-crypto nox-node nox-oracle nox-client \
    nox-test-infra nox-sim nox-kps; do \
    mkdir -p "crates/$dir/src" && echo "// stub" > "crates/$dir/src/lib.rs"; \
    done && \
    echo "fn main() {}" > crates/nox-kps/src/main.rs && \
    mkdir -p src && echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && echo "fn main() {}" > src/bin/price_server.rs && \
    mkdir -p benches && \
    echo "fn main() {}" > benches/replay_bench.rs && \
    echo "fn main() {}" > benches/exit_bench.rs && \
    echo "fn main() {}" > benches/pipeline_bench.rs

# nox-sim bin stubs
RUN mkdir -p crates/nox-sim/src/bin && \
    for bin in nox_multi_sim stress_test nox_bench \
    nox_multiprocess_bench nox_realworld_bench nox_privacy_analytics \
    nox_mesh_server nox_paid_mesh_server nox_dashboard_sim; do \
    echo "fn main() {}" > "crates/nox-sim/src/bin/${bin}.rs"; \
    done

# Cache dependency compilation (this layer is cached by Docker/buildx)
# The || true handles expected partial failures from stub sources.
# nox-kps builds with its own profile (release-kps: unwinding; see Cargo.toml).
RUN cargo build --release --bin nox --bin price_server 2>&1 || true
RUN cargo build --profile release-kps -p nox-kps --bin nox-kps 2>&1 || true

# Copy actual source and force rebuild of our code only
COPY . .
RUN touch src/main.rs src/bin/price_server.rs && \
    find crates/ -name "*.rs" -newer Cargo.lock -exec touch {} + 2>/dev/null || true

# Inject git commit hash for X-Nox-Version header
ARG NOX_BUILD_HASH=""
ENV NOX_BUILD_HASH=${NOX_BUILD_HASH}

# Final build - deps cached, only our source recompiles
RUN cargo build --locked --release --bin nox --bin price_server \
    && cargo build --locked --profile release-kps -p nox-kps --bin nox-kps \
    && ./target/release-kps/nox-kps --version

# ==============================================================================
# Runtime image
# ==============================================================================
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

LABEL org.opencontainers.image.source="https://github.com/hisoka-io/nox"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.url="https://hisoka.io"
LABEL org.opencontainers.image.title="nox"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 nox \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin nox \
    && groupadd --gid 10002 nox-kps \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin nox-kps

COPY --from=builder /build/target/release/nox /usr/local/bin/nox
COPY --from=builder /build/target/release/price_server /usr/local/bin/price_server
COPY --from=builder /build/target/release-kps/nox-kps /usr/local/bin/nox-kps

# nox-kps runs as uid 10002, apart from the node's uid 10001: it cannot read
# the node's keys and the node cannot read the KPS identity. Named volumes
# mounted at these paths start with this ownership.
RUN install -d -o 0 -g 0 -m 0755 /etc/nox \
    && install -d -o 10001 -g 10001 -m 0750 /var/lib/nox \
    && install -d -o 0 -g 0 -m 0755 /etc/nox-kps \
    && install -d -o 10002 -g 10002 -m 0700 /var/lib/nox-kps \
    && install -d -o 10002 -g 10002 -m 0755 /var/lib/nox-kps/keccak

USER 10001:10001

# 15005/udp: nox-kps (WebRTC + QUIC). Its admin port 15006/tcp stays on loopback.
EXPOSE 15000 15001 15002 15003 15004 15005/udp

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:15001/topology || exit 1

CMD ["nox", "--config", "/etc/nox/config.toml"]
