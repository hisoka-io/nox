# ==============================================================================
# nox-kps: KPS entry sidecar for Nox nodes. Multi-stage build.
#   1. builder: dependencies cached from stub sources, then the real build
#   2. runtime: debian slim, no shell tools beyond the base, non-root uid 10002
# Base images are pinned by digest (looked up 2026-10-04); bump them together
# with rust-toolchain.toml.
# ==============================================================================

FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

WORKDIR /build

# The base image is the toolchain pin (rust-toolchain.toml names the same
# release; it is not copied so rustup does not fetch clippy/rustfmt here).
COPY Cargo.toml Cargo.lock ./
COPY crates/nox-kps/Cargo.toml crates/nox-kps/Cargo.toml

# Compile the dependency graph once against stub sources (cached layer).
RUN mkdir -p crates/nox-kps/src \
    && echo "fn main() {}" > crates/nox-kps/src/main.rs \
    && echo "" > crates/nox-kps/src/lib.rs \
    && cargo build --locked --release --bin nox-kps \
    && rm -rf crates/nox-kps/src

COPY crates/nox-kps/src crates/nox-kps/src
RUN touch crates/nox-kps/src/main.rs crates/nox-kps/src/lib.rs \
    && cargo build --locked --release --bin nox-kps \
    && ./target/release/nox-kps --version

# ==============================================================================
# Runtime
# ==============================================================================
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

LABEL org.opencontainers.image.source="https://github.com/hisoka-io/nox-kps"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.url="https://hisoka.io"
LABEL org.opencontainers.image.title="nox-kps"
LABEL org.opencontainers.image.description="KPS entry sidecar for Nox mixnet nodes (WebRTC + QUIC on one UDP port)"

# uid 10002: distinct from the node's uid 10001, so nox-kps cannot read the
# node's keys and the node cannot read the KPS identity.
RUN groupadd --gid 10002 nox-kps \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin nox-kps \
    && install -d -o 0 -g 0 -m 0755 /etc/nox-kps \
    && install -d -o 10002 -g 10002 -m 0700 /var/lib/nox-kps \
    && install -d -o 10002 -g 10002 -m 0755 /var/lib/nox-kps/keccak

COPY --from=builder /build/target/release/nox-kps /usr/local/bin/nox-kps

USER 10002:10002

# 15005/udp: KPS (WebRTC + QUIC). 15006/tcp: loopback admin (metrics, healthz).
EXPOSE 15005/udp

VOLUME ["/var/lib/nox-kps"]

HEALTHCHECK --interval=15s --timeout=6s --start-period=10s --retries=3 \
    CMD ["nox-kps", "healthcheck"]

CMD ["nox-kps", "run", "--config", "/etc/nox-kps/config.toml"]
