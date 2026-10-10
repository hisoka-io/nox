#!/usr/bin/env bash
# Runs the unit tests of vendor/webrtc-sctp. The crate sits outside the
# workspace (it is used through [patch.crates-io]), so it is copied to a
# scratch directory and built as a workspace of its own, starting from the
# root Cargo.lock so shared dependencies keep their pinned versions.
# Extra arguments go to the test binary.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -R "$root/vendor/webrtc-sctp" "$work/webrtc-sctp"
printf '\n[workspace]\n' >> "$work/webrtc-sctp/Cargo.toml"
cp "$root/Cargo.lock" "$work/webrtc-sctp/Cargo.lock"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/vendor-sctp}"
cd "$work/webrtc-sctp"
# The fuzz artifact tests read fuzzer output kept outside the vendored source.
cargo test --lib -- --skip fuzz_artifact_test "$@"
