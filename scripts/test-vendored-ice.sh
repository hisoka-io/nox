#!/usr/bin/env bash
# Runs unit tests of vendor/webrtc-ice the same way scripts/test-vendored-sctp.sh
# runs the webrtc-sctp ones: in a scratch copy built as a workspace of its own,
# starting from the root Cargo.lock. Arguments go to the test binary; without
# any, the regression test for the nox change runs.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -R "$root/vendor/webrtc-ice" "$work/webrtc-ice"
printf '\n[workspace]\n' >> "$work/webrtc-ice/Cargo.toml"
cp "$root/Cargo.lock" "$work/webrtc-ice/Cargo.lock"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/vendor-ice}"
cd "$work/webrtc-ice"
if [ $# -eq 0 ]; then
    set -- test_lite_selects_pair_on_first_authenticated_check
fi
cargo test --lib -- "$@"
