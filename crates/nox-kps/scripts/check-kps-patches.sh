#!/usr/bin/env bash
# Checks that the workspace [patch.crates-io] revs for webrtc and webrtc-sctp
# equal the ones in libs/rust/Cargo.toml at the kps tag this workspace pins.
# A kps bump that forgets the patches fails here instead of at runtime.
#
# Usage: scripts/check-kps-patches.sh            (fetches the upstream file)
#        KPS_CARGO_TOML=path scripts/check-kps-patches.sh   (offline)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tag="$(sed -n 's/^kps = { git = "[^"]*", tag = "\([^"]*\)" }.*/\1/p' "$root/crates/nox-kps/Cargo.toml")"
if [[ -z "$tag" ]]; then
  echo "cannot find the kps tag in crates/nox-kps/Cargo.toml" >&2
  exit 1
fi

if [[ -n "${KPS_CARGO_TOML:-}" ]]; then
  upstream="$(cat "$KPS_CARGO_TOML")"
else
  url="https://raw.githubusercontent.com/ethereum/kps/${tag}/libs/rust/Cargo.toml"
  upstream="$(curl -fsSL --retry 3 "$url")"
fi

rev_of() { # <crate> <text>
  printf '%s\n' "$2" | sed -n "s/^$1 = { git = \"[^\"]*\", rev = \"\([0-9a-f]\{40\}\)\" }.*/\1/p"
}

status=0
for crate in webrtc webrtc-sctp; do
  ours="$(rev_of "$crate" "$(cat "$root/Cargo.toml")")"
  theirs="$(rev_of "$crate" "$upstream")"
  if [[ -z "$ours" || -z "$theirs" ]]; then
    echo "$crate: patch rev missing (workspace: '${ours}', kps ${tag}: '${theirs}')" >&2
    status=1
  elif [[ "$ours" != "$theirs" ]]; then
    echo "$crate: workspace patches rev $ours but kps ${tag} uses $theirs" >&2
    status=1
  else
    echo "$crate: $ours matches kps ${tag}"
  fi
done
exit "$status"
