#!/usr/bin/env bash
# Checks that the nox workspace [patch.crates-io] revs for webrtc and webrtc-sctp
# equal the ones in libs/rust/Cargo.toml at the kps tag nox-kps pins (for a
# crate vendored under vendor/<crate>, its NOX_VENDOR_BASE names the rev),
# and that Cargo.lock resolved that tag to the commit it names upstream (a
# moved tag fails here). A kps bump that forgets the patches fails here
# instead of at runtime.
#
# Usage: scripts/check-kps-patches.sh            (fetches the upstream file and tag)
#        KPS_CARGO_TOML=path KPS_TAG_COMMIT=<sha> scripts/check-kps-patches.sh   (offline)
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
locked="$(grep -A2 '^name = "kps"$' "$root/Cargo.lock" | sed -n 's/^source = ".*#\([0-9a-f]\{40\}\)"$/\1/p')"
if [[ -n "${KPS_TAG_COMMIT:-}" ]]; then
  tag_commit="$KPS_TAG_COMMIT"
else
  tag_commit="$(git ls-remote https://github.com/ethereum/kps "refs/tags/${tag}" | cut -f1)"
fi
if [[ -z "$locked" || "$locked" != "$tag_commit" ]]; then
  echo "kps: Cargo.lock pins '${locked}' but tag ${tag} is '${tag_commit}'" >&2
  status=1
else
  echo "kps: Cargo.lock commit $locked is tag ${tag}"
fi
for crate in webrtc webrtc-sctp; do
  ours="$(rev_of "$crate" "$(cat "$root/Cargo.toml")")"
  if [[ -z "$ours" && -f "$root/vendor/$crate/NOX_VENDOR_BASE" ]] \
    && grep -q "^$crate = { path = \"vendor/$crate\" }" "$root/Cargo.toml"; then
    ours="$(tr -d '[:space:]' < "$root/vendor/$crate/NOX_VENDOR_BASE")"
  fi
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
