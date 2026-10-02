#!/usr/bin/env bash
# Verifies release metadata before an image or release is published.
#
#   scripts/check-release.sh            # crate versions agree with each other
#   scripts/check-release.sh v0.4.0     # ...and with the tag, and CHANGELOG.md has a [0.4.0] section
set -euo pipefail

cd "$(dirname "$0")/.."

tag=${1:-}

metadata=$(cargo metadata --no-deps --format-version 1 --locked)

workspace_version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
if [[ -z "$workspace_version" ]]; then
    echo "Cargo.toml has no [workspace.package] version" >&2
    exit 1
fi

failed=0

while IFS=$'\t' read -r name version; do
    if [[ "$version" != "$workspace_version" ]]; then
        echo "$name is at $version, workspace is at $workspace_version (use version.workspace = true)" >&2
        failed=1
    fi
done < <(jq -r '.packages[] | [.name, .version] | @tsv' <<<"$metadata")

# Path dependencies between workspace crates carry a version requirement so the crates can be
# published. It must name the workspace version, or crates.io builds would pull an older release.
while IFS=$'\t' read -r from dep req; do
    if [[ "$req" != "^$workspace_version" ]]; then
        echo "$from depends on $dep with requirement '$req', expected '$workspace_version'" >&2
        failed=1
    fi
done < <(jq -r '
    (.packages | map(.name)) as $members
    | .packages[] | .name as $from
    | .dependencies[]
    | select(.path != null and (.name as $n | $members | index($n)))
    | select(.req != "*")
    | [$from, .name, .req] | @tsv' <<<"$metadata")

if [[ -n "$tag" ]]; then
    tag_version=${tag#refs/tags/}
    tag_version=${tag_version#v}
    if [[ "$tag_version" != "$workspace_version" ]]; then
        echo "tag $tag does not match the crate version $workspace_version" >&2
        failed=1
    fi
    if ! grep -Eq "^## \[$(printf '%s' "$tag_version" | sed 's/[.]/\\./g')\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md; then
        echo "CHANGELOG.md has no '## [$tag_version] - YYYY-MM-DD' section" >&2
        failed=1
    fi
fi

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi

echo "release metadata OK: version $workspace_version${tag:+, tag $tag}"
