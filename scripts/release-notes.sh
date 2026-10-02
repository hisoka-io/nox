#!/usr/bin/env bash
# Prints the CHANGELOG.md section for one version, without its heading.
#
#   scripts/release-notes.sh 0.4.0-rc.2
set -euo pipefail

cd "$(dirname "$0")/.."

version=${1:?usage: release-notes.sh <version>}
version=${version#v}

notes=$(awk -v heading="## [$version]" '
    index($0, heading) == 1 { found = 1; next }
    found && /^## \[/ { exit }
    found { print }
' CHANGELOG.md)

if [[ -z "${notes//[[:space:]]/}" ]]; then
    echo "CHANGELOG.md has no notes for $version" >&2
    exit 1
fi

# Drop leading and trailing blank lines.
printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'
