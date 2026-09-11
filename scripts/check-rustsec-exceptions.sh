#!/usr/bin/env bash
set -euo pipefail

current_date=${NOX_SECURITY_POLICY_DATE:-$(date -u +%F)}

check_deadline() {
    local item=$1
    local deadline=$2
    local owner=$3
    if [[ ! "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ || -z "$owner" ]]; then
        echo "$item is missing a valid deadline or owner" >&2
        exit 1
    fi
    if [[ "$deadline" < "$current_date" ]]; then
        echo "$item exception expired on $deadline (owner: $owner)" >&2
        exit 1
    fi
}

while IFS= read -r exception; do
    advisory=$(printf '%s\n' "$exception" | sed -n 's/.*"\(RUSTSEC-[0-9-]*\)".*/\1/p')
    deadline=$(printf '%s\n' "$exception" | sed -n 's/.*expires=\([0-9-]*\).*/\1/p')
    owner=$(printf '%s\n' "$exception" | sed -n 's/.*owner=\([^ ]*\).*/\1/p')
    check_deadline "$advisory" "$deadline" "$owner"
done < <(sed -n '/^ignore = \[/,/^\]/p' deny.toml | grep 'RUSTSEC-')

for required in "core2 0.4.0" "keccak 0.1.5" "spin 0.9.8"; do
    grep -Fq "| Yanked \`$required\` |" SECURITY.md || {
        echo "yanked dependency $required is missing from SECURITY.md" >&2
        exit 1
    }
done

while IFS='|' read -r _ item _ _ owner deadline _; do
    item=${item#*\`}
    item=${item%\`*}
    owner=$(printf '%s' "$owner" | xargs)
    deadline=$(printf '%s' "$deadline" | xargs)
    check_deadline "yanked $item" "$deadline" "$owner"
done < <(grep '^| Yanked `' SECURITY.md)
