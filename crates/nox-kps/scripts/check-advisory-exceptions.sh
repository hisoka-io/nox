#!/usr/bin/env bash
# Fails when an advisory exception in deny.toml has passed its expires= date,
# so every exception is re-reviewed instead of lingering.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
today="${TODAY:-$(date -u +%Y-%m-%d)}"
status=0
found=0
while IFS= read -r line; do
  id="$(printf '%s' "$line" | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' | head -1)"
  expires="$(printf '%s' "$line" | grep -oE 'expires=[0-9]{4}-[0-9]{2}-[0-9]{2}' | cut -d= -f2)"
  [[ -z "$id" ]] && continue
  found=$((found + 1))
  if [[ -z "$expires" ]]; then
    echo "$id: no expires=YYYY-MM-DD in deny.toml" >&2
    status=1
  elif [[ "$expires" < "$today" || "$expires" == "$today" ]]; then
    echo "$id: exception expired on $expires (today $today); re-review it" >&2
    status=1
  else
    echo "$id: exception valid until $expires"
  fi
done < <(grep -E '^\s*\{ id = "RUSTSEC-' "$root/deny.toml")
echo "$found advisory exception(s) checked"
exit "$status"
