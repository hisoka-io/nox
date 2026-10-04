#!/usr/bin/env bash
# Smoke test for a built nox-kps image: init once, check-config, run with a
# read-only root filesystem as uid 10002, healthcheck, restart, and confirm the
# certhash is unchanged. Needs Docker and host networking (Linux).
#
# Usage: scripts/container-smoke.sh <image>
set -euo pipefail

image="${1:?usage: container-smoke.sh <image>}"
name="nox-kps-smoke-$$"
vol_id="nox-kps-smoke-identity-$$"
vol_b="nox-kps-smoke-bundles-$$"
work="$(mktemp -d)"
udp_port="${SMOKE_UDP_PORT:-25005}"
admin_port="${SMOKE_ADMIN_PORT:-25006}"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm -f "$vol_id" "$vol_b" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/config.toml" <<TOML
listen = "127.0.0.1:${udp_port}"
advertise = ["127.0.0.1"]
allow_private_advertise = true
admin_listen = "127.0.0.1:${admin_port}"
TOML
chmod 0644 "$work/config.toml"

common=(--network host --read-only --tmpfs /tmp:size=16m --cap-drop ALL
  --security-opt no-new-privileges:true
  -v "$work/config.toml:/etc/nox-kps/config.toml:ro"
  -v "$vol_id:/var/lib/nox-kps" -v "$vol_b:/var/lib/nox-kps/keccak")

echo "== image size"
size=$(docker image inspect "$image" --format '{{.Size}}')
echo "$size bytes"
if (( size > 150 * 1024 * 1024 )); then echo "image larger than 150 MB" >&2; exit 1; fi

echo "== init"
docker run --rm "${common[@]}" "$image" nox-kps init | tee "$work/init.txt"
first=$(sed -n 's/^certhash: //p' "$work/init.txt")
[[ -n "$first" ]] || { echo "init printed no certhash" >&2; exit 1; }
if docker run --rm "${common[@]}" "$image" nox-kps init; then
  echo "a second init must refuse to replace the key" >&2; exit 1
fi

echo "== check-config"
docker run --rm "${common[@]}" "$image" nox-kps check-config

echo "== run"
docker run -d --name "$name" "${common[@]}" "$image" >/dev/null
for _ in $(seq 1 30); do
  if docker exec "$name" nox-kps healthcheck; then break; fi
  sleep 1
done
docker exec "$name" nox-kps healthcheck
uid=$(docker exec "$name" id -u)
[[ "$uid" == "10002" ]] || { echo "runs as uid $uid, expected 10002" >&2; exit 1; }

echo "== restart keeps the certhash"
docker restart "$name" >/dev/null
for _ in $(seq 1 30); do
  if docker exec "$name" nox-kps healthcheck; then break; fi
  sleep 1
done
second=$(docker exec "$name" nox-kps address | sed -n 's/^address: .*:\(uEi[^ ]*\)$/\1/p' | head -1)
[[ "$first" == "$second" ]] || { echo "certhash changed: $first -> $second" >&2; exit 1; }
docker stop -t 15 "$name" >/dev/null
echo "container smoke passed (certhash $first)"
