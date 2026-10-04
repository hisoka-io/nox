#!/usr/bin/env bash
# Smoke test for nox-kps in a built nox image: the image carries all three
# binaries; nox-kps runs as uid 10002 with a read-only root filesystem and its
# identity in a named volume. Checks init (once only), address, check-config,
# run, healthcheck (admin /healthz, then an end-to-end QUIC dial of the KPS
# listener whose GET /health reaches a mock node ingress), the uid, and that a
# restart keeps the certhash.
#
# The configuration comes from NOX_KPS__* variables, so the test needs no bind
# mounts and runs against any Docker engine with host networking.
#
# Usage: scripts/kps-container-smoke.sh <image>
#        DOCKER=docker.exe scripts/kps-container-smoke.sh <image>   (another client binary)
set -euo pipefail

image="${1:?usage: kps-container-smoke.sh <image>}"
docker="${DOCKER:-docker}"
mock_image="${SMOKE_MOCK_IMAGE:-busybox:1.36.1}"
suffix="$$"
name="nox-kps-smoke-${suffix}"
mock="nox-kps-smoke-ingress-${suffix}"
vol_id="nox-kps-smoke-identity-${suffix}"
vol_b="nox-kps-smoke-bundles-${suffix}"
udp_port="${SMOKE_UDP_PORT:-25005}"
admin_port="${SMOKE_ADMIN_PORT:-25006}"
ingress_port="${SMOKE_INGRESS_PORT:-25002}"

cleanup() {
  "$docker" rm -f "$name" "$mock" >/dev/null 2>&1 || true
  "$docker" volume rm -f "$vol_id" "$vol_b" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_healthy() { # <args to nox-kps healthcheck>
  for _ in $(seq 1 30); do
    if "$docker" exec "$name" nox-kps healthcheck "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  "$docker" exec "$name" nox-kps healthcheck "$@"
}

env_args=(
  -e "NOX_KPS__LISTEN=127.0.0.1:${udp_port}"
  -e "NOX_KPS__ADVERTISE=127.0.0.1"
  -e "NOX_KPS__ALLOW_PRIVATE_ADVERTISE=true"
  -e "NOX_KPS__ADMIN_LISTEN=127.0.0.1:${admin_port}"
  -e "NOX_KPS__UPSTREAM_INGRESS=127.0.0.1:${ingress_port}"
  -e "NOX_KPS__UPSTREAM_TOPOLOGY=127.0.0.1:${ingress_port}"
  -e "NOX_KPS__LOG_FORMAT=text"
)
common=(--network host --read-only --tmpfs /tmp:size=16m --cap-drop ALL
  --security-opt no-new-privileges:true --user 10002:10002
  -v "${vol_id}:/var/lib/nox-kps" -v "${vol_b}:/var/lib/nox-kps/keccak")

echo "== image carries the node binaries"
"$docker" run --rm "$image" nox --version
"$docker" run --rm --entrypoint test "$image" -x /usr/local/bin/price_server
"$docker" run --rm "$image" nox-kps --version

echo "== mock node ingress (GET /health answers 200)"
"$docker" run -d --name "$mock" --network host "$mock_image" \
  sh -c "mkdir -p /www && echo ok > /www/health && exec httpd -f -p 127.0.0.1:${ingress_port} -h /www" >/dev/null

echo "== init"
init_out=$("$docker" run --rm "${common[@]}" "${env_args[@]}" "$image" nox-kps init)
printf '%s\n' "$init_out"
certhash=$(printf '%s\n' "$init_out" | sed -n 's/^certhash: //p')
[[ -n "$certhash" ]] || { echo "init printed no certhash" >&2; exit 1; }
if "$docker" run --rm "${common[@]}" "${env_args[@]}" "$image" nox-kps init >/dev/null 2>&1; then
  echo "a second init must refuse to replace the key" >&2
  exit 1
fi
env_args+=(-e "NOX_KPS__EXPECTED_CERTHASH=${certhash}")

echo "== address"
address=$("$docker" run --rm "${common[@]}" "${env_args[@]}" "$image" nox-kps address)
printf '%s\n' "$address"
grep -Fq "address: 127.0.0.1:${udp_port}:${certhash}" <<<"$address" \
  || { echo "address does not carry the init certhash" >&2; exit 1; }

echo "== check-config"
"$docker" run --rm "${common[@]}" "${env_args[@]}" "$image" nox-kps check-config

echo "== run"
"$docker" run -d --name "$name" "${common[@]}" "${env_args[@]}" "$image" nox-kps run >/dev/null
wait_healthy
wait_healthy --kps
uid=$("$docker" exec "$name" id -u)
[[ "$uid" == "10002" ]] || { echo "nox-kps runs as uid $uid, expected 10002" >&2; exit 1; }
"$docker" exec "$name" sh -c 'test ! -r /var/lib/nox' \
  || { echo "uid 10002 can read the node's /var/lib/nox" >&2; exit 1; }

echo "== restart keeps the certhash"
"$docker" restart "$name" >/dev/null
wait_healthy --kps
second=$("$docker" exec "$name" nox-kps address | sed -n 's/^address: .*:\(uEi[^ ]*\)$/\1/p' | head -1)
[[ "$certhash" == "$second" ]] || { echo "certhash changed: $certhash -> $second" >&2; exit 1; }

echo "== graceful stop"
"$docker" stop -t 15 "$name" >/dev/null
code=$("$docker" inspect "$name" --format '{{.State.ExitCode}}')
[[ "$code" == "0" ]] || { echo "nox-kps exited with $code on SIGTERM" >&2; "$docker" logs "$name" | tail -20 >&2; exit 1; }
echo "container smoke passed (certhash $certhash)"
