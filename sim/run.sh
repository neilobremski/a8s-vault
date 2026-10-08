#!/bin/sh
# sim/run.sh [clean] — a simulated A8S network in Docker:
#   sim-broker   mosquitto with a password (network access is the security boundary)
#   sim-vault    the vault seat, run by a8s as the dedicated Unix user `vault`
#   sim-agent    agent1, a filedrop seat on a throwaway container (wiped mid-test)
#   sim-mallory  another seat on the network that has seen agent1's voucher
#   sim-sniffer  a credentialed subscriber recording every envelope on the topic
# Only /durable (a host dir: vault fingerprint + current voucher) survives the wipe.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(dirname "$HERE")
AR3=${AR3_DIR:-$(dirname "$REPO")/ar3}
PY=${SIM_PYTHON_IMAGE:-public.ecr.aws/docker/library/python:3.12-slim}
MQ=${SIM_MOSQUITTO_IMAGE:-public.ecr.aws/docker/library/eclipse-mosquitto:2}
NET=a8s-vault-sim; VOL=a8s-vault-sim-shared; RUN="$HERE/.run"

cleanup() {
  docker rm -f sim-broker sim-vault sim-agent sim-mallory sim-sniffer >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
}
cleanup
[ "${1:-}" = clean ] && exit 0
[ -n "${KEEP:-}" ] || trap cleanup EXIT
[ -x "$AR3/a8s" ] || { echo "need an ar3 checkout at $AR3 (set AR3_DIR)" >&2; exit 2; }

step() { printf '\n== %s\n' "$*"; }
rm -rf "$RUN"; mkdir -p "$RUN/mosquitto" "$RUN/durable"
docker build -q -t a8s-vault-sim --build-arg BASE="$PY" "$HERE" >/dev/null
docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null

PASS=$(openssl rand -hex 16)
printf 'listener 1883\nallow_anonymous false\npassword_file /mosquitto/config/passwd\n' \
  > "$RUN/mosquitto/mosquitto.conf"
docker run --rm -v "$RUN/mosquitto:/m" "$MQ" sh -c \
  "mosquitto_passwd -b -c /m/passwd a8s $PASS && chown mosquitto:mosquitto /m/passwd && chmod 600 /m/passwd"
docker run -d --name sim-broker --network "$NET" -v "$RUN/mosquitto:/mosquitto/config" "$MQ" >/dev/null
sleep 1
docker run -d --name sim-sniffer --network "$NET" "$MQ" \
  mosquitto_sub -h sim-broker -u a8s -P "$PASS" -t '#' -v >/dev/null

node() {  # node <container> <seat> <role> <user> [docker run args...]
  name=$1; seat=$2; role=$3; user=$4; shift 4
  docker run -d --name "$name" --network "$NET" -v "$AR3:/opt/ar3:ro" -v "$REPO:/opt/a8s-vault:ro" \
    -v "$VOL:/shared" "$@" a8s-vault-sim sleep infinity >/dev/null
  home=$(docker exec "$name" sh -c "getent passwd $user | cut -d: -f6")
  docker exec "$name" sh -c "chmod 1777 /shared && umask 077 && printf %s '$PASS' > $home/.mqtt-pass \
    && chown $user $home/.mqtt-pass"
  docker exec -u "$user" -e HOME="$home" "$name" /opt/a8s-vault/sim/node.sh "$seat" "$role"
}
vault() { docker exec -u vault -e HOME=/home/vault sim-vault /opt/a8s-vault/a8s-vault "$@"; }
agent() { docker exec "$1" python3 /opt/a8s-vault/sim/agent_flow.py "$2"; }

step "vault seat, as Unix user 'vault'"
node sim-vault vault vault vault
vault fingerprint > "$RUN/durable/vault.fingerprint"
vault voucher issue agent1 > "$RUN/durable/voucher"
vault admin add neil >/dev/null
echo "fingerprint $(cat "$RUN/durable/vault.fingerprint"); first voucher issued with the local CLI"

step "agent1, first VM"
node sim-agent agent1 agent root -v "$RUN/durable:/durable"
sleep 2
agent sim-agent first

step "agent1's VM is wiped and replaced"
docker rm -f sim-agent >/dev/null
node sim-agent agent1 agent root -v "$RUN/durable:/durable"
sleep 2
agent sim-agent after-wipe
agent sim-agent burned

step "mallory, another seat holding agent1's voucher"
node sim-mallory mallory agent root -v "$RUN/durable:/durable:ro"
sleep 2
agent sim-mallory mallory

step "vault host and wire checks"
ok() { echo "ok   $*"; }
fail() { echo "FAIL $*"; exit 1; }
docker exec sim-vault sh -c 'ps -eo user:12,args | grep -v grep | grep "a8s"' | grep -q '^vault ' \
  && ok "a8s daemon for the vault seat runs as user 'vault'" || fail "daemon user"
perms=$(docker exec sim-vault stat -c '%U %a' /home/vault/.config/a8s-vault/vault.key)
[ "$perms" = "vault 600" ] && ok "vault.key is vault-owned, mode 600" || fail "key perms: $perms"
if docker exec -u nobody sim-vault cat /home/vault/.config/a8s-vault/vault.key >/dev/null 2>&1; then
  fail "another Unix user can read vault.key"; else ok "another Unix user cannot read vault.key"; fi
if docker exec sim-vault grep -rqs "PRIVATE KEY v2" /home/vault /shared; then
  fail "plaintext found at rest"; else ok "no plaintext in vault data or shared attachment storage"; fi
docker logs sim-sniffer > "$RUN/wire.log" 2>&1
if grep -q "PRIVATE KEY v2" "$RUN/wire.log"; then fail "plaintext on the wire"; fi
vouchers=$(docker exec sim-mallory cat /durable/voucher /durable/burned)
[ "$(echo "$vouchers" | grep -c '^a8sv1-')" = 2 ] || fail "could not read the vouchers to check"
for v in $vouchers; do
  if grep -q "$v" "$RUN/wire.log"; then fail "voucher on the wire"; fi
done
ok "sniffer saw $(grep -c . "$RUN/wire.log") envelope(s): no file content, no voucher in the clear"
vault seat list
printf '\nSIMULATION PASSED\n'
