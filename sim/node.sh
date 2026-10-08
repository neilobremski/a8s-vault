#!/bin/sh
# node.sh <seat> vault|agent — runs inside a sim container.
set -eu
seat="$1"; role="$2"
a8s remote broker mqtt://sim-broker:1883 a8s-sim --user a8s --pass "$(cat "$HOME/.mqtt-pass")" >/dev/null
a8s storage shared /shared >/dev/null
mkdir -p "$HOME/seat"
if [ "$role" = vault ]; then
  /opt/a8s-vault/a8s-vault init
  a8s add "$seat" "$HOME/seat" /opt/a8s-vault/definitions/vault.json \
    --A8S_VAULT=/opt/a8s-vault/a8s-vault >/dev/null
else
  a8s add "$seat" "$HOME/seat" filedrop >/dev/null
fi
a8s start "$seat" >/dev/null
echo "node $seat ($role) up as $(id -un)"
