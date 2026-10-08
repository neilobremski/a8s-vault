#!/bin/sh
# open.sh <private.key> <in> <out>   -- writes <out> only if the MAC verifies
set -eu
O="${OPENSSL:-openssl}"; key="$1"; in="$2"; out="$3"
[ "$(head -n 1 "$in")" = "A8S-VAULT-1" ] || { echo "not an a8s-vault v1 file" >&2; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
hdr=$(head -n 3 "$in" | wc -c | tr -d ' ')
tail -c +$((hdr + 1)) "$in" > "$tmp/body"
secret=$(sed -n 2p "$in" | "$O" base64 -d -A | "$O" pkeyutl -decrypt -inkey "$key" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256)
ek=${secret%%:*}; rest=${secret#*:}; mk=${rest%%:*}; iv=${rest#*:}
mac=$("$O" dgst -sha256 -mac HMAC -macopt "hexkey:$mk" "$tmp/body" | sed 's/.*= //')
[ "$mac" = "$(sed -n 3p "$in")" ] || { echo "MAC mismatch: corrupted or tampered" >&2; exit 3; }
"$O" enc -d -aes-256-cbc -K "$ek" -iv "$iv" -in "$tmp/body" -out "$tmp/plain"
mv "$tmp/plain" "$out"
