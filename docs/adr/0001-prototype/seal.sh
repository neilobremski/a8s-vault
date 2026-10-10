#!/bin/sh
# seal.sh <recipient.pem> <in> <out>   -- needs only sh + openssl/libressl
set -eu
O="${OPENSSL:-openssl}"; pub="$1"; in="$2"; out="$3"
ek=$("$O" rand -hex 32); mk=$("$O" rand -hex 32); iv=$("$O" rand -hex 16)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
"$O" enc -aes-256-cbc -K "$ek" -iv "$iv" -in "$in" -out "$tmp/body"
mac=$("$O" dgst -sha256 -mac HMAC -macopt "hexkey:$mk" "$tmp/body" | sed 's/.*= //')
wrapped=$(printf '%s:%s:%s' "$ek" "$mk" "$iv" | "$O" pkeyutl -encrypt -pubin -inkey "$pub" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 | "$O" base64 -A)
{ printf 'A8S-VAULT-1\n%s\n%s\n' "$wrapped" "$mac"; cat "$tmp/body"; } > "$out"
