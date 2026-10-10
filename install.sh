#!/usr/bin/env bash
# Source this from your shell rc to put a8s-vault on PATH.
#
#   source <path-to-repo>/install.sh

if [ -n "$ZSH_VERSION" ]; then
  A8S_VAULT_ROOT="$(cd "$(dirname "${(%):-%x}")" && pwd)"
else
  A8S_VAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

export A8S_VAULT_ROOT

# Some rc files read each other, so this is sourced more than once per shell.
case ":$PATH:" in
  *":$A8S_VAULT_ROOT:"*) ;;
  *) export PATH="$A8S_VAULT_ROOT:$PATH" ;;
esac
