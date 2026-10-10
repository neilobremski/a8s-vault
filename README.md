# a8s-vault

An A8S seat that stores files for agents, including agents on ephemeral VMs
that lose every local file. Everything after `/connect` is sealed end to end:
other seats on the shared topic, the broker, attachment storage and convo
archives only ever see ciphertext.

Design: [ADR 0001](docs/adr/0001-a8s-vault-design.md) (format, storage) and
[ADR 0002](docs/adr/0002-ephemeral-agent-identity-and-recovery.md) (sessions,
vouchers). Needs `python3` (stdlib only) and `openssl` (OpenSSL 3 or LibreSSL).

## How an agent uses it

```sh
tell vault /public-key                 # -> vault.pem; check the fingerprint
a8s-vault client pin vault.pem --fingerprint <F>
a8s-vault client connect               # throwaway key; a new /connect wipes the old session
a8s-vault client auth --voucher-file ~/durable/voucher
# reply: a8s-vault client open "$MESSAGE" --save-voucher ~/durable/voucher
a8s-vault client send "/store keys/ssh.pem" --file ~/.ssh/id_ed25519
a8s-vault client send "/retrieve keys/ssh.pem"
# reply: a8s-vault client open "$MESSAGE" --out ~/restore
```

Every vault reply arrives as a normal tell (`A8SV1:<base64>` plus any
`ATTACHED FILE:` lines); `client open` checks the vault's signature, decrypts
it with the current connection key and writes retrieved files. A reply sealed
to an earlier connection key (the vault's "you were disconnected" notice to a
wiped VM) exits 3 and can be ignored.

The only things an agent keeps outside its VM are the vault fingerprint and
its current voucher. Neither is a secret: a voucher is single-use, bound to the
seat it was issued for, and useless without access to the A8S network. Each
`/authenticate` burns the voucher and returns the next one; save it before
doing anything else. `/voucher new` mints spares (at most 10 unused per seat).

Sealed commands: `/authenticate <voucher>`, `/list`, `/store <name>`,
`/retrieve <name>`, `/delete <name>`, `/voucher new|list|revoke-all`,
`/logout`. `/store` overwrites an existing name. Names may contain `/`.
Plaintext: `/help`, `/help recipe` (raw openssl), `/public-key`, `/connect`.

## Running the vault

Run it as a **dedicated Unix user** so other agents on the host cannot read
its key or data, or swap its code:

```sh
sudo useradd --create-home vault
sudo -iu vault
git clone https://github.com/neilobremski/a8s-vault && cd a8s-vault
./a8s-vault init                                     # key + pepper in ~/.config/a8s-vault
a8s add vault ~/vault-seat "$PWD/definitions/vault.json" --A8S_VAULT="$PWD/a8s-vault"
a8s start vault
./a8s-vault voucher issue agent1                     # hand this to agent1 out of band
```

Admin is local only; none of it exists on the wire:

| Command | |
|---|---|
| `a8s-vault voucher issue <seat>` | Mint a voucher (bootstrap, or recover a locked-out seat) |
| `a8s-vault voucher purge <seat>` | Delete every voucher for the seat and reset its failure count |
| `a8s-vault seat list` / `seat disconnect <seat>` | Sessions; drop one |
| `a8s-vault admin add\|rm\|list <seat>` | Seats that receive alerts (burned-voucher reuse, /connect storms) |
| `a8s-vault fingerprint` | The key fingerprint agents pin |

`openssl enc` takes each per-message AES key as `-K` on its command line, so on
a shared host another user can read it from `/proc/<pid>/cmdline` while it
runs. Give the vault its own container or VM, or mount `/proc` with
`hidepid=2`.

## Tests

```sh
tests/run        # unit + handler/client flow with a fake tell
tools/lint
sim/run.sh       # Docker: credentialed mosquitto, vault as user `vault`,
                 # an agent whose container is wiped mid-run, a second seat
                 # holding agent1's voucher, and a sniffer on the topic
```

`sim/run.sh` expects an ar3 checkout beside this repo (or `AR3_DIR`). It pulls
images from `public.ecr.aws` (override with `SIM_PYTHON_IMAGE` /
`SIM_MOSQUITTO_IMAGE`).
