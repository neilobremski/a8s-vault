# ADR 0001: a8s-vault, an encrypted storage seat on A8S

- **Status:** Proposed (draft for review). ADR 0002 supersedes §4.2 (UUID dropped: the container is the seat), §4.3, and the command surface in §4.6.
- **Date:** 2026-10-08
- **Context repos:** witw-llc/ar3 (a8s 0.1.103), neilobremski/a8s-browser 0.3.3 (structural reference)

## 1. Context

We want an A8S node (`vault`) that any agent on the network can use to keep
files for itself. Any agent can use it without installing anything beyond
`tell` and `openssl`.

The proposed model:

1. `tell vault /public-key` returns the vault's public key (`vault.pem`).
2. The sender encrypts a file to that key and `/store`s it under a
   **vault UUID**. The container is identified by **(sender name, UUID)**.
3. To `/retrieve`, the sender attaches **its own public key**. The vault
   decrypts the file and re-encrypts it to that key, so the file is
   protected in transit back to the sender.
4. At rest, files are encrypted to the vault's key. The private key lives
   separately in `~/.config/a8s-vault`.

The premise is that A8S already requires authentication (MQTT credentials
and so on), so sender names can be trusted.

## 2. What a8s actually gives us (verified against the code)

| Fact | Where | Consequence for the vault |
|---|---|---|
| `from` is force-stamped from outbox ownership, but only for **local** nodes | `docs/a8s.md` "Mental model"; `mailbox._stamp_from` | Sender names can be trusted on one machine |
| A node reached over a remote **asserts its own name**. "The allowlist is a filter, not proof of identity, and the broker's own access control is what keeps strangers off the topic." | a8s-browser README, Trust | Over MQTT/S3/folder, **anyone holding broker credentials can claim to be `neil`**. Broker auth admits you to the network. It does not tie you to a name. |
| MQTT subscribes to **one shared topic** (`transports/mqtt.py: client.subscribe(self._topic)`). Every node that doesn't own the recipient logs `NOT_LOCAL` / sends `no_local_recipient`. | `docs/a8s.md` remotes, receipts | **Every node on the network receives every envelope**: command text, UUIDs and filenames |
| A name may live on several machines at once, and every machine holding it gets a copy | `docs/a8s.md` s3 remote | A second node registered as `vault` gets every vault request and can answer them |
| Message bodies are archived in `conversations.sqlite3` (default 50,000 rows), on the sending and receiving machines | `a8s convo`, `convo_max_rows` | UUIDs and filenames persist in plaintext logs |
| Attachments cross clusters via storage services, including `tempfile_org` (a public link) and presigned S3 (24h) | `docs/a8s.md` "Storage services" | Ciphertext is often publicly fetchable for hours, so confidentiality depends entirely on the crypto |
| `max_file_bytes` default is **50 MB**; `tell --split` chunks larger files | `settings.py` | v1 limit, or chunking is needed |
| The wake argv gets `$SENDER $RECIPIENT $MESSAGE $TIMESTAMP $AGE $META $NOW` plus per-node vars. Attachments arrive as `ATTACHED FILE: <abs path>` lines in `$MESSAGE`, under `.files/<msg ULID>/` | `definitions.py` | Same handler shape as a8s-browser. The ULID can be read from the path for idempotency. |
| A nonzero wake exit is retried (backoff, several attempts) and runs `handle` again | `daemon.py`; a8s-browser `handler._reply` | `handle` must be idempotent, and should exit 0 once the reply has gone out |

## 3. Headline gaps in the proposal as written

**G1. Remote sender names are not authenticated.** Broker credentials are
network-wide. Any seat on the network, or anything else holding the HiveMQ
credentials, can send `from: neil`.

**G2. The vault UUID is not a secret from anyone on the network.** It travels
in the plaintext command body. Every subscriber on the shared topic receives
it, the broker operator can read it, and it is archived in convo databases.
So it gives entropy against guessing, but no confidentiality.

**G3. G1 + G2 together mean `/retrieve`-to-any-key has no access control
against network members.** Anyone who saw one `/store neil <uuid> file.txt`
can send `from: neil`, `/retrieve <uuid> file.txt`, attach their own key,
and get the plaintext. **This is the gap that matters most.**

**G4. Vault impersonation.** A rogue node also registered as `vault` gets
copies of every request. If it answers `/public-key` with its own key first,
clients encrypt to the attacker. A client has no way to tell which `vault`
answered.

**G5. Integrity and availability.** Anyone can encrypt to the vault's public
key, because it is public. A spoofer who knows the UUID can overwrite or
delete someone else's files. Encryption shows that a blob is well-formed.
It does not show who made it.

**G6. A private key on the same host only protects data at rest, not against
the host.** The vault key next to the data protects backups, synced folders
and stolen disks. It does not stop any process running as the same Unix user
from reading it, and that includes other agents (r4t rosters, Claude sessions)
on the vault machine.

## 4. Decision (proposed)

### 4.1 Crypto: the `openssl` CLI, with one fixed hybrid format

Neil's lean, adopted. It matches the stdlib-only Python rule (the vault
shells out to `openssl`), and clients need no installs on macOS or Linux.

Format **`A8S-VAULT-1`** (a single file, readable with `head`/`tail`):

```
A8S-VAULT-1\n
base64( RSA-OAEP(SHA-256, MGF1-SHA-256)( "<enc_key_hex>:<mac_key_hex>:<iv_hex>" ) )\n
hex( HMAC-SHA256(mac_key, ciphertext) )\n
<AES-256-CBC ciphertext>
```

Encrypt-then-MAC. The MAC is checked **before** decrypting, and the output
file is written only after the check passes. Keys are RSA-3072, as PEM
(`vault.pem` and `<sender>.pem` are plain SubjectPublicKeyInfo, not
certificates, which matches the UX in the proposal).

**Prototype verified on this VM:** `docs/adr/0001-prototype/seal.sh` and
`open.sh` (POSIX sh + openssl only).

| Check | OpenSSL 3.0.2 | LibreSSL 3.3.6 (what macOS ships) |
|---|---|---|
| seal → open round trip, 5 MB / 3 B / 0 B | ok | ok |
| Cross-implementation (seal on one, open on the other) | ok both directions | ok both directions |
| `pkeyutl` OAEP-SHA256 wrap/unwrap | ok | ok |
| `enc -aes-256-cbc -K/-iv` output | byte-identical | byte-identical |
| HMAC via `dgst -mac HMAC -macopt hexkey:` | identical | identical |
| 1-byte tamper | exit 3, no output file | n/a (same script) |
| `dgst -sha256 -sign` / `-verify` (for 4.3) | ok | ok, cross-verified |

**Pitfalls found while testing (why not the "obvious" recipes):**

- `openssl enc -aes-256-gcm` on LibreSSL **runs silently and emits no tag**,
  so the output is unauthenticated. `enc` cannot be used for AEAD on either
  implementation.
- `openssl cms -aes-256-gcm` (AuthEnvelopedData) from OpenSSL 3 **cannot be
  decrypted by LibreSSL 3.3.6**. LibreSSL's own `cms -aes-256-gcm` output is
  **rejected by OpenSSL 3**. GCM over CMS is not portable.
- `openssl cms` with AES-CBC is portable but **unauthenticated**: a tampered
  file decrypts with exit 0 to corrupted plaintext. It also needs X.509
  certificates, not bare `.pem` keys.
- On a failed GCM check, OpenSSL 3 `cms -decrypt` **still writes the full
  plaintext to `-out`** (exit 4). If GCM is ever used, decrypt to a temp file
  and rename only on exit 0.
- LibreSSL 3.3.6 has no X25519 in `genpkey`, so we stay on RSA.

### 4.2 Container identity: (sender, UUID), stored hashed. **Superseded by [ADR 0002](0002-ephemeral-agent-identity-and-recovery.md)**: one container per seat, and vouchers replace the UUID

- Container dir: `~/.local/share/a8s-vault/containers/<sha256(sender_lower + "\0" + uuid)>/`.
  The disk never shows UUIDs or sender names, and path-injection from
  `acme:phil`-style senders is impossible.
- The UUID must parse as **UUIDv4** (122 random bits). `/new` returns a fresh
  one for agents that don't want to generate their own.
- Filenames inside a container stay plaintext (sanitized to a basename). They
  are already plaintext on the wire (see G2).
- `/list <uuid>` lists one container. There is **no** cross-container
  listing, because that would make the UUID pointless.

### 4.3 Owner key pinning (closes G3, G5). **Superseded by [ADR 0002](0002-ephemeral-agent-identity-and-recovery.md)**, because ephemeral agents can't keep a key

The **first `/store` into a new container must also attach the owner's public
key**. The vault pins its fingerprint to that container. After that:

- `/retrieve` **always encrypts to the pinned key**. An attached key is
  optional. If one is attached and does not match, the request is refused
  with the pinned fingerprint shown. A spoofer who knows the UUID gets
  nothing they can open.
- `/store` (overwrite) and `/delete` into an existing container need a
  detached signature by the owner key over `sha256(blob) + command line`
  (`seal --sign` does this). Without one, a spoofer can't damage data.
- Cost: lose the owner private key and you lose the container. That is
  intentional, and `/help` says so.

Option B is the proposal as written (any key at retrieve, no signature). It
is simpler, but G3 then stands, so the vault is only as safe as "nobody else
on the broker" (single-tenant network). If chosen, that needs to be explicit
in the README.

### 4.4 Vault authenticity (closes G4)

- `/public-key` replies with `vault.pem` and its **SHA-256 fingerprint**
  (of the DER SPKI). The fingerprint is also published out of band (README,
  install output, `a8s-vault doctor`).
- The client helper **pins the vault fingerprint on first use** (TOFU) in
  `~/.config/a8s-vault/known_vaults`. It warns loudly if the fingerprint
  changes.
- Every vault reply carries a signature line over the reply body (and over
  attachment hashes), so clients can confirm they're talking to the real vault.

### 4.5 At rest

- `/store` checks the `A8S-VAULT-1` header and the HMAC (an unwrap only, no
  decryption). The sender's sealed blob is then **stored as-is**, since it
  is already encrypted to the vault key. No plaintext touches disk on store.
  The write is atomic (`tmp` + `rename`) and idempotent on message ULID.
- `/retrieve` verifies the MAC, then runs `decrypt | re-encrypt` as a pipe to
  the owner key. Plaintext lives only in a pipe and, at most, a temp dir with
  mode 0700 that is removed on exit.
- Keys: `~/.config/a8s-vault/vault.key` (0600, dir 0700), separate from the
  data dir. G6 is mitigated by **recommending that the vault run as a
  dedicated Unix user** (or in a container). That user is the real
  boundary. No passphrase in v1, because wakes are unattended. macOS
  Keychain could come later.
- Key rotation: re-wrap line 2 of each blob (the small header) under the new
  key. The bodies stay as they are. The old key is kept read-only until the
  re-wrap is done.

### 4.6 Command surface (helpful by default). **Superseded by [ADR 0002](0002-ephemeral-agent-identity-and-recovery.md)** (`/connect`, `/authenticate`, sealed commands)

```
/help                         what this is, the commands, and the openssl recipe
/help recipe                  the exact seal/open commands for openssl-only agents
/public-key                   -> vault.pem + fingerprint
/new                          -> a fresh UUID (save it; the vault cannot recover it for you)
/store <uuid> <name>          attach <name>.enc (+ owner.pem on first store; + .sig after)
/retrieve <uuid> <name>...    -> <name>.enc sealed to the pinned owner key
/list <uuid>                  names, sizes, stored-at
/delete <uuid> <name>         signed
```

- Anything that isn't a command gets `/help` back, not an error.
- Every error says what to do next. Examples: "this attachment isn't
  A8S-VAULT-1; seal it first: `a8s-vault seal vault.pem file.txt`" and
  "plaintext was attached; it was **not** stored, and it has already crossed
  the network".
- The reply is sent with `tell <sender> - --attach ...`. Exit 0 once the
  reply is out (same pattern as a8s-browser).
- Quotas per sender (`A8S_VAULT_QUOTA_MB`, default e.g. 500) and a max file
  count, so one seat can't fill the disk.

### 4.7 Packaging (mirrors a8s-browser)

`a8s-vault` (bash/PS polyglot launcher), `.cmd`/`.ps1`, `get.sh` (clone to
`~/.a8s-vault` + PATH line), `install.sh`, `src/{cli,handler,crypto,store,doctor}.py`,
`definitions/vault.json`, `tests/run`, `tools/lint`, PII scan, test and release
workflows, `VERSION` bump per merge. The same CLI is the client:
`a8s-vault keygen | seal | open | sign | verify`. It wraps the same openssl
calls that `/help recipe` prints, so agents without the CLI aren't blocked.

```json
{ "invoke": ["$A8S_VAULT", "handle", "--node", "$RECIPIENT", "--from", "$SENDER",
             "--message", "$MESSAGE", "--quota-mb=$A8S_VAULT_QUOTA_MB?"],
  "max_wake_seconds": 300, "idle": { "timeout": 0 } }
```

## 5. Alternatives considered

| Option | Verdict |
|---|---|
| Python `cryptography` (AES-GCM, X25519) | Best primitives, but breaks stdlib-only, and clients would need it too. Rejected for v1. |
| `age` | Best UX and modern crypto, but not preinstalled anywhere. Could be an alternate format later. |
| `gpg` | Present on Linux, not on macOS. Keyring UX is heavy for agents. |
| `openssl cms` | Standard format, but not portable with GCM and not authenticated with CBC (both verified above). Needs certificates. |
| Plaintext `/store` over TLS-to-broker | Broker, every subscriber and public storage links all see it. Rejected. |
| UUID as the only secret | See G2. Not enough on a shared topic. |

## 6. Risks and tradeoffs that remain

1. **Home-grown construction.** CBC+HMAC with RSA-OAEP is standard
   practice, but our framing is new. Mitigations: freeze the format, commit
   test vectors, keep the code small, and refuse to decrypt anything that
   fails the MAC.
2. **Keys on argv.** `-K`, `-iv` and `-macopt hexkey:` put the ephemeral
   per-file keys in `ps` output for a few milliseconds. This only matters on
   a shared multi-user host, and goes away with a dedicated vault user.
   Follow-up: test whether `-kfile`/`fd:` variants behave the same on LibreSSL.
3. **Windows.** A stock Windows install has no `openssl`. It ships with Git
   for Windows, but not on PATH for `cmd`. `doctor` should find it there.
4. **Metadata leaks** (filenames, UUIDs, commands, sizes, timing) are
   accepted in v1. Fixing them means a sealed request envelope, which costs
   more friction.
5. **50 MB per attachment.** Bigger files need `--split` and reassembly,
   which is deferred.
6. **Lost UUID or owner key means lost data.** This is intended. `/help` and
   `/new` say so up front.
7. **LibreSSL drift.** Only 3.3.6 was tested. CI should run the seal/open
   matrix against both implementations.

## 7. Open questions for Neil

1. ~~**Retrieval policy**~~: resolved by ADR 0002. Replies are sealed to the
   current connect key of an authenticated session.
2. ~~**Signed overwrite/delete**~~: resolved by ADR 0002. A sealed command
   inside an authenticated session authorises it.
3. **Overwrite semantics:** replace, refuse (`--force` to replace), or keep N
   versions?
4. **Run-as:** is a dedicated Unix user acceptable as the recommended
   deployment?
5. **Seat name and host:** `vault` on which machine (and which network)?
