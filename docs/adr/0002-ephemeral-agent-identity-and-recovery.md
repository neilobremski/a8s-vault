# ADR 0002: Sealed sessions and vouchers for agents that lose their files

- **Status:** Proposed (draft for review). Rewritten from Neil's design of
  2026-10-08.
- **Amends:** ADR 0001 §4.3 (owner key pinning) and §5 (command surface).

## 1. Problem

Many vault clients run on ephemeral VMs and **lose every file between runs**,
including any private key they made. Pinning an owner key (ADR 0001 §4.3)
therefore means a lost VM is a lost vault. These agents do have a **durable
store**: it isn't on the VM and isn't encrypted, but no other agent knows
about it. They can also keep non-secret values in their instructions.

## 2. Decision

The vault's protocol is a **sealed session** between the seat and the
vault, unlocked by a **voucher**:

1. **`/connect`**: the agent attaches a fresh public key. The vault ties it
   to the sender seat. From then on, everything in both directions is
   sealed. This is the only command (with `/help` and `/public-key`) that
   is accepted in plaintext.
2. **`/authenticate <voucher>`** (sealed): proves the agent is entitled to
   the seat's container. A voucher is a high-entropy random string. The
   vault keeps only its hash.
3. **Authenticated session**: `/list`, `/store`, `/retrieve`, `/delete`, and
   `/voucher` (to get new ones). All requests and all replies are sealed.

Keys are throwaway. Each new VM runs `/connect` again with a new key. The
only thing that has to survive is the current voucher in the durable store.

### 2.1 Trust model

- **Access to the A8S network is the security boundary.** Being on the
  network at all requires whatever credentials its remotes and storage
  services are configured with: MQTT auth, S3 keys, the OAuth MCP bridge.
  The vault trusts seat names from inside that boundary. A remote set up
  without access credentials is an operator footgun the vault cannot fix,
  and `/help` and the README say so.
- **The voucher is not a secret.** It is a continuity factor bound to the
  seat. It tells the vault that this fresh connection belongs to the agent
  that owns the seat's container, and is not some other instance or a
  misrouted message. Like the UUID in ADR 0001, it may sit in plain,
  durable storage. Access is the voucher combined with the seat, and the
  seat is only reachable through network credentials.
- **What the sealed channel is for.** It is confidentiality in transit and at
  rest against everything that sees A8S traffic without being the
  endpoint: every node on the shared MQTT topic, the broker, storage
  services hosting attachments, and `conversations.sqlite3` archives.
  Reading those yields only ciphertext and voucher hashes.
- **A new `/connect` resets the session.** It wipes all connection and
  authentication state, so a hijacked connection only breaks the previous
  connection's access and grants nothing on its own.
- **The vault key is pinned by the client.** The agent keeps the vault's
  fingerprint as a non-secret value and seals only to it, so a second seat
  answering to `vault` sees ciphertext only.

### 2.2 Wire format

- **Agent to vault:** the body is `A8SV1:<base64>`, where the payload is an
  ADR 0001 `A8S-VAULT-1` blob sealed to the vault key:

  ```json
  {"cmd": "/retrieve notes.md", "conn": "<sha256 of connect key DER>",
   "ts": "2026-10-08T17:00:00Z", "nonce": "<128-bit hex>"}
  ```

  Use `openssl base64 -A` (one line, the same on OpenSSL and LibreSSL; macOS
  `base64` lacks `-w0`). A sealed command is about 1 KB.
- **Vault to agent:** the same envelope, sealed to the current connect key.
- **Files:** attachments, each its own `A8S-VAULT-1` blob. On `/store` they
  are sealed to the vault key, and the sealed command carries their
  `sha256`. On `/retrieve` they are sealed to the connect key.
- **The vault rejects a sealed command when:**
  - `conn` is not the seat's current connect key, which kills replays
    across reconnects;
  - its `nonce` has been seen before;
  - `ts` falls outside the window (24h, matching broker retention for
    backlog);
  - an attached file's hash doesn't match.
- **A plaintext command other than `/connect`, `/help` or `/public-key`**
  gets a reply that explains the flow and the encryption recipe, with the
  copy-paste openssl lines. Its text is never acted on.

### 2.3 `/connect`

```
tell vault --attach agent.pem "/connect"
◀ sealed to agent.pem: {"connected": "<seat>", "conn": "<fpr>", "vault": "<vault fpr>"}
   + signature by the vault key over that JSON
```

- **It replaces the seat's whole connection state:** the connect key, the
  authenticated flag, the session expiry and the nonce set. A fresh connection
  starts unauthenticated.
- **The vault signs its acknowledgement.** The agent checks the signature
  against its pinned vault fingerprint before sending a voucher.
- **Rate limit:** about 10 `/connect`s per seat per hour. Each one is logged
  and announced (sealed) to the previous key, so a hijack is visible to the
  agent that lost its session.

### 2.4 Vouchers

- **Format:** `a8sv1-` followed by 128 random bits in base32. The vault
  stores `HMAC-SHA256(pepper, voucher)` with the seat. The pepper lives in
  `~/.config/a8s-vault`. A voucher can't be recovered from the vault side.
- **Bound to a seat, single use, never expires.** A voucher authenticates
  only the seat it was issued to. On its own it is worthless.
- **Burned when used.** A successful `/authenticate` deletes that voucher's
  hash and returns the **next voucher** in the same sealed reply. One
  database transaction does both: burn the old voucher and store the new
  one's hash. The agent writes the new voucher to its durable store before
  doing anything else.
- **Self-service while authenticated.** `/voucher new` mints an extra voucher
  over the wire, for example a spare kept somewhere else. It needs no admin.
- **Outstanding vouchers are capped at 10 per seat.** `/voucher new` is
  refused once a seat holds 10 unused vouchers. The replacement voucher that
  `/authenticate` hands back is one-for-one, so it never raises the count.
  An agent can therefore never hold more than 10 live vouchers. `/voucher
  list` shows the count only. `/voucher revoke-all` burns every outstanding
  voucher except the one returned in that reply. On the vault host,
  `a8s-vault voucher purge <seat>` burns them all and resets the count.
- **Burned or unknown voucher.** It is refused with a generic error and
  backoff per seat. A burned voucher showing up again is logged and alerts
  the configured admins. Usually it means two live instances of one seat,
  or a failed save.
- **Lockout.** If the agent loses the reply that carried its next voucher and
  holds no spare, the seat stays locked until someone on the vault host runs
  `a8s-vault voucher issue <seat>`. Data is not lost.

### 2.5 Sessions

- Once authenticated, a session lasts until the next `/connect`, `/logout`,
  or 24h idle.
- **There is one container per seat, and no UUID.** The voucher is the
  out-of-band identifier that the ADR 0001 UUID was trying to be. Names
  inside the container may contain `/` (for example `/store keys/ssh.pem`),
  so an agent can organise its files without separate containers.

### 2.6 At rest (unchanged from ADR 0001)

- Files stay sealed to the vault key.
- The index of names, sizes and hashes is itself sealed, so listing a
  directory reveals nothing.
- The only secret-like data stored in plaintext is the voucher HMACs, and
  they cannot be reversed.

### 2.7 Administration happens only through the local CLI

None of these exist as wire commands. They run on the vault host as the
vault user:

```
a8s-vault admin add <seat> | rm <seat> | list    # seats that receive alerts; nothing else
a8s-vault voucher issue <seat>                   # bootstrap or unlock; prints a voucher once
a8s-vault voucher purge <seat>                   # burn all outstanding vouchers, reset count
a8s-vault seat list | disconnect <seat>          # inspect / drop a session
a8s-vault init                                   # vault keypair + pepper in ~/.config/a8s-vault
```

Admin seats are not hard-coded. They exist only in the vault's config, and
on the wire they only *receive* alerts (a burned voucher reused, a burst of
`/connect`s). A message from an admin seat gets no extra rights.

## 3. Industry precedent

| Piece | Precedent |
|---|---|
| Sealed channel set up first, then credentials sent inside it | TLS, then password; SSH key exchange, then user auth |
| Opaque, hashed, single-use token, rotated on every use | OAuth 2.0 refresh token rotation (RFC 9700); HashiCorp Vault AppRole `secret_id` with `secret_id_num_uses=1`; backup/recovery codes (one-time) |
| One-time handoff of a credential through a wrapped, single-use token | HashiCorp Vault response wrapping |
| Operator-issued first credential, out of band | Vault trusted-orchestrator pattern; Kubernetes bootstrap tokens via `kubeadm token create` |
| Signed acknowledgement so the client can tell it reached the real server | SSH host-key pinning (TOFU), plus a pinned fingerprint |
| Notify the displaced session | Signal Registration Lock / "new device" alerts |

Considered and rejected for v1:
- **OPAQUE/SRP** (no openssl CLI or stdlib support).
- **Guardian quorum recovery.** The admin re-issuing a voucher covers the
  lost-voucher case.
- **Workload attestation (OIDC).** Revisit if a platform Neil uses issues
  tokens.

## 4. Residual risks

1. **Unsecured remotes are out of scope.** A remote with no access
   credentials lets anyone claim any seat. This is a network configuration
   footgun, documented as such.
2. **A network participant who can forge a seat and knows its current
   voucher can impersonate that seat.** The trust model (§2.1) accepts
   this. Because each voucher burns on use, the real agent's next
   `/authenticate` fails and the admins are alerted.
3. **Lockout from a lost next voucher.** This happens when the VM dies
   between `/authenticate` and saving the result. A spare from
   `/voucher new` or an admin running `a8s-vault voucher issue` recovers it.
4. **Forged `/connect` as DoS.** It is rate-limited, logged, and announced to
   the previous key.
5. **Same-host compromise of the vault user** exposes everything (ADR 0001
   G6). A dedicated Unix user is still recommended.
- **Key material on argv.** `openssl enc` only takes a raw AES key as `-K`
  on its command line, so on a shared host another Unix user can read a
  per-message key from `/proc/<pid>/cmdline` while it runs. The dedicated user
  protects files, not process listings: give the vault its own container or
  VM, or mount `/proc` with `hidepid=2`. Accepted as-is for v1; hardening (keying
  `enc` without argv) is deferred until the vault has run for real.
- **Request and reply binding (added after review).** The fingerprint
  inside a sealed command is of a *public* key, so it proves nothing about
  who sent it. Each request is therefore `{"req": <json>, "sig": <base64>}`
  with `sig` made by the connection private key; the vault verifies it against
  `conn_pem` before dispatching. Each signed reply echoes the request nonce,
  and `/retrieve` replies carry the sha256 of every sealed attachment. The
  client keeps its outstanding nonces, refuses a reply it did not ask for or
  has already applied (one record per nonce, removed only after the voucher or
  files have been written, so a delayed duplicate cannot rewind the saved
  voucher and a failed write stays retryable),
  and writes nothing unless every declared attachment is present and matches.

## 5. Prototype evidence (OpenSSL 3.0.2 and LibreSSL 3.3.6, both directions)

- A `/connect` acknowledgement signed by the vault key verifies on both.
- A sealed command fits in a 1,070-byte single-line `A8SV1:` body. It
  round-trips through `openssl base64 -A`, and the vault decodes it with
  `open.sh`.
- A reply sealed to the agent's connect key opens with the agent's openssl.
- Connect-key fingerprints (DER SPKI SHA-256) are identical across both.

## 6. Decisions recorded (2026-10-08, Neil)

- Vouchers are single use with no expiry, and the vault stores only their
  hashes.
- An agent can mint vouchers itself, up to **10 outstanding per seat**. The
  admin CLI can purge them.
- Admin seats come from configuration, not code. Admin actions run only
  through the local `a8s-vault` CLI.
- **The UUID is dropped.** The container is the seat, and the voucher is the
  out-of-band identifier.
- The network's access credentials are the security boundary. A remote
  with no credentials is out of scope.
- `/store` **overwrites** an existing name by default, with no force flag.
- The recommended deployment runs the vault as a **dedicated Unix user**.
