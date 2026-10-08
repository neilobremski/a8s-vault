"""a8s wake entry point: one tell in, one reply (sealed, after /connect) back."""
import base64
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone

import crypto
import vault as vaultlib
from vault import VaultError

ATTACHED = "ATTACHED FILE: "
UNAVAILABLE = "ATTACHMENT UNAVAILABLE: "

HELP = """{seat}: encrypted storage for agents. Vault key fingerprint (pin it):
  {fpr}

Everything except /help, /public-key and /connect must be SEALED.

1. tell {seat} /public-key                      -> vault.pem; check the fingerprint above
2. tell {seat} --attach me.pem /connect         -> a throwaway RSA public key (>=2048 bits).
   Replies are sealed to it from now on. A new /connect wipes the old session.
3. tell {seat} "A8SV1:<base64 of a blob sealed to vault.pem>"
   The blob's plaintext is JSON:
     {{"v":1, "cmd":"/authenticate <voucher>", "conn":"<sha256 of me.pem DER>",
      "ts":"<UTC ISO-8601>", "nonce":"<random hex>", "files":{{"<attachment>":"<sha256>"}}}}
   /authenticate burns the voucher and returns the next one. Save it before anything else.

Sealed commands, once authenticated:
  /list   /store <name> (attach one file sealed to vault.pem)   /retrieve <name>
  /delete <name>   /voucher new | list | revoke-all   /logout

Vouchers are single-use, at most {cap} unused per seat. The first one comes from the vault's
operator (`a8s-vault voucher issue <seat>` on the vault host).

Easiest client: `a8s-vault client` (https://github.com/neilobremski/a8s-vault) does
all of this. Raw openssl recipe for sealing: tell {seat} "/help recipe"."""

RECIPE = """Seal (sh + openssl or LibreSSL; <pub.pem> <in> <out>):
  ek=$(openssl rand -hex 32); mk=$(openssl rand -hex 32); iv=$(openssl rand -hex 16)
  openssl enc -aes-256-cbc -K $ek -iv $iv -in IN -out body
  mac=$(openssl dgst -sha256 -mac HMAC -macopt hexkey:$mk body | sed 's/.*= //')
  w=$(printf '%s:%s:%s' $ek $mk $iv | openssl pkeyutl -encrypt -pubin -inkey PUB \\
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \\
    | openssl base64 -A)
  {{ printf 'A8S-VAULT-1\\n%s\\n%s\\n' "$w" "$mac"; cat body; }} > OUT
Wire body: printf 'A8SV1:%s' "$(openssl base64 -A -in OUT)"
Open: reverse it. Line 2 unwraps with pkeyutl -decrypt, then check the line-3 HMAC over the
ciphertext BEFORE decrypting. Replies are JSON {{"body":"<json>","sig":"<base64>"}};
verify sig (dgst -sha256 -verify vault.pem) over body."""


def split_message(message):
    """The tell body without a8s's attachment lines, plus the attached paths."""
    lines, files, missing = [], [], []
    for line in (message or "").splitlines():
        if line.startswith(ATTACHED):
            files.append(line[len(ATTACHED):].strip())
        elif line.startswith(UNAVAILABLE):
            missing.append(line[len(UNAVAILABLE):].strip())
        else:
            lines.append(line)
    return "\n".join(lines).strip(), files, missing


def _tell(recipient, body, files):
    argv = ["tell", recipient, "-"]
    for path in files:
        argv += ["--attach", path]
    subprocess.run(argv, input=body, text=True, check=True, stdout=subprocess.DEVNULL)


def _sealed_reply(vault, pem, obj):
    body = json.dumps(obj, sort_keys=True)
    sig = base64.b64encode(crypto.sign(vault.key_path, body.encode())).decode()
    payload = json.dumps({"body": body, "sig": sig}).encode()
    return crypto.to_wire(crypto.seal(pem.encode() if isinstance(pem, str) else pem, payload))


class Wake:
    def __init__(self, seat, sender, message):
        self.seat = seat
        self.sender = sender
        self.who = sender.lower()
        self.text, self.files, self.missing = split_message(message)
        self.outdir = tempfile.mkdtemp(prefix="a8s-vault-out-")
        self.vault = None

    def run(self):
        try:
            self.vault = vaultlib.Vault().load()
        except VaultError as exc:
            return self.send(f"{self.seat}: unavailable: {exc}")
        try:
            if self.text.startswith(crypto.WIRE):
                return self.sealed()
            return self.plain()
        finally:
            self.notify_admins()
            shutil.rmtree(self.outdir, ignore_errors=True)

    def send(self, body, files=(), to=None):
        try:
            _tell(to or self.sender, body, list(files))
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return 1
        return 0

    def notify_admins(self):
        for text in self.vault.alerts if self.vault else []:
            for admin in self.vault.admins():
                self.send(f"{self.seat} alert: {text}", to=admin)

    # --- plaintext ---------------------------------------------------------
    def plain(self):
        words = self.text.split()
        cmd = words[0].lower() if words else ""
        if cmd == "/public-key":
            path = os.path.join(self.outdir, "vault.pem")
            shutil.copy(self.vault.pub_path, path)
            return self.send(f"{self.seat}: public key attached. fingerprint {self.vault.fpr}",
                             [path])
        if cmd == "/connect":
            return self.connect()
        if cmd == "/help" and words[1:2] == ["recipe"]:
            return self.send(RECIPE)
        body = HELP.format(seat=self.seat, fpr=self.vault.fpr, cap=vaultlib.VOUCHER_CAP)
        if cmd and cmd != "/help":
            body = (f"{self.seat}: refusing plaintext {cmd!r}. Only /help, /public-key and "
                    "/connect travel in the clear.\n\n" + body)
        return self.send(body)

    def connect(self):
        if len(self.files) != 1:
            return self.send(f"{self.seat}: /connect needs exactly one attached public key "
                             f"(got {len(self.files)}). {' '.join(self.missing)}".strip())
        try:
            with open(self.files[0], "rb") as handle:
                pem = handle.read(20000)
            with self.vault.db:
                fpr, old = self.vault.connect(self.who, pem)
        except (OSError, VaultError, crypto.CryptoError) as exc:
            return self.send(f"{self.seat}: /connect refused: {exc}")
        if old:
            self.send(_sealed_reply(self.vault, old, {
                "ok": True, "op": "disconnected", "seat": self.who, "vault": self.vault.fpr,
                "detail": f"a new /connect replaced this connection (new key {fpr[:16]}...)"}))
        return self.send(_sealed_reply(self.vault, self.vault.session(self.who)["conn_pem"], {
            "ok": True, "op": "connect", "seat": self.who, "conn": fpr, "vault": self.vault.fpr,
            "next": "send a sealed /authenticate <voucher>"}))

    # --- sealed ------------------------------------------------------------
    def sealed(self):
        v = self.vault
        row = v.session(self.who)
        if not row:
            return self.send(f"{self.seat}: no connection for {self.who}; /connect first")
        try:
            blob = crypto.from_wire(self.text.split()[0])
            req = json.loads(crypto.open_sealed(v.key_path, blob))
            cmd, conn, nonce = req["cmd"], req["conn"], str(req["nonce"])
            ts = datetime.strptime(req["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (crypto.CryptoError, ValueError, KeyError, TypeError) as exc:
            return self.send(f"{self.seat}: could not open sealed message ({exc}). "
                             "Is it sealed to this vault's key? fingerprint " + v.fpr)
        if conn != row["conn_fpr"]:
            return self.send(f"{self.seat}: sealed for a different connection; /connect again")
        pem = row["conn_pem"]
        if abs(time.time() - ts.timestamp()) > vaultlib.TS_WINDOW or not 16 <= len(nonce) <= 128:
            return self.send(_sealed_reply(v, pem, {"ok": False, "cmd": cmd,
                                                    "error": "stale timestamp or bad nonce"}))
        digest = hashlib.sha256(blob).hexdigest()
        cached = v.nonce_get(self.who, nonce)
        if cached:
            if cached["digest"] != digest:
                return self.send(_sealed_reply(v, pem, {"ok": False, "cmd": cmd,
                                                        "error": "nonce reused"}))
            if cached["reply"]:
                return self.send(cached["reply"])
        files = []
        with v.db:
            try:
                result = self.dispatch(cmd, req.get("files") or {}, files)
                result.update(ok=True)
            except VaultError as exc:
                result = {"ok": False, "error": str(exc)}
            except Exception as exc:
                traceback.print_exc(file=sys.stderr)
                result = {"ok": False, "error": f"internal error: {type(exc).__name__}"}
            result["cmd"] = cmd.split()[0] if cmd.split() else cmd
            reply = _sealed_reply(v, pem, result)
            v.nonce_put(self.who, nonce, digest, None if files else reply)
        return self.send(reply, files)

    def dispatch(self, cmd, declared, out_files):
        v, who = self.vault, self.who
        try:
            words = shlex.split(cmd)
        except ValueError as exc:
            raise VaultError(f"cannot parse command: {exc}") from exc
        op = words[0].lower() if words else ""
        args = words[1:]
        if op == "/authenticate":
            if len(args) != 1:
                raise VaultError("usage: /authenticate <voucher>")
            return {"voucher": v.authenticate(who, args[0]),
                    "note": "the voucher you sent is burned; save this one before anything else"}
        if op in ("/help", ""):
            return {"help": HELP.format(seat=self.seat, fpr=v.fpr, cap=vaultlib.VOUCHER_CAP)}
        v.require_auth(who)
        if op == "/logout":
            v.logout(who)
            return {}
        if op == "/list":
            return {"files": v.list_files(who)}
        if op == "/voucher":
            sub = args[0].lower() if args else ""
            if sub == "new":
                return {"voucher": v.mint(who), "live": v.voucher_count(who)}
            if sub == "list":
                return {"live": v.voucher_count(who), "cap": vaultlib.VOUCHER_CAP}
            if sub == "revoke-all":
                return {"voucher": v.revoke_all(who), "live": 1,
                        "note": "every other voucher for this seat is burned"}
            raise VaultError("usage: /voucher new | list | revoke-all")
        if op in ("/store", "/retrieve", "/delete") and len(args) != 1:
            raise VaultError(f"usage: {op} <name>")
        if op == "/store":
            return self.store(args[0], declared)
        if op == "/retrieve":
            name = vaultlib.check_name(args[0])
            plain = v.retrieve(who, name)
            attach = name.replace("/", "__") + ".enc"
            path = os.path.join(self.outdir, attach)
            with open(path, "wb") as handle:
                handle.write(crypto.seal(v.session(who)["conn_pem"].encode(), plain))
            out_files.append(path)
            return {"files": {attach: name}}
        if op == "/delete":
            v.delete(who, args[0])
            return {"deleted": args[0]}
        raise VaultError(f"unknown command {op!r}; sealed /help lists them")

    def store(self, name, declared):
        if len(self.files) != 1:
            gone = f"; unavailable: {', '.join(self.missing)}" if self.missing else ""
            count = len(self.files)
            raise VaultError(f"/store needs exactly one attached file (got {count}){gone}")
        path = self.files[0]
        base = os.path.basename(path)
        with open(path, "rb") as handle:
            sealed = handle.read()
        want = declared.get(base)
        if not want or want != hashlib.sha256(sealed).hexdigest():
            raise VaultError(f"attachment {base} does not match the sha256 in the sealed command")
        entry, replaced = self.vault.store(self.who, name, sealed)
        return {"stored": name, "size": entry["size"], "sha256": entry["sha256"],
                "replaced": replaced}


def handle(seat, sender, message):
    return Wake(seat, sender, message).run()
