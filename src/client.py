"""Agent side: pin the vault key, /connect with a throwaway key, seal commands, open replies."""
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time

import crypto
from handler import ATTACHED, UNAVAILABLE, split_message


class ClientError(Exception):
    pass


class StaleReply(ClientError):
    """Sealed to an earlier connection key, e.g. the vault's notice to a wiped VM's old key."""


def state_dir():
    return os.environ.get("A8S_VAULT_CLIENT") or os.path.expanduser("~/.cache/a8s-vault-client")


def _path(name):
    return os.path.join(state_dir(), name)


def _ensure_dir():
    os.makedirs(state_dir(), mode=0o700, exist_ok=True)


def _pinned():
    try:
        with open(_path("vault.pem"), "rb") as handle:
            pem = handle.read()
    except FileNotFoundError as exc:
        raise ClientError(
            "no pinned vault key: `a8s-vault client pin vault.pem --fingerprint F`") from exc
    want = os.environ.get("A8S_VAULT_FINGERPRINT", "").strip().lower()
    got = crypto.fingerprint(pem)
    if want and want != got:
        raise ClientError(f"pinned vault key {got} does not match A8S_VAULT_FINGERPRINT {want}")
    return pem


def _tell(to, body, files=()):
    argv = ["tell", to, "-"]
    for path in files:
        argv += ["--attach", path]
    subprocess.run(argv, input=body, text=True, check=True)


def pin(pem_path, expected=None):
    with open(pem_path, "rb") as handle:
        pem = crypto.load_public(handle.read())
    fpr = crypto.fingerprint(pem)
    expected = (expected or os.environ.get("A8S_VAULT_FINGERPRINT", "")).strip().lower()
    if expected and expected != fpr:
        raise ClientError(f"fingerprint mismatch: key is {fpr}, expected {expected}")
    _ensure_dir()
    with open(_path("vault.pem"), "wb") as handle:
        handle.write(pem)
    return fpr


def connect(to):
    _pinned()
    _ensure_dir()
    for name in ("conn.key", "conn.pem", "pending.json"):
        if os.path.exists(_path(name)):
            os.unlink(_path(name))
    crypto.generate_key(_path("conn.key"))
    with open(_path("conn.pem"), "wb") as handle:
        handle.write(crypto.public_pem(_path("conn.key")))
    _tell(to, "/connect", [_path("conn.pem")])
    return crypto.fingerprint(crypto.public_pem(_path("conn.key")))


def _pending(update=None):
    """Nonces of requests sent on this connection whose reply has not been applied yet."""
    path = _path("pending.json")
    try:
        with open(path) as handle:
            nonces = json.load(handle)
    except (FileNotFoundError, ValueError):
        nonces = []
    if update is not None:
        _save_atomic(path, json.dumps(update(nonces)))
    return nonces


def seal_command(cmd, file_path=None):
    """Return (wire_body, [attachment paths]) for one sealed command."""
    vault_pem = _pinned()
    if not os.path.exists(_path("conn.key")):
        raise ClientError("not connected: `a8s-vault client connect` first")
    files, declared = [], {}
    if file_path:
        with open(file_path, "rb") as handle:
            sealed = crypto.seal(vault_pem, handle.read())
        tmp = tempfile.mkdtemp(prefix="a8s-vault-up-")
        out = os.path.join(tmp, os.path.basename(file_path) + ".enc")
        with open(out, "wb") as handle:
            handle.write(sealed)
        files.append(out)
        declared[os.path.basename(out)] = hashlib.sha256(sealed).hexdigest()
    req = {"v": 1, "cmd": cmd, "conn": crypto.fingerprint(crypto.public_pem(_path("conn.key"))),
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "nonce": os.urandom(16).hex(), "files": declared}
    signed = json.dumps(req)
    sig = base64.b64encode(crypto.sign(_path("conn.key"), signed.encode())).decode()
    _pending(lambda nonces: [*nonces[-200:], req["nonce"]])
    payload = json.dumps({"req": signed, "sig": sig}).encode()
    return crypto.to_wire(crypto.seal(vault_pem, payload)), files


def send(to, cmd, file_path=None):
    body, files = seal_command(cmd, file_path)
    _tell(to, body, files)


def _save_atomic(path, text):
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def open_reply(message, out_dir=None, save_voucher=None, extra_files=()):
    """Verify and decrypt one reply. Returns (reply dict | None, plaintext, written paths)."""
    text, files, missing = split_message(message)
    files = list(files) + list(extra_files)
    if not text.startswith(crypto.WIRE):
        return None, text, []
    try:
        payload = json.loads(crypto.open_sealed(_path("conn.key"), crypto.from_wire(text)))
    except crypto.CryptoError as exc:
        raise StaleReply(f"not sealed to the current connection key; ignore it ({exc})") from exc
    if not crypto.verify(_pinned(), payload["body"].encode(), base64.b64decode(payload["sig"])):
        raise ClientError("reply signature does not verify against the pinned vault key")
    reply = json.loads(payload["body"])
    nonce = reply.get("nonce")
    if nonce is None:
        if reply.get("op") not in ("connect", "disconnected"):
            raise ClientError("reply carries no request nonce; ignoring it")
    elif nonce not in _pending():
        raise ClientError("reply does not match an outstanding request (replayed, or already "
                          "applied); nothing changed")
    mapping = reply.get("files") if isinstance(reply.get("files"), dict) else {}
    outputs = _verified_attachments(mapping if reply.get("cmd") == "/retrieve" else {},
                                    files, missing, out_dir or ".")
    if nonce is not None:
        _pending(lambda nonces: [n for n in nonces if n != nonce])
    if save_voucher and reply.get("voucher"):
        _save_atomic(save_voucher, reply["voucher"])
    written = []
    for target, plain in outputs:
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(plain)
        written.append(target)
    return reply, None, written


def _verified_attachments(mapping, files, missing, out_dir):
    """Every attachment the signed reply declares must be present and match its sha256."""
    by_name = {os.path.basename(p): p for p in files}
    outputs, problems = [], []
    for attach, info in mapping.items():
        name = info.get("name") if isinstance(info, dict) else None
        want = info.get("sha256") if isinstance(info, dict) else None
        path = by_name.get(attach)
        if not (name and want and path):
            state = "unavailable" if attach in missing else "missing"
            problems.append(f"{attach} ({state})")
            continue
        with open(path, "rb") as handle:
            sealed = handle.read()
        if hashlib.sha256(sealed).hexdigest() != want:
            problems.append(f"{attach} (sha256 does not match the signed reply)")
            continue
        target = os.path.join(out_dir, name)
        if os.path.relpath(target, out_dir).startswith(".."):
            raise ClientError(f"refusing to write outside the output directory: {name}")
        outputs.append((target, crypto.open_sealed(_path("conn.key"), sealed)))
    if problems:
        raise ClientError("retrieval incomplete, nothing written: " + ", ".join(problems))
    return outputs


__all__ = ["ATTACHED", "UNAVAILABLE", "ClientError", "connect", "open_reply", "pin",
           "seal_command", "send"]
