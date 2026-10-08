"""Agent side: pin the vault key, /connect with a throwaway key, seal commands, open replies."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
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
    for name in ("conn.key", "conn.pem"):
        if os.path.exists(_path(name)):
            os.unlink(_path(name))
    shutil.rmtree(_path("pending"), ignore_errors=True)
    crypto.generate_key(_path("conn.key"))
    with open(_path("conn.pem"), "wb") as handle:
        handle.write(crypto.public_pem(_path("conn.key")))
    _tell(to, "/connect", [_path("conn.pem")])
    return crypto.fingerprint(crypto.public_pem(_path("conn.key")))


PENDING_KEEP = 200


def _pending_path(nonce):
    if not nonce or not all(c in "0123456789abcdef" for c in nonce):
        raise ClientError("malformed nonce")
    return _path(os.path.join("pending", nonce))


def _pending_add(nonce):
    """One empty file per outstanding request, so sends and reply handling never
    read-modify-write a shared list; the file is removed only once the reply's
    effects (voucher saved, files written) have succeeded."""
    folder = _path("pending")
    os.makedirs(folder, exist_ok=True)
    with open(_pending_path(nonce), "x"):
        pass
    stamps = []
    for name in os.listdir(folder):
        try:
            stamps.append((os.stat(os.path.join(folder, name)).st_mtime, name))
        except FileNotFoundError:
            continue   # completed by a concurrent `client open` after listdir saw it
    for _, stale in sorted(stamps)[:-PENDING_KEEP]:
        try:
            os.unlink(os.path.join(folder, stale))
        except FileNotFoundError:
            pass


def _pending_has(nonce):
    return os.path.exists(_pending_path(nonce))


def _pending_done(nonce):
    try:
        os.unlink(_pending_path(nonce))
    except FileNotFoundError:
        pass


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
    _pending_add(req["nonce"])
    payload = json.dumps({"req": signed, "sig": sig}).encode()
    return crypto.to_wire(crypto.seal(vault_pem, payload)), files


def send(to, cmd, file_path=None):
    body, files = seal_command(cmd, file_path)
    _tell(to, body, files)


@contextlib.contextmanager
def _reply_lock():
    """Exclusive across client processes. Checking a reply's nonce, applying its
    effects and consuming the nonce happen under one lock, so two `client open`
    runs of the same reply cannot both pass the check and the later one cannot
    write back a voucher the vault has already burned. Released on close/exit."""
    _ensure_dir()
    fd = os.open(_path("reply.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write_private(path, data):
    """Write bytes owner-only (0600) whatever the umask or an existing file's mode:
    a private temp file beside the target, fsynced, then renamed over it."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".a8s-vault-")
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _makedirs_private(path):
    """Create missing directories as 0700; existing ones are left alone. os.makedirs
    applies its mode to the leaf only, and through the umask, so each new level is
    created and chmod'ed here."""
    if os.path.isdir(path):
        return
    _makedirs_private(os.path.dirname(path))
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        return
    os.chmod(path, 0o700)


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
    if nonce is None and reply.get("op") not in ("connect", "disconnected"):
        raise ClientError("reply carries no request nonce; ignoring it")
    with _reply_lock():
        if nonce is not None and not _pending_has(str(nonce)):
            raise ClientError("reply does not match an outstanding request (replayed, or "
                              "already applied); nothing changed")
        mapping = reply.get("files") if isinstance(reply.get("files"), dict) else {}
        outputs = _verified_attachments(mapping if reply.get("cmd") == "/retrieve" else {},
                                        files, missing, out_dir or ".")
        try:
            if save_voucher and reply.get("voucher"):
                _write_private(save_voucher, (reply["voucher"] + "\n").encode())
            written = []
            for target, plain in outputs:   # restored secrets: 0600 files, new dirs 0700
                _makedirs_private(os.path.dirname(os.path.abspath(target)))
                _write_private(target, plain)
                written.append(target)
        except OSError as exc:
            raise ClientError(f"could not apply the reply ({exc}); the request stays "
                              "outstanding, fix the path and open the same reply again") from exc
        if nonce is not None:
            _pending_done(str(nonce))
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
