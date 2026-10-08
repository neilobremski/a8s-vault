"""Vault state: keys, seats and their sealed sessions, vouchers, and containers.

Methods never commit. Callers wrap a whole request in `with vault.db:` so a
voucher burn, the next voucher and the cached reply land in one transaction.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time

import crypto

CONNECT_LIMIT = 10          # per seat per hour
AUTH_FAIL_LIMIT = 5         # per seat per hour
VOUCHER_CAP = 10            # live vouchers per seat
SESSION_IDLE = 24 * 3600
TS_WINDOW = 24 * 3600
NONCE_KEEP = 2 * TS_WINDOW
NAME_RE = re.compile(r"^[A-Za-z0-9._@+=,-]+(/[A-Za-z0-9._@+=,-]+)*$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS seats (
  seat TEXT PRIMARY KEY, conn_pem TEXT, conn_fpr TEXT,
  authed INTEGER NOT NULL DEFAULT 0, last_active REAL, connected_at REAL);
CREATE TABLE IF NOT EXISTS vouchers (
  hash TEXT PRIMARY KEY, seat TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS nonces (
  seat TEXT NOT NULL, nonce TEXT NOT NULL, digest TEXT NOT NULL, reply TEXT, ts REAL NOT NULL,
  PRIMARY KEY (seat, nonce));
CREATE TABLE IF NOT EXISTS events (ts REAL NOT NULL, seat TEXT, kind TEXT NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS admins (seat TEXT PRIMARY KEY);
"""


class VaultError(Exception):
    pass


def _xdg(var, default):
    return os.environ.get(var) or os.path.expanduser(default)


def config_dir():
    return os.environ.get("A8S_VAULT_CONFIG") or os.path.join(
        _xdg("XDG_CONFIG_HOME", "~/.config"), "a8s-vault")


def data_dir():
    return os.environ.get("A8S_VAULT_DATA") or os.path.join(
        _xdg("XDG_DATA_HOME", "~/.local/share"), "a8s-vault")


def new_voucher():
    return "a8sv1-" + base64.b32encode(os.urandom(16)).decode().rstrip("=").lower()


def check_name(name):
    if not name or len(name) > 200 or not NAME_RE.match(name):
        raise VaultError(
            f"bad name {name!r}: use letters, digits, ._@+=,- and '/' between parts")
    if any(part in (".", "..") for part in name.split("/")):
        raise VaultError(f"bad name {name!r}: '.' and '..' are not allowed")
    return name


class Vault:
    def __init__(self, config=None, data=None):
        self.config = config or config_dir()
        self.data = data or data_dir()
        self.key_path = os.path.join(self.config, "vault.key")
        self.pub_path = os.path.join(self.config, "vault.pem")
        self.pepper_path = os.path.join(self.config, "pepper")
        self.alerts = []
        self.db = None

    # --- setup -----------------------------------------------------------
    def init(self):
        created = False
        for path in (self.config, self.data, self._blobs(), self._index_dir()):
            os.makedirs(path, mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
        if not os.path.exists(self.key_path):
            crypto.generate_key(self.key_path)
            created = True
        with open(self.pub_path, "wb") as handle:
            handle.write(crypto.public_pem(self.key_path))
        if not os.path.exists(self.pepper_path):
            fd = os.open(self.pepper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(os.urandom(32).hex())
        self.load()
        return created

    def load(self):
        if not os.path.exists(self.key_path):
            raise VaultError(f"vault not initialised: run `a8s-vault init` ({self.config})")
        with open(self.pub_path, "rb") as handle:
            self.pub_pem = handle.read()
        with open(self.pepper_path) as handle:
            self._pepper = bytes.fromhex(handle.read().strip())
        self.fpr = crypto.fingerprint(self.pub_pem)
        self.db = sqlite3.connect(os.path.join(self.data, "vault.sqlite3"))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        return self

    def _blobs(self):
        return os.path.join(self.data, "blobs")

    def _index_dir(self):
        return os.path.join(self.data, "index")

    def _mac(self, *parts):
        return hmac.new(self._pepper, "\0".join(parts).encode(), hashlib.sha256).hexdigest()

    def _event(self, seat, kind, detail=""):
        self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (time.time(), seat, kind, detail))

    def _recent(self, seat, kind, window=3600):
        return self.db.execute(
            "SELECT COUNT(*) FROM events WHERE seat=? AND kind=? AND ts>?",
            (seat, kind, time.time() - window)).fetchone()[0]

    def alert(self, text):
        self.alerts.append(text)

    # --- connections ------------------------------------------------------
    def connect(self, seat, pem):
        """Replace every bit of the seat's connection state. Returns (fpr, old_pem)."""
        if self._recent(seat, "connect") >= CONNECT_LIMIT:
            self._event(seat, "connect_limited")
            raise VaultError(f"too many /connect for {seat} in the last hour; try later")
        pem = crypto.load_public(pem).decode()
        fpr = crypto.fingerprint(pem)
        row = self.session(seat)
        old = row["conn_pem"] if row and row["conn_fpr"] != fpr else None
        self.db.execute(
            "INSERT INTO seats (seat, conn_pem, conn_fpr, authed, last_active, connected_at) "
            "VALUES (?,?,?,0,?,?) ON CONFLICT(seat) DO UPDATE SET conn_pem=excluded.conn_pem, "
            "conn_fpr=excluded.conn_fpr, authed=0, last_active=excluded.last_active, "
            "connected_at=excluded.connected_at",
            (seat, pem, fpr, time.time(), time.time()))
        self.db.execute("DELETE FROM nonces WHERE seat=?", (seat,))
        self._event(seat, "connect", fpr)
        if self._recent(seat, "connect") == CONNECT_LIMIT:
            self.alert(f"{seat}: {CONNECT_LIMIT} /connect calls in an hour")
        return fpr, old

    def session(self, seat):
        return self.db.execute("SELECT * FROM seats WHERE seat=?", (seat,)).fetchone()

    def disconnect(self, seat):
        self.db.execute("DELETE FROM seats WHERE seat=?", (seat,))
        self.db.execute("DELETE FROM nonces WHERE seat=?", (seat,))
        self._event(seat, "disconnect")

    def logout(self, seat):
        self.db.execute("UPDATE seats SET authed=0 WHERE seat=?", (seat,))

    def require_auth(self, seat):
        row = self.session(seat)
        if not row or not row["authed"]:
            raise VaultError("not authenticated: send /authenticate <voucher> first")
        if time.time() - (row["last_active"] or 0) > SESSION_IDLE:
            self.logout(seat)
            raise VaultError("session idle too long: send /authenticate <voucher> again")
        self.db.execute("UPDATE seats SET last_active=? WHERE seat=?", (time.time(), seat))

    # --- replay protection -------------------------------------------------
    def nonce_get(self, seat, nonce):
        return self.db.execute(
            "SELECT digest, reply FROM nonces WHERE seat=? AND nonce=?", (seat, nonce)).fetchone()

    def nonce_put(self, seat, nonce, digest, reply):
        self.db.execute("DELETE FROM nonces WHERE ts<?", (time.time() - NONCE_KEEP,))
        self.db.execute(
            "INSERT OR REPLACE INTO nonces VALUES (?,?,?,?,?)",
            (seat, nonce, digest, reply, time.time()))

    # --- vouchers ---------------------------------------------------------
    def _live(self, seat):
        return self.db.execute(
            "SELECT COUNT(*) FROM vouchers WHERE seat=? AND state='live'", (seat,)).fetchone()[0]

    def _add_voucher(self, seat):
        voucher = new_voucher()
        self.db.execute("INSERT INTO vouchers VALUES (?,?,'live',?)",
                        (self._mac("voucher", voucher), seat, time.time()))
        return voucher

    def authenticate(self, seat, voucher):
        row = self.session(seat)
        if not row:
            raise VaultError("no connection: /connect first")
        if self._recent(seat, "auth_fail") >= AUTH_FAIL_LIMIT:
            raise VaultError("too many failed /authenticate attempts; wait an hour or ask an admin")
        found = self.db.execute(
            "SELECT state FROM vouchers WHERE hash=? AND seat=?",
            (self._mac("voucher", voucher.strip()), seat)).fetchone()
        if not found or found["state"] != "live":
            self._event(seat, "auth_fail")
            if found:
                self._event(seat, "voucher_reuse")
                self.alert(f"{seat}: a burned voucher was presented again (two live instances "
                           "of this seat, or a lost reply)")
            raise VaultError("voucher not accepted")
        self.db.execute("UPDATE vouchers SET state='burned' WHERE hash=?",
                        (self._mac("voucher", voucher.strip()),))
        self.db.execute("UPDATE seats SET authed=1, last_active=? WHERE seat=?",
                        (time.time(), seat))
        self._event(seat, "auth_ok")
        return self._add_voucher(seat)

    def mint(self, seat):
        if self._live(seat) >= VOUCHER_CAP:
            raise VaultError(f"{seat} already holds {VOUCHER_CAP} unused vouchers")
        return self._add_voucher(seat)

    def voucher_count(self, seat):
        return self._live(seat)

    def revoke_all(self, seat):
        self.db.execute("UPDATE vouchers SET state='burned' WHERE seat=? AND state='live'", (seat,))
        return self._add_voucher(seat)

    def issue(self, seat):
        self._event(seat, "voucher_issue")
        return self._add_voucher(seat)

    def purge(self, seat):
        count = self.db.execute("DELETE FROM vouchers WHERE seat=?", (seat,)).rowcount
        self.db.execute("DELETE FROM events WHERE seat=? AND kind='auth_fail'", (seat,))
        self._event(seat, "voucher_purge", str(count))
        return count

    # --- admins -----------------------------------------------------------
    def admins(self):
        return [r["seat"] for r in self.db.execute("SELECT seat FROM admins ORDER BY seat")]

    def admin_add(self, seat):
        self.db.execute("INSERT OR IGNORE INTO admins VALUES (?)", (seat,))

    def admin_rm(self, seat):
        self.db.execute("DELETE FROM admins WHERE seat=?", (seat,))

    def seats(self):
        return self.db.execute(
            "SELECT s.seat, s.conn_fpr, s.authed, s.last_active, "
            "(SELECT COUNT(*) FROM vouchers v WHERE v.seat=s.seat AND v.state='live') AS live "
            "FROM seats s ORDER BY s.seat").fetchall()

    # --- containers -------------------------------------------------------
    def _index_path(self, seat):
        return os.path.join(self._index_dir(), self._mac("index", seat) + ".enc")

    def _read_index(self, seat):
        path = self._index_path(seat)
        if not os.path.exists(path):
            return {}
        with open(path, "rb") as handle:
            return json.loads(crypto.open_sealed(self.key_path, handle.read()))

    def _write_index(self, seat, index):
        _atomic_write(self._index_path(seat),
                      crypto.seal(self.pub_pem, json.dumps(index, sort_keys=True).encode()))

    def list_files(self, seat):
        index = self._read_index(seat)
        return [dict(name=name, size=e["size"], sha256=e["sha256"], stored_at=e["stored_at"])
                for name, e in sorted(index.items())]

    def store(self, seat, name, sealed):
        check_name(name)
        try:
            plain = crypto.open_sealed(self.key_path, sealed)
        except crypto.CryptoError as exc:
            raise VaultError(f"attachment is not sealed to this vault's key: {exc}") from exc
        index = self._read_index(seat)
        blob = os.urandom(16).hex()
        _atomic_write(os.path.join(self._blobs(), blob), sealed)
        old = index.get(name)
        index[name] = dict(blob=blob, size=len(plain), sha256=hashlib.sha256(plain).hexdigest(),
                           stored_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self._write_index(seat, index)
        if old:
            _unlink(os.path.join(self._blobs(), old["blob"]))
        self._event(seat, "store")
        return index[name], bool(old)

    def retrieve(self, seat, name):
        entry = self._read_index(seat).get(check_name(name))
        if not entry:
            raise VaultError(f"no such file: {name}")
        with open(os.path.join(self._blobs(), entry["blob"]), "rb") as handle:
            return crypto.open_sealed(self.key_path, handle.read())

    def delete(self, seat, name):
        index = self._read_index(seat)
        entry = index.pop(check_name(name), None)
        if not entry:
            raise VaultError(f"no such file: {name}")
        self._write_index(seat, index)
        _unlink(os.path.join(self._blobs(), entry["blob"]))
        self._event(seat, "delete")


def _atomic_write(path, data):
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _unlink(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
