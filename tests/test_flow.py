"""End-to-end through handler + client with a fake `tell` that records what it would send."""
import os
import stat

import pytest

import client
import crypto
import handler
import vault as vaultlib

FAKE_TELL = """#!/bin/sh
d="$FAKE_TELL_DIR/$(date +%s%N)"; mkdir -p "$d"; echo "$1" > "$d/to"; shift 2
cat > "$d/body"
while [ $# -gt 0 ]; do
  cp "$2" "$d/"; echo "ATTACHED FILE: $d/$(basename "$2")" >> "$d/files"; shift 2
done
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tell = bindir / "tell"
    tell.write_text(FAKE_TELL)
    tell.chmod(tell.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_TELL_DIR", str(tmp_path / "sent"))
    monkeypatch.setenv("A8S_VAULT_CONFIG", str(tmp_path / "cfg"))
    monkeypatch.setenv("A8S_VAULT_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("A8S_VAULT_CLIENT", str(tmp_path / "agent"))
    v = vaultlib.Vault()
    v.init()
    client.pin(v.pub_path, v.fpr)
    return tmp_path, v


def outbox(tmp_path):
    """Messages sent since the last call, oldest first."""
    root = tmp_path / "sent"
    msgs = []
    for d in sorted(root.iterdir()) if root.exists() else []:
        if (d / ".seen").exists():
            continue
        (d / ".seen").touch()
        files = (d / "files").read_text() if (d / "files").exists() else ""
        msgs.append(((d / "to").read_text().strip(), (d / "body").read_text() + "\n" + files))
    return msgs


def last(tmp_path):
    return outbox(tmp_path)[-1]


def wake(tmp_path, sender, msg):
    assert handler.handle("vault", sender, msg) == 0
    return last(tmp_path)


def agent_send(tmp_path, sender, cmd, file_path=None):
    body, files = client.seal_command(cmd, file_path)
    msg = body + "".join(f"\nATTACHED FILE: {p}" for p in files)
    to, reply = wake(tmp_path, sender, msg)
    assert to == sender
    return client.open_reply(reply, out_dir=str(tmp_path / "got"))


def connect(tmp_path, sender):
    client.connect("vault")
    to, body = last(tmp_path)
    assert to == "vault" and body.startswith("/connect")
    _, reply = wake(tmp_path, sender, body)
    data, _, _ = client.open_reply(reply)
    assert data["ok"] and data["op"] == "connect"


def test_full_flow(env):
    tmp_path, v = env
    with v.db:
        voucher = v.issue("neil")
    connect(tmp_path, "neil")
    data, _, _ = agent_send(tmp_path, "neil", "/list")
    assert not data["ok"] and "not authenticated" in data["error"]
    data, _, _ = agent_send(tmp_path, "neil", f"/authenticate {voucher}")
    assert data["ok"] and data["voucher"] != voucher
    nxt = data["voucher"]
    src = tmp_path / "secret.txt"
    src.write_text("hello vault")
    data, _, _ = agent_send(tmp_path, "neil", "/store keys/secret.txt", str(src))
    assert data["ok"] and data["replaced"] is False
    src.write_text("hello again")
    data, _, _ = agent_send(tmp_path, "neil", "/store keys/secret.txt", str(src))
    assert data["replaced"] is True
    data, _, written = agent_send(tmp_path, "neil", "/retrieve keys/secret.txt")
    assert data["ok"] and open(written[0]).read() == "hello again"
    data, _, _ = agent_send(tmp_path, "neil", "/list")
    assert [f["name"] for f in data["files"]] == ["keys/secret.txt"]

    # VM wiped: new key, new connection, old voucher burned, next voucher works.
    connect(tmp_path, "neil")
    data, _, _ = agent_send(tmp_path, "neil", "/list")
    assert not data["ok"]
    data, _, _ = agent_send(tmp_path, "neil", f"/authenticate {voucher}")
    assert not data["ok"]
    data, _, _ = agent_send(tmp_path, "neil", f"/authenticate {nxt}")
    assert data["ok"]


def test_voucher_is_seat_bound_and_capped(env):
    tmp_path, v = env
    with v.db:
        voucher = v.issue("neil")
    connect(tmp_path, "mallory")
    data, _, _ = agent_send(tmp_path, "mallory", f"/authenticate {voucher}")
    assert not data["ok"]
    connect(tmp_path, "neil")
    data, _, _ = agent_send(tmp_path, "neil", f"/authenticate {voucher}")
    assert data["ok"]
    for _ in range(vaultlib.VOUCHER_CAP - 1):
        assert agent_send(tmp_path, "neil", "/voucher new")[0]["ok"]
    data, _, _ = agent_send(tmp_path, "neil", "/voucher new")
    assert not data["ok"] and "unused vouchers" in data["error"]


def test_plaintext_refused_and_replay(env):
    tmp_path, v = env
    _, body = wake(tmp_path, "neil", "/list")
    assert "refusing plaintext" in body
    with v.db:
        voucher = v.issue("neil")
    connect(tmp_path, "neil")
    sealed, _ = client.seal_command(f"/authenticate {voucher}")
    _, r1 = wake(tmp_path, "neil", sealed)
    _, r2 = wake(tmp_path, "neil", sealed)   # a8s retry / replay: same cached reply
    assert r1 == r2
    connect(tmp_path, "neil")                # new connection: old ciphertext is dead
    _, r3 = wake(tmp_path, "neil", sealed)
    assert "different connection" in r3


def test_hijack_connect_grants_nothing(env):
    tmp_path, v = env
    with v.db:
        voucher = v.issue("neil")
    connect(tmp_path, "neil")
    assert agent_send(tmp_path, "neil", f"/authenticate {voucher}")[0]["ok"]
    with v.db:
        v.connect("neil", crypto.public_pem(v.key_path))   # a forged /connect as neil
    assert v.session("neil")["authed"] == 0


def test_tamper_rejected(env):
    _, v = env
    blob = crypto.seal(v.pub_pem, b"x" * 100)
    bad = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(v.key_path, bad)
