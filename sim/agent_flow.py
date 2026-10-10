#!/usr/bin/env python3
"""Runs inside an agent container. Drives the vault the way an agent would: tell + inbox."""
import glob
import json
import os
import subprocess
import sys
import time

VAULT = os.environ.get("A8S_VAULT_SEAT", "vault")
INBOX = os.path.expanduser("~/seat/.inbox")
FILES = os.path.expanduser("~/seat/.files")
CLI = "/opt/a8s-vault/a8s-vault"
DURABLE = "/durable"            # survives VM wipes; nothing secret lives here
SEEN = set(glob.glob(os.path.join(INBOX, "*.json")))   # earlier phases's mail
os.environ["TELL_OUTBOX_DIR"] = os.path.expanduser("~/seat/.outbox")


def sh(*argv, check=True):
    proc = subprocess.run(argv, capture_output=True, text=True)
    if check and proc.returncode:
        sys.exit(f"FAIL {' '.join(argv)}\n{proc.stdout}{proc.stderr}")
    return proc


def reply(timeout=90):
    """Next message from the vault, as `content + ATTACHED FILE lines`."""
    end = time.time() + timeout
    while time.time() < end:
        for path in sorted(glob.glob(os.path.join(INBOX, "*.json"))):
            if path in SEEN:
                continue
            SEEN.add(path)
            env = json.load(open(path))
            if env.get("from") != VAULT:
                continue
            if os.environ.get("SIM_DEBUG"):
                print(json.dumps(env, indent=1)[:1500])
            files = []
            for f in env.get("files") or []:
                name = f if isinstance(f, str) else f.get("filename", "")
                files.append(os.path.join(FILES, env["id"], name))
            return "\n".join([env.get("content", "")] + [f"ATTACHED FILE: {p}" for p in files])
        time.sleep(0.5)
    sys.exit("FAIL no reply from vault")


def opened(*extra):
    while True:
        proc = subprocess.run([CLI, "client", "open", "-", *extra], input=reply(),
                              capture_output=True, text=True)
        if proc.returncode != 3:
            break
        print("   (skipped a reply sealed to an earlier connection key)")
    out = proc.stdout + proc.stderr
    print("   <-", out.strip().replace("\n", "\n      ")[:600])
    return proc.returncode, out


def expect(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        sys.exit(1)


def bootstrap():
    sh("tell", VAULT, "/public-key")
    msg = reply()
    pem = [ln.split(": ", 1)[1] for ln in msg.splitlines() if ln.startswith("ATTACHED FILE:")]
    expect(pem, "vault sent its public key")
    fpr = open(f"{DURABLE}/vault.fingerprint").read().strip()
    sh(CLI, "client", "pin", pem[0], "--fingerprint", fpr)
    expect(True, f"pinned vault key {fpr[:16]}... against the durable fingerprint")
    sh(CLI, "client", "connect", "--to", VAULT)
    rc, out = opened()
    expect(rc == 0 and '"op": "connect"' in out, "/connect reply opens and verifies")


def send(cmd, *extra):
    sh(CLI, "client", "send", "--to", VAULT, cmd, *extra)


def auth():
    sh(CLI, "client", "auth", "--to", VAULT, "--voucher-file", f"{DURABLE}/voucher")
    return opened("--save-voucher", f"{DURABLE}/voucher")


def phase_first():
    bootstrap()
    send("/list")
    rc, out = opened()
    expect(rc != 0 and "not authenticated" in out, "sealed /list refused before /authenticate")
    old = open(f"{DURABLE}/voucher").read().strip()
    rc, out = auth()
    new = open(f"{DURABLE}/voucher").read().strip()
    expect(rc == 0 and new != old, "voucher burned; replacement saved to durable store")
    open(f"{DURABLE}/burned", "w").write(old)
    os.makedirs("/tmp/work", exist_ok=True)
    with open("/tmp/work/ssh.pem", "w") as f:
        f.write("first version\n")
    send("/store keys/ssh.pem", "--file", "/tmp/work/ssh.pem")
    rc, out = opened()
    expect(rc == 0 and '"replaced": false' in out, "/store keys/ssh.pem")
    with open("/tmp/work/ssh.pem", "w") as f:
        f.write("PRIVATE KEY v2\n")
    send("/store keys/ssh.pem", "--file", "/tmp/work/ssh.pem")
    rc, out = opened()
    expect(rc == 0 and '"replaced": true' in out, "second /store overwrote it (no force flag)")
    send("/list")
    rc, out = opened()
    expect(rc == 0 and "keys/ssh.pem" in out, "/list shows keys/ssh.pem")


def phase_after_wipe():
    expect(not os.path.exists(os.path.expanduser("~/.cache/a8s-vault-client")),
           "fresh VM: no client key, no files")
    bootstrap()
    rc, out = auth()
    expect(rc == 0, "authenticated with the voucher from the durable store")
    send("/retrieve keys/ssh.pem")
    rc, out = opened("--out", "/tmp/restore")
    got = open("/tmp/restore/keys/ssh.pem").read()
    expect(rc == 0 and got == "PRIVATE KEY v2\n", "retrieved the overwritten file after the wipe")
    for _ in range(9):
        send("/voucher new")
        opened()
    send("/voucher new")
    rc, out = opened()
    expect(rc != 0 and "10 unused vouchers" in out, "11th voucher refused (cap 10)")


def phase_burned():
    bootstrap()
    sh(CLI, "client", "auth", "--to", VAULT, "--voucher-file", f"{DURABLE}/burned")
    rc, out = opened()
    expect(rc != 0 and "not accepted" in out, "a burned voucher is refused")


def phase_mallory():
    bootstrap()
    sh(CLI, "client", "auth", "--to", VAULT, "--voucher-file", f"{DURABLE}/voucher")
    rc, out = opened()
    expect(rc != 0 and "not accepted" in out, "another seat cannot use agent1's voucher")
    sh("tell", VAULT, "/list")
    msg = reply()
    expect("refusing plaintext" in msg, "plaintext /list refused")


if __name__ == "__main__":
    {"first": phase_first, "after-wipe": phase_after_wipe, "burned": phase_burned,
     "mallory": phase_mallory}[sys.argv[1]]()
