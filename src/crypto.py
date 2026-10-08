"""A8S-VAULT-1 sealing, signatures and RSA keys, by way of the openssl CLI.

Works the same with OpenSSL 3 and LibreSSL (macOS). The format is the one in
docs/adr/0001: RSA-OAEP-SHA256 wraps a random AES-256-CBC key, an HMAC-SHA256
key and an IV; the HMAC covers the ciphertext and is checked before anything is
decrypted.
"""
import base64
import hashlib
import hmac
import os
import re
import subprocess
import tempfile

MAGIC = b"A8S-VAULT-1"
WIRE = "A8SV1:"
MIN_RSA_BITS = 2048
OAEP = [
    "-pkeyopt", "rsa_padding_mode:oaep",
    "-pkeyopt", "rsa_oaep_md:sha256",
    "-pkeyopt", "rsa_mgf1_md:sha256",
]


class CryptoError(Exception):
    pass


def _openssl():
    return os.environ.get("A8S_VAULT_OPENSSL", "openssl")


def _run(args, data=b""):
    proc = subprocess.run([_openssl(), *args], input=data, capture_output=True)
    if proc.returncode:
        detail = proc.stderr.decode(errors="replace").strip().splitlines()
        raise CryptoError(f"openssl {args[0]} failed: {detail[0] if detail else proc.returncode}")
    return proc.stdout


class _TempFile:
    """A 0600 temp file holding `data`, removed on exit."""

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        fd, self.path = tempfile.mkstemp(prefix="a8s-vault-")
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.data)
        return self.path

    def __exit__(self, *exc):
        os.unlink(self.path)


def generate_key(path):
    old = os.umask(0o077)
    try:
        _run(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", path])
    finally:
        os.umask(old)
    os.chmod(path, 0o600)


def public_pem(key_path):
    return _run(["pkey", "-in", key_path, "-pubout"])


def load_public(pem):
    """Validate and normalise a public key. Raises CryptoError for anything else."""
    if not isinstance(pem, bytes):
        pem = pem.encode()
    try:
        text = _run(["pkey", "-pubin", "-noout", "-text"], pem).decode(errors="replace")
    except CryptoError as exc:
        raise CryptoError("not a PEM public key") from exc
    match = re.search(r"\((\d+) bit", text)
    if "Modulus" not in text or not match:
        raise CryptoError("only RSA public keys are supported")
    if int(match.group(1)) < MIN_RSA_BITS:
        raise CryptoError(f"RSA key is {match.group(1)} bits; need at least {MIN_RSA_BITS}")
    return _run(["pkey", "-pubin"], pem)


def fingerprint(pem):
    """SHA-256 of the DER SubjectPublicKeyInfo, identical across OpenSSL and LibreSSL."""
    if not isinstance(pem, bytes):
        pem = pem.encode()
    return hashlib.sha256(_run(["pkey", "-pubin", "-outform", "DER"], pem)).hexdigest()


def seal(pub_pem, plaintext):
    enc_key, mac_key, iv = os.urandom(32), os.urandom(32), os.urandom(16)
    body = _run(["enc", "-aes-256-cbc", "-K", enc_key.hex(), "-iv", iv.hex()], plaintext)
    mac = hmac.new(mac_key, body, hashlib.sha256).hexdigest()
    secret = f"{enc_key.hex()}:{mac_key.hex()}:{iv.hex()}".encode()
    with _TempFile(pub_pem) as pub:
        wrapped = _run(["pkeyutl", "-encrypt", "-pubin", "-inkey", pub, *OAEP], secret)
    return b"\n".join([MAGIC, base64.b64encode(wrapped), mac.encode(), body])


def open_sealed(key_path, blob):
    """Return the plaintext, or raise CryptoError. Nothing is decrypted unless the MAC holds."""
    parts = blob.split(b"\n", 3)
    if len(parts) != 4 or parts[0] != MAGIC:
        raise CryptoError("not an A8S-VAULT-1 blob")
    try:
        wrapped = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise CryptoError("malformed wrapped key") from exc
    secret = _run(["pkeyutl", "-decrypt", "-inkey", key_path, *OAEP], wrapped).decode()
    try:
        enc_hex, mac_hex, iv_hex = secret.split(":")
        mac_key = bytes.fromhex(mac_hex)
    except ValueError as exc:
        raise CryptoError("malformed key material") from exc
    expected = hmac.new(mac_key, parts[3], hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts[2].decode(errors="replace")):
        raise CryptoError("MAC mismatch: corrupted or tampered")
    return _run(["enc", "-d", "-aes-256-cbc", "-K", enc_hex, "-iv", iv_hex], parts[3])


def sign(key_path, data):
    return _run(["dgst", "-sha256", "-sign", key_path], data)


def verify(pub_pem, data, signature):
    with _TempFile(pub_pem) as pub, _TempFile(signature) as sig:
        proc = subprocess.run(
            [_openssl(), "dgst", "-sha256", "-verify", pub, "-signature", sig],
            input=data, capture_output=True,
        )
    return proc.returncode == 0


def to_wire(blob):
    return WIRE + base64.b64encode(blob).decode()


def from_wire(text):
    text = text.strip()
    if not text.startswith(WIRE):
        raise CryptoError("not an A8SV1 message")
    try:
        return base64.b64decode(text[len(WIRE):], validate=True)
    except ValueError as exc:
        raise CryptoError("malformed base64 in A8SV1 message") from exc
