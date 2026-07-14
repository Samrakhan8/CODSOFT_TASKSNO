"""
crypto_store.py - encryption at rest using envelope encryption (AES-256-GCM).

Design
------
* A long-lived **master key** (KEK) protects everything. In production it comes
  from the SFS_MASTER_KEY environment variable (or a KMS); for local use it is
  generated once and persisted to storage/.masterkey with tight permissions.
* Each file gets its own random **data key** (DEK). The file is encrypted with
  AES-256-GCM under its DEK; the DEK is then wrapped (encrypted) with the master
  key. Only the wrapped DEK, the nonces, and the ciphertext are stored - the
  plaintext DEK never touches disk.
* The file's id is bound in as AES-GCM associated data, so ciphertext cannot be
  silently swapped between records, and any tampering fails the auth tag.

This is the same pattern KMS-backed systems use, kept dependency-light.
"""

import base64
import hashlib
import os
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MasterKeyError(RuntimeError):
    pass


def _load_or_create_master_key(storage_dir):
    """Master key resolution order: env var -> persisted file -> new file."""
    env = os.environ.get("SFS_MASTER_KEY")
    if env:
        try:
            key = base64.urlsafe_b64decode(env)
        except Exception as exc:  # noqa: BLE001
            raise MasterKeyError("SFS_MASTER_KEY is not valid base64") from exc
        if len(key) != 32:
            raise MasterKeyError("SFS_MASTER_KEY must decode to 32 bytes")
        return key

    path = os.path.join(storage_dir, ".masterkey")
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read()

    # First run with no configured key: generate and persist one.
    os.makedirs(storage_dir, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    with open(path, "wb") as fh:
        fh.write(key)
    try:  # best-effort lock-down (POSIX; on Windows this is a no-op-ish)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


class CryptoStore:
    def __init__(self, storage_dir):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self._master = _load_or_create_master_key(storage_dir)

    def _blob_path(self, file_id):
        # file_id is a server-generated UUID hex, so it can never traverse.
        return os.path.join(self.storage_dir, file_id + ".enc")

    def encrypt(self, file_id, plaintext):
        """Encrypt bytes for a file, write the blob, return crypto metadata."""
        aad = file_id.encode()
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)

        wrap_nonce = os.urandom(12)
        wrapped_dek = AESGCM(self._master).encrypt(wrap_nonce, dek, aad)

        with open(self._blob_path(file_id), "wb") as fh:
            fh.write(ciphertext)

        return {
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_key": base64.b64encode(wrapped_dek).decode(),
            "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
            "size": len(plaintext),
        }

    def decrypt(self, file_id, meta):
        """Read and decrypt a file's blob, verifying integrity."""
        aad = file_id.encode()
        wrapped_dek = base64.b64decode(meta["wrapped_key"])
        wrap_nonce = base64.b64decode(meta["wrap_nonce"])
        dek = AESGCM(self._master).decrypt(wrap_nonce, wrapped_dek, aad)

        nonce = base64.b64decode(meta["nonce"])
        with open(self._blob_path(file_id), "rb") as fh:
            ciphertext = fh.read()
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, aad)

        if hashlib.sha256(plaintext).hexdigest() != meta["sha256"]:
            raise ValueError("integrity check failed for %s" % file_id)
        return plaintext

    def remove(self, file_id):
        path = self._blob_path(file_id)
        if os.path.exists(path):
            os.remove(path)
