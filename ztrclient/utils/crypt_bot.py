import base64
import json
import os
import secrets
import stat
import threading
from typing import Tuple, Union

try:
    import fcntl
except ImportError:  # no flock on this platform — create_keys() then runs unlocked, as before
    fcntl = None

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# Parsing a private-key PEM is by far the most expensive thing a CryptBot does -- pycryptodome checks the key's
# primes as it imports it: ~65ms on a server CPU, ~450ms on a Raspberry Pi 4 -- and every new CryptBot used to
# do it again for the same file (hops build one per request, the client one per tunnel). A key file does not
# change, so the parsed key is kept for the life of the process, per (path, modification time, size); replacing
# the file loads the new one.
_PRIV_KEY_CACHE = {}
_PRIV_KEY_CACHE_LOCK = threading.Lock()
_PRIV_KEY_CACHE_MAX = 32


def _load_private_key_cached(path: str) -> RSA.RsaKey:
    st = os.stat(path)
    cache_key = (os.path.abspath(path), st.st_mtime_ns, st.st_size)
    with _PRIV_KEY_CACHE_LOCK:
        hit = _PRIV_KEY_CACHE.get(cache_key)
    if hit is not None:
        return hit
    with open(path, "rb") as f:
        parsed = RSA.import_key(f.read())
    with _PRIV_KEY_CACHE_LOCK:
        if len(_PRIV_KEY_CACHE) >= _PRIV_KEY_CACHE_MAX:
            _PRIV_KEY_CACHE.clear()
        _PRIV_KEY_CACHE[cache_key] = parsed
    return parsed


def encrypt_msg(msg: bytes, public_key: RSA.RsaKey) -> Tuple[bytes, bytes, bytes]:
    """Encrypt message with AES-CBC and encrypt AES key with RSA-OAEP."""
    aes_key = secrets.token_bytes(32)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = aes_cipher.encrypt(pad(msg, AES.block_size))
    
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    return ciphertext, encrypted_aes_key, aes_cipher.iv


def decrypt_msg(ciphertext: bytes, encrypted_aes_key: bytes, iv: bytes, private_key: RSA.RsaKey, as_: str = "str") -> Union[str, bytes]:
    """Decrypt AES key with RSA-OAEP and decrypt ciphertext with AES-CBC."""
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    
    return plaintext.decode("utf-8") if as_ == "str" else plaintext


class CryptBot:
    def __init__(self, pathPrivateKey: str, pathPublicKey: str, pathRecipientPublicKey: str):
        self.pathPrivateKey = pathPrivateKey
        self.pathPublicKey = pathPublicKey
        self.pathRecipientPublicKey = pathRecipientPublicKey

        self._priv_key: RSA.RsaKey = None
        self._pub_key: RSA.RsaKey = None
        self._recipient_pub_key: RSA.RsaKey = None
        self._payload_delimiter = b":###:"

    # ------------------------------------------------------------------
    # Single-Library Key Cache
    # ------------------------------------------------------------------

    def _load_priv_key(self) -> RSA.RsaKey:
        if self._priv_key is None:
            self._priv_key = _load_private_key_cached(self.pathPrivateKey)
        return self._priv_key

    def _load_recipient_pub_key(self) -> RSA.RsaKey:
        if self._recipient_pub_key is None:
            with open(self.pathRecipientPublicKey, "rb") as f:
                self._recipient_pub_key = RSA.import_key(f.read())
        return self._recipient_pub_key

    def set_recipient_pubkey(self, path: str):
        self.pathRecipientPublicKey = path
        self._recipient_pub_key = None

    def set_own_keys(self, pathPrivateKey: str = None, pathPublicKey: str = None):
        if pathPrivateKey:
            self.pathPrivateKey = pathPrivateKey
            self._priv_key = None
        if pathPublicKey:
            self.pathPublicKey = pathPublicKey
            self._pub_key = None

    # ------------------------------------------------------------------
    # Core Crypto Operations
    # ------------------------------------------------------------------
    
    def sign_(self, msg: str):
        h = SHA256.new(msg.encode("utf-8"))
        signature = pkcs1_15.new(self._load_priv_key()).sign(h)
        return signature

    def encrypt_sign(self, msg: Union[str, bytes]) -> Tuple[bytes, bytes, bytes, bytes]:
        if isinstance(msg, str):
            msg = msg.encode("utf-8")

        # Sign
        h = SHA256.new(msg)
        signature = pkcs1_15.new(self._load_priv_key()).sign(h)

        # Encrypt
        ct, eak, iv = encrypt_msg(msg, self._load_recipient_pub_key())
        return ct, eak, iv, signature

    def decrypt_msg_verify(self, msgClient: Tuple[bytes, bytes, bytes, bytes], as_: str = "str") -> Union[str, bytes, None]:
        if isinstance(msgClient, tuple) and len(msgClient) == 4:
            ct, eak, iv, signature = msgClient
            decrypted_msg = decrypt_msg(ct, eak, iv, self._load_priv_key(), as_="bytes")

            h = SHA256.new(decrypted_msg)
            try:
                pkcs1_15.new(self._load_recipient_pub_key()).verify(h, signature)
            except (ValueError, TypeError):
                return None

            return decrypted_msg.decode("utf-8") if as_ == "str" else decrypted_msg
        return None

    def decrypt_msg_no_verify(self, msgClient: Tuple[bytes, bytes, bytes, bytes], as_: str = "str") -> Union[str, bytes, None]:
        if isinstance(msgClient, tuple) and len(msgClient) == 4:
            ct, eak, iv, _ = msgClient
            return decrypt_msg(ct, eak, iv, self._load_priv_key(), as_=as_)
        return None

    # ------------------------------------------------------------------
    # Delimiter Payload Methods
    # ------------------------------------------------------------------

    def encrypt_sign_BytesPayload(self, msg: Union[str, bytes]) -> bytes:
        ct, eak, iv, signature = self.encrypt_sign(msg)
        return self._payload_delimiter.join([ct, eak, iv, signature])

    def unpackBytesPayload(self, payload: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        ct, eak, iv, signature = payload.split(self._payload_delimiter, 3)
        return ct, eak, iv, signature

    def decrypt_msg_verifyBytesPayload(self, payload: bytes, verify: bool = True, as_: str = "str"):
        data = self.unpackBytesPayload(payload)
        if verify:
            return self.decrypt_msg_verify(data, as_)
        return self.decrypt_msg_no_verify(data, as_)
        
    # ------------------------------------------------------------------
    # Key Management
    # ------------------------------------------------------------------

    def check_keys(self) -> bool:
        return os.path.exists(self.pathPublicKey) and os.path.exists(self.pathPrivateKey)

    def _tighten_private_key(self):
        """A private key other users can read isn't private, and earlier versions wrote it that way. Takes group and
        other access away from an existing one. Quietly does nothing when it isn't ours to change (another user owns
        it), on a platform without these permission bits, or when the path is a link (the target may be shared)."""
        try:
            if os.path.islink(self.pathPrivateKey):
                return
            mode = stat.S_IMODE(os.stat(self.pathPrivateKey).st_mode)
            if mode & 0o077:
                os.chmod(self.pathPrivateKey, mode & 0o700)
        except OSError:
            pass

    def create_keys(self, rsa_size: int = 2048, reuse: bool = False):
        if self.check_keys() and reuse:
            self._tighten_private_key()
            return self.load_keys()

        # One generator at a time: processes starting together on a fresh
        # install each generated their own pair, and only one of those could
        # be the pair left on disk. The rest wait here, then load that one.
        lock_fd = os.open(os.path.dirname(os.path.abspath(self.pathPrivateKey)), os.O_RDONLY)
        try:
            if fcntl:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if reuse and self.check_keys():
                self._tighten_private_key()
                return self.load_keys()

            key = RSA.generate(rsa_size)
            self._write_atomically(self.pathPrivateKey, key.export_key("PEM"), mode=0o600)
            self._write_atomically(self.pathPublicKey, key.publickey().export_key("PEM"))

            self._priv_key = key
            self._pub_key = key.publickey()
            return self._pub_key, self._priv_key
        finally:
            os.close(lock_fd)  # also releases the lock

    @staticmethod
    def _write_atomically(path: str, data: bytes, mode: int = 0o666):
        """Writes data to a temp file and renames it into place. The file is created with `mode` (less the umask) from
        the start, so a private key is never readable by others, not even for an instant."""
        tmp_path = f"{path}.{os.getpid()}.tmp"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load_keys(self) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        priv = self._load_priv_key()
        with open(self.pathPublicKey, "rb") as f:
            pub = RSA.import_key(f.read())
        return pub, priv

    def rawPublicKey(self) -> bytes:
        with open(self.pathPublicKey, "rb") as f:
            return f.read()
