import base64
import json
import os
import secrets
from typing import Tuple, Union

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


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
            with open(self.pathPrivateKey, "rb") as f:
                self._priv_key = RSA.import_key(f.read())
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

    def create_keys(self, rsa_size: int = 2048, reuse: bool = False):
        if self.check_keys() and reuse:
            return self.load_keys()

        key = RSA.generate(rsa_size)
        priv_pem = key.export_key("PEM")
        pub_pem = key.publickey().export_key("PEM")

        with open(self.pathPrivateKey, "wb") as f:
            f.write(priv_pem)
        with open(self.pathPublicKey, "wb") as f:
            f.write(pub_pem)

        self._priv_key = key
        self._pub_key = key.publickey()
        return self._pub_key, self._priv_key

    def load_keys(self) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        priv = self._load_priv_key()
        with open(self.pathPublicKey, "rb") as f:
            pub = RSA.import_key(f.read())
        return pub, priv

    def rawPublicKey(self) -> bytes:
        with open(self.pathPublicKey, "rb") as f:
            return f.read()
