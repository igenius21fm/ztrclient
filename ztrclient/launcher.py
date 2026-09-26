import os
import sys

try:
    from utils.crypt_bot import CryptBot
except ImportError:
    print("pycryptodome isn't installed for this Python interpreter.")
    print("Run ./launcher.sh instead of calling launcher.py directly — it")
    print("creates ztr's venv (with pycryptodome in it) and runs this for you.")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

crypt = CryptBot(
            pathPrivateKey=f"{SCRIPT_DIR}/privateKey.pem",
            pathPublicKey=f"{SCRIPT_DIR}/publicKey.pem",
            pathRecipientPublicKey=""
        )
crypt.create_keys(rsa_size=3072, reuse=True)

if __name__ == "__main__":
    pubKey = open(crypt.pathPublicKey, "r").read()
    print(f"My PubKey:\n {pubKey}\n")
    signature = crypt.sign_(input("Nonce To Sign: "))
    print(f"Signature Hex: {signature.hex()}")
