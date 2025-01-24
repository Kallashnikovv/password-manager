import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import KDF_ITERATIONS

def derive_fernet_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Make a 32 byte key from the given password + salt using PBKDF2HMAC,
    and encode it for use by Fernet
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def encrypt_ephemeral_key_with_password(ephemeral_key: bytes, password: str, out_file: str):
    """
    Makes a Fernet key from the given password and a random salt,
    then encrypts the ephemeral key and writes to out_file with format:
      [16-byte salt][encrypted_ephemeral_key]
    """
    salt = os.urandom(16)
    fernet_key = derive_fernet_key_from_password(password, salt)
    f = Fernet(fernet_key)
    encrypted = f.encrypt(ephemeral_key)
    with open(out_file, 'wb') as fp:
        fp.write(salt + encrypted)

def decrypt_ephemeral_key_with_password(password: str, in_file: str) -> bytes:
    """
    Reads [16-byte salt] + [encrypted_ephemeral_key] from in_file,
    makes Fernet key with password & salt, decrypts it
    and returns the decrypted ephemeral key bytes
    """
    if not os.path.exists(in_file):
        raise FileNotFoundError(f"Missing file: {in_file}")
    with open(in_file, 'rb') as fp:
        data = fp.read()

    salt = data[:16]
    encrypted = data[16:]
    fernet_key = derive_fernet_key_from_password(password, salt)
    f = Fernet(fernet_key)
    ephemeral_key = f.decrypt(encrypted)
    return ephemeral_key
