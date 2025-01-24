import os
import json
import base64
from cryptography.fernet import Fernet
from .config import CREDENTIALS_FILE

def load_credentials(ephemeral_key: bytes, file : str = None) -> dict:
    """
    Load credentials from CREDENTIALS_FILE (Fernet-encrypted by ephemeral_key)
    Return a dictionary of credentials if successful, otherwise {}.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    if file is not None:
        if not os.path.exists(file):
            return {}
        with open(file, 'rb') as file:
            encrypted_data = file.read()
            if not encrypted_data:
                return {}
    else:
        with open(CREDENTIALS_FILE, 'rb') as file:
            encrypted_data = file.read()
            if not encrypted_data:
                return {}

    f = Fernet(base64.urlsafe_b64encode(ephemeral_key))
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        print("Error: Could not decrypt credentials file.")
        return {}

def save_credentials(credentials: dict, ephemeral_key: bytes, file : str = None):
    """
    Encrypt the credentials dict with ephemeral_key and write to CREDENTIALS_FILE
    """
    f = Fernet(base64.urlsafe_b64encode(ephemeral_key))
    data = json.dumps(credentials).encode('utf-8')
    encrypted = f.encrypt(data)
    if file is not None:
        with open(file, 'wb') as file:
            file.write(encrypted)
    else:
        with open(CREDENTIALS_FILE, 'wb') as file:
            file.write(encrypted)
