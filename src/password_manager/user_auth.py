import bcrypt

def fix_bcrypt_version():
    """
    If the installed 'bcrypt' package doesn't define '__about__',
    we insert a fake '__about__' with a version attribute so Passlib won't crash.
    """
    if not hasattr(bcrypt, '__about__'):
        class about:
            __version__ = "9.9.9" 
        bcrypt.__about__ = about

fix_bcrypt_version()

import os
import getpass
from passlib.context import CryptContext

# Create a global passlib context for bcrypt hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def store_passlib_hash(password: str, hash_file: str):
    """
    Store password hash in hash_file
    """
    hashed = pwd_context.hash(password)
    with open(hash_file, 'wb') as f:
        f.write(hashed.encode('utf-8'))

def verify_passlib_password(password: str, hash_file: str) -> bool:
    """
    Verify given password against the stored hash in hash_file
    Returns True if matches, False otherwise
    """
    if not os.path.exists(hash_file):
        return False

    with open(hash_file, 'rb') as f:
        stored_hash = f.read().decode('utf-8')
    return pwd_context.verify(password, stored_hash)

def prompt_for_new_password(label: str) -> str:
    """
    For CLI to prompt the user for a new password
    """
    while True:
        p1 = getpass.getpass(f"Create a new {label} password: ")
        p2 = getpass.getpass(f"Confirm the new {label} password: ")
        if p1 == p2:
            return p1
        else:
            print(f"{label.capitalize()} passwords do not match. Please try again.\n")
