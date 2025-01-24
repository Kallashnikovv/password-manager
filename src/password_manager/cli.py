import getpass
import sys
import os

from .config import (
    MASTER_HASH_FILE,
    RECOVERY_HASH_FILE,
    ENCRYPTED_KEY_MASTER_FILE,
    ENCRYPTED_KEY_RECOVERY_FILE,
    CREDENTIALS_FILE
)
from src.password_manager.user_auth import (
    prompt_for_new_password,
    store_passlib_hash,
    verify_passlib_password
)
from src.password_manager.ephemeral_key import (
    decrypt_ephemeral_key_with_password,
    encrypt_ephemeral_key_with_password
)
from src.password_manager.credentials import load_credentials, save_credentials


def view_credentials(credentials: dict):
    """ Print stored credentials to the console """
    if not credentials:
        print("No credentials stored.")
        return
    print("\nStored Credentials:")
    for account, info in credentials.items():
        username = info.get('username', '')
        pwd = info.get('password', '')
        print(f"- {account} | username: {username} password: {pwd}")
    print()


def add_or_update_credential(credentials: dict):
    """ Ask user for account, username, password and store them in credentials """
    account = input("Enter account name (e.g., 'gmail'): ").strip()
    username = input("Enter username/email: ").strip()
    pwd = getpass.getpass("Enter password: ")

    credentials[account] = {
        'username': username,
        'password': pwd
    }
    print(f"\nCredentials for '{account}' updated successfully.\n")


def reset_master_password():
    """
    If correct: resets the master password using the recovery password.
        1. Decrypt ephemeral key with recovery password
        2. Prompt for new master password
        3. Re-encrypt ephemeral key with new master password
    """
    attempts = 3
    ephemeral_key = None
    for _ in range(attempts):
        recovery_pw = getpass.getpass("Enter your RECOVERY password: ")
        if verify_passlib_password(recovery_pw, RECOVERY_HASH_FILE):
            # Correct: use it to decrypt ephemeral key
            try:
                ephemeral_key = decrypt_ephemeral_key_with_password(
                    recovery_pw,
                    ENCRYPTED_KEY_RECOVERY_FILE
                )
            except Exception:
                print("Error: Could not decrypt ephemeral key with recovery password.")
                return
            break
        else:
            print("Incorrect recovery password. Try again.\n")
    else:
        print("Too many failed attempts. Returning to menu.")
        return

    if ephemeral_key is None:
        print("Recovery failed. Returning to menu.")
        return

    # 2. Prompt for new master password
    new_master = prompt_for_new_password("MASTER")
    store_passlib_hash(new_master, MASTER_HASH_FILE)

    # 3. Re-encrypt ephemeral key with new master password
    encrypt_ephemeral_key_with_password(
        ephemeral_key,
        new_master,
        ENCRYPTED_KEY_MASTER_FILE
    )
    print("\nMaster password successfully reset!\n")

def _check_initial_setup():
    """
    Check if master/recovery hashes exist
    If not, ask user to create them and generate ephemeral key
    """
    if os.path.exists(MASTER_HASH_FILE) and os.path.exists(RECOVERY_HASH_FILE):
        return

    # Master password creation
    print("No master password found. Let's create one.")
    master_pw = prompt_for_new_password("MASTER")
    store_passlib_hash(master_pw, MASTER_HASH_FILE)

    # Recovery password creation
    print("No recovery password found. Let's create one.")
    recovery_pw = prompt_for_new_password("RECOVERY")
    store_passlib_hash(recovery_pw, RECOVERY_HASH_FILE)

    # Generate ephemeral key
    ephemeral_key = os.urandom(32)

    # Encrypt ephemeral key with both master and recovery
    encrypt_ephemeral_key_with_password(ephemeral_key, master_pw, ENCRYPTED_KEY_MASTER_FILE)
    encrypt_ephemeral_key_with_password(ephemeral_key, recovery_pw, ENCRYPTED_KEY_RECOVERY_FILE)

    # Create empty credentials file if needed
    if not os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'wb') as f:
            f.write(b'')

    print("Initial setup complete!\n")


def _login_master_password():
    """
    Ask user for MASTER password. If correct, return ephemeral_key, else None
    """
    attempts = 3
    for _ in range(attempts):
        master_pw = getpass.getpass("Enter MASTER password: ")
        if verify_passlib_password(master_pw, MASTER_HASH_FILE):
            # Attempt to decrypt ephemeral key
            try:
                ephemeral_key = decrypt_ephemeral_key_with_password(master_pw, ENCRYPTED_KEY_MASTER_FILE)
                return ephemeral_key
            except Exception as e:
                print(f"Error: Could not decrypt ephemeral key ({e}).")
        else:
            print("Incorrect master password.\n")

    return None


def run_cli():
    """
    Start CLI
    """
    _check_initial_setup()

    ephemeral_key = _login_master_password()
    if ephemeral_key is None:
        print("Failed to authenticate. Exiting.")
        sys.exit(1)

    # Load existing credentials
    credentials = load_credentials(ephemeral_key)

    while True:
        print("=== CLI PASSWORD MANAGER ===")
        print("1. View stored credentials")
        print("2. Add/update credential")
        print("3. Reset MASTER password (requires RECOVERY)")
        print("4. Exit")
        choice = input("Enter choice (1/2/3/4): ").strip()

        if choice == '1':
            view_credentials(credentials)
        elif choice == '2':
            add_or_update_credential(credentials)
            save_credentials(credentials, ephemeral_key)
        elif choice == '3':
            reset_master_password()
        elif choice == '4':
            sys.exit(0)
        else:
            print("Invalid choice. Try again.\n")
