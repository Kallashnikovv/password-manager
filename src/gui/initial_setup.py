import os

from PyQt6.QtWidgets import QMessageBox, QInputDialog, QLineEdit

from src.password_manager.config import (
    MASTER_HASH_FILE,
    RECOVERY_HASH_FILE,
    ENCRYPTED_KEY_MASTER_FILE,
    ENCRYPTED_KEY_RECOVERY_FILE,
    CREDENTIALS_FILE
)
from src.password_manager.user_auth import (
    store_passlib_hash
)
from src.password_manager.ephemeral_key import (
    encrypt_ephemeral_key_with_password
)

def initial_setup_gui():
    """
    If MASTER/RECOVERY hashes don't exist, prompt user to create them,
    then generate & store the ephemeral key encrypted by both.
    """
    if os.path.exists(MASTER_HASH_FILE) and os.path.exists(RECOVERY_HASH_FILE):
        return  # Already set up

    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Information)
    msg.setWindowTitle("Initial Setup")
    msg.setText("No master/recovery password found.\nPlease create them now.")
    msg.exec()

    # Create MASTER password
    master_pw = _create_password("MASTER")
    # Create RECOVERY password
    recovery_pw = _create_password("RECOVERY")

    # Generate ephemeral key
    ephemeral_key = os.urandom(32)

    # Encrypt ephemeral key for MASTER
    encrypt_ephemeral_key_with_password(ephemeral_key, master_pw, ENCRYPTED_KEY_MASTER_FILE)
    # Encrypt ephemeral key for RECOVERY
    encrypt_ephemeral_key_with_password(ephemeral_key, recovery_pw, ENCRYPTED_KEY_RECOVERY_FILE)

    # Create empty credentials.json if needed
    if not os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'wb') as f:
            f.write(b'')

    QMessageBox.information(None, "Setup Complete",
        "Master/Recovery passwords and keys have been initialized."
    )

def _create_password(label: str) -> str:
    """Helper to prompt the user for a new password of type label (MASTER or RECOVERY)."""
    from PyQt6.QtWidgets import QMessageBox
    pw_set = False
    final_pw = ""

    while not pw_set:
        pw1, ok1 = QInputDialog.getText(
            None,
            f"{label} Password",
            f"Enter NEW {label} password:",
            QLineEdit.EchoMode.Password
        )
        if not ok1 or not pw1:
            QMessageBox.warning(None, "Error", f"You must provide a {label} password.")
            continue

        pw2, ok2 = QInputDialog.getText(
            None,
            f"Confirm {label} Password",
            f"Re-enter {label} password:",
            QLineEdit.EchoMode.Password
        )
        if not ok2 or (pw1 != pw2):
            QMessageBox.warning(None, "Error", f"{label} passwords do not match.")
            continue

        # Store passlib hash
        if label == "MASTER":
            store_passlib_hash(pw1, MASTER_HASH_FILE)
        else:
            store_passlib_hash(pw1, RECOVERY_HASH_FILE)
        
        final_pw = pw1
        pw_set = True

    return final_pw
