from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from src.password_manager.config import (
    MASTER_HASH_FILE,
    ENCRYPTED_KEY_MASTER_FILE
)
from src.password_manager.user_auth import verify_passlib_password
from src.password_manager.ephemeral_key import decrypt_ephemeral_key_with_password

class LoginDialog(QDialog):
    """
    A QDialog for entering the MASTER password.
    If successful, ephemeral_key is set on self, else None.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login - Password Manager")
        self.ephemeral_key = None

        layout = QVBoxLayout()

        # Label
        layout.addWidget(QLabel("Enter MASTER password:"))

        # Password Field
        self.master_input = QLineEdit()
        self.master_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.master_input)

        # Buttons
        btn_layout = QHBoxLayout()
        login_btn = QPushButton("Login")
        cancel_btn = QPushButton("Cancel")
        login_btn.clicked.connect(self.handle_login)
        cancel_btn.clicked.connect(self.handle_cancel)
        btn_layout.addWidget(login_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def handle_login(self):
        pw = self.master_input.text().strip()
        if not pw:
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return

        # Verify with Passlib
        if verify_passlib_password(pw, MASTER_HASH_FILE):
            # Decrypt ephemeral key
            try:
                key = decrypt_ephemeral_key_with_password(pw, ENCRYPTED_KEY_MASTER_FILE)
                self.ephemeral_key = key
                # Accept the dialog
                from PyQt6.QtWidgets import QDialog
                self.done(QDialog.DialogCode.Accepted.value)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to decrypt ephemeral key.\n{e}")
        else:
            QMessageBox.warning(self, "Error", "Incorrect MASTER password.")

    def handle_cancel(self):
        self.ephemeral_key = None
        from PyQt6.QtWidgets import QDialog
        self.done(QDialog.DialogCode.Rejected.value)
