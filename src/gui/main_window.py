from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QInputDialog, QLineEdit, QMessageBox
)

from src.password_manager.config import (
    MASTER_HASH_FILE,
    RECOVERY_HASH_FILE,
    ENCRYPTED_KEY_MASTER_FILE,
    ENCRYPTED_KEY_RECOVERY_FILE
)
from src.password_manager.user_auth import (
    store_passlib_hash,
    verify_passlib_password
)
from src.password_manager.ephemeral_key import (
    encrypt_ephemeral_key_with_password,
    decrypt_ephemeral_key_with_password
)
from src.password_manager.credentials import (
    load_credentials,
    save_credentials
)

class MainWindow(QMainWindow):
    """
    Main application window: displays credentials in a table,
    allows adding/updating credentials, and resetting master password
    using the recovery password.
    """
    def __init__(self, ephemeral_key: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Manager")
        self.ephemeral_key = ephemeral_key
        self.credentials = {}

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        # Table for credentials
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Domain", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        main_layout.addWidget(self.table)

        # Button panel
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        add_btn = QPushButton("Add/Update")
        reset_btn = QPushButton("Reset Master Password")
        quit_btn = QPushButton("Quit")

        refresh_btn.clicked.connect(self.load_creds)
        add_btn.clicked.connect(self.add_or_update_credential)
        reset_btn.clicked.connect(self.reset_master_password)
        quit_btn.clicked.connect(self.close)

        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(reset_btn)
        btn_layout.addWidget(quit_btn)

        main_layout.addLayout(btn_layout)

        # Load credentials
        self.load_creds()

    def load_creds(self):
        """Load credentials from disk and populate the table."""
        self.credentials = load_credentials(self.ephemeral_key)
        self.populate_table()

    def populate_table(self):
        self.table.setRowCount(0)
        row = 0
        for account, info in self.credentials.items():
            self.table.insertRow(row)
            username = info.get("username", "")
            password = info.get("password", "")
            self.table.setItem(row, 0, QTableWidgetItem(account))
            self.table.setItem(row, 1, QTableWidgetItem(username))
            self.table.setItem(row, 2, QTableWidgetItem(password))
            row += 1

    def add_or_update_credential(self):
        """
        Prompt user for domain, username, password (via QInputDialog), then store.
        """
        domain, ok = QInputDialog.getText(self, "Domain", "Enter Domain Name:")
        if not ok or not domain:
            return
        username, ok = QInputDialog.getText(self, "Username", "Enter Username/Email:")
        if not ok:
            return
        password, ok = QInputDialog.getText(
            self, "Password", "Enter Password:", QLineEdit.EchoMode.Password
        )
        if not ok:
            return

        self.credentials[domain] = {
            "username": username,
            "password": password
        }
        save_credentials(self.credentials, self.ephemeral_key)
        self.load_creds()

    def reset_master_password(self):
        """
        Prompt for recovery password, if correct, decrypt ephemeral key from
        ENCRYPTED_KEY_RECOVERY_FILE. Then prompt for new MASTER password.
        """
        recovery_pw, ok = QInputDialog.getText(
            self,
            "Recovery Password",
            "Enter RECOVERY password:",
            QLineEdit.EchoMode.Password
        )
        if not ok or not recovery_pw:
            return

        if not verify_passlib_password(recovery_pw, RECOVERY_HASH_FILE):
            QMessageBox.warning(self, "Error", "Incorrect RECOVERY password.")
            return

        # Decrypt ephemeral key
        try:
            rec_ephem = decrypt_ephemeral_key_with_password(recovery_pw, ENCRYPTED_KEY_RECOVERY_FILE)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not decrypt ephemeral key.\n{e}")
            return

        # Prompt for new master password
        new_m1, ok1 = QInputDialog.getText(
            self,
            "New Master Password",
            "Enter new MASTER password:",
            QLineEdit.EchoMode.Password
        )
        if not ok1 or not new_m1:
            return

        new_m2, ok2 = QInputDialog.getText(
            self,
            "Confirm Master Password",
            "Re-enter MASTER password:",
            QLineEdit.EchoMode.Password
        )
        if not ok2 or (new_m1 != new_m2):
            QMessageBox.warning(self, "Error", "MASTER passwords do not match.")
            return

        # Store new master hash
        store_passlib_hash(new_m1, MASTER_HASH_FILE)
        # Re-encrypt ephemeral key with new master password
        encrypt_ephemeral_key_with_password(rec_ephem, new_m1, ENCRYPTED_KEY_MASTER_FILE)

        QMessageBox.information(self, "Success", "Master password has been reset successfully.")
