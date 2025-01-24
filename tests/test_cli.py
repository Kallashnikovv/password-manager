import os
import pytest
from src.password_manager.cli import _check_initial_setup, _login_master_password
from src.password_manager.user_auth import store_passlib_hash
from src.password_manager.ephemeral_key import encrypt_ephemeral_key_with_password

@pytest.fixture
def temp_files(tmp_path):
    return {
        "MASTER_HASH_FILE": tmp_path / "master.hash",
        "RECOVERY_HASH_FILE": tmp_path / "recovery.hash",
        "ENCRYPTED_KEY_MASTER_FILE": tmp_path / "encrypted_key_master.bin",
        "ENCRYPTED_KEY_RECOVERY_FILE": tmp_path / "encrypted_key_recovery.bin",
        "CREDENTIALS_FILE": tmp_path / "credentials.json"
    }

def test_initial_setup(monkeypatch, temp_files):
    monkeypatch.setattr('builtins.input', lambda _: "test_password")
    monkeypatch.setattr('getpass.getpass', lambda _: "test_password")
    _check_initial_setup(
        master_hash_file=temp_files["MASTER_HASH_FILE"],
        recovery_hash_file=temp_files["RECOVERY_HASH_FILE"],
        encrypted_key_master_file=temp_files["ENCRYPTED_KEY_MASTER_FILE"],
        encrypted_key_recovery_file=temp_files["ENCRYPTED_KEY_RECOVERY_FILE"],
        credentials_file=temp_files["CREDENTIALS_FILE"]
    )
    assert os.path.exists(temp_files["MASTER_HASH_FILE"])
    assert os.path.exists(temp_files["RECOVERY_HASH_FILE"])

def test_login_master_password(monkeypatch, temp_files):
    password = "test_password"
    ephemeral_key = os.urandom(32)
    
    # Store the master password hash
    store_passlib_hash(password, temp_files["MASTER_HASH_FILE"])
    
    # Encrypt the ephemeral key with the master password
    encrypt_ephemeral_key_with_password(ephemeral_key, password, temp_files["ENCRYPTED_KEY_MASTER_FILE"])
    
    monkeypatch.setattr('getpass.getpass', lambda _: password)
    monkeypatch.setattr('src.password_manager.cli.MASTER_HASH_FILE', temp_files["MASTER_HASH_FILE"])
    monkeypatch.setattr('src.password_manager.cli.ENCRYPTED_KEY_MASTER_FILE', temp_files["ENCRYPTED_KEY_MASTER_FILE"])
    
    decrypted_key = _login_master_password()
    assert decrypted_key == ephemeral_key
