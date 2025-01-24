import os
import pytest
from src.password_manager.credentials import load_credentials, save_credentials

@pytest.fixture
def temp_credentials_file(tmp_path):
    return tmp_path / "credentials.json"

def test_load_and_save_credentials(temp_credentials_file):
    ephemeral_key = os.urandom(32)
    credentials = {
        "example.com": {
            "username": "user",
            "password": "pass"
        }
    }
    save_credentials(credentials, ephemeral_key, temp_credentials_file)
    loaded_credentials = load_credentials(ephemeral_key, temp_credentials_file)
    assert credentials == loaded_credentials
