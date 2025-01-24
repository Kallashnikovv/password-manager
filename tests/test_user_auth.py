import pytest
from src.password_manager.user_auth import (
    store_passlib_hash,
    verify_passlib_password,
    prompt_for_new_password
)

@pytest.fixture
def temp_hash_file(tmp_path):
    return tmp_path / "temp.hash"

def test_store_and_verify_password(temp_hash_file):
    password = "test_password"
    store_passlib_hash(password, temp_hash_file)
    assert verify_passlib_password(password, temp_hash_file) == True
    assert verify_passlib_password("wrong_password", temp_hash_file) == False

def test_prompt_for_new_password(monkeypatch):
    monkeypatch.setattr('getpass.getpass', lambda _: "test_password")
    assert prompt_for_new_password("test") == "test_password"
