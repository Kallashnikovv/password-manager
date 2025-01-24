import os
import pytest

@pytest.fixture
def temp_data_folder(tmp_path):
    return tmp_path / "data_store"

def test_data_folder_exists(temp_data_folder):
    os.makedirs(temp_data_folder, exist_ok=True)
    assert os.path.exists(temp_data_folder)
