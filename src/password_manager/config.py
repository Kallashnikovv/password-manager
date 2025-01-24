import os

# Define the folder to store all data files
DATA_FOLDER = "data_store"

# Ensure the folder exists at runtime
if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER, exist_ok=True)

# Each file path within that folder
MASTER_HASH_FILE          = os.path.join(DATA_FOLDER, 'master.hash')
RECOVERY_HASH_FILE        = os.path.join(DATA_FOLDER, 'recovery.hash')
ENCRYPTED_KEY_MASTER_FILE = os.path.join(DATA_FOLDER, 'encrypted_key_master.bin')
ENCRYPTED_KEY_RECOVERY_FILE = os.path.join(DATA_FOLDER, 'encrypted_key_recovery.bin')
CREDENTIALS_FILE          = os.path.join(DATA_FOLDER, 'credentials.json')

# Number of PBKDF2 iterations for key derivation
KDF_ITERATIONS = 100_000
