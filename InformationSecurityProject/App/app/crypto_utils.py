import logging
import json
import os
from cryptography.fernet import Fernet

from .audit import audit

def load_config():

    # load config from config.json.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'config.json')
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning("config.json not found, using empty defaults.")
        audit("config.json not found, using empty defaults.")
        return {}

# load the JSON data
_config_data = load_config()

# try fetching from environment (Most Secure)
# try fetching from JSON config
# if both are missing/null, generate a new key
_env_key = os.environ.get("ENCRYPTION_KEY")
_json_key = _config_data.get("ENCRYPTION_KEY")

if _env_key:
    key = _env_key.encode()
elif _json_key:
    key = _json_key.encode()
else:
    # no key found in Env or JSON ----> generate a fresh one
    key = Fernet.generate_key()
    audit(f"Generated new ENCRYPTION_KEY {key}")
print(key)

fernet = Fernet(key)

def encrypt_value(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt_value(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()