import logging
from cryptography.fernet import Fernet

from .config import Config
from .audit import audit



# Get or generate encryption key
if Config.ENCRYPTION_KEY is None:
    # New key on every run
    key = Fernet.generate_key()
    audit("Generated new ENCRYPTION_KEY")
else:
    key = Config.ENCRYPTION_KEY.encode()

fernet = Fernet(key)


def encrypt_value(plaintext: str) -> str:
    
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    
    return fernet.decrypt(ciphertext.encode()).decode()
