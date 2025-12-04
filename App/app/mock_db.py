import logging
from werkzeug.security import generate_password_hash

from .crypto_utils import encrypt_value
from .audit import audit


# In the future this will be replaced by actual DB queries.
PLAIN_USERS = [
    {
        "id": 1,
        "username": "alice_patient",
        "password": "patient123",
        "role": "patient",
        "full_name": "Alice Patient",
        "email": "alice@example.com",
    },
    {
        "id": 2,
        "username": "dr_bob",
        "password": "medic123",
        "role": "medic",
        "full_name": "Dr. Bob Medic",
        "email": "bob.medic@example.com",
    },
    {
        "id": 3,
        "username": "carol_admin",
        "password": "admin123",
        "role": "admin",
        "full_name": "Carol Admin",
        "email": "carol.admin@example.com",
    },
]

PLAIN_APPOINTMENTS = [
    {"id": 1, "patient_id": 1, "medic_id": 2, "date": "2025-01-10", "status": "completed"},
    {"id": 2, "patient_id": 1, "medic_id": 2, "date": "2025-02-01", "status": "completed"},
    {"id": 3, "patient_id": 1, "medic_id": 2, "date": "2025-03-15", "status": "scheduled"},
    {"id": 4, "patient_id": 1, "medic_id": 2, "date": "2025-03-20", "status": "scheduled"},
]

USERS = {}        
APPOINTMENTS = [] 


def initialize_mock_db():

    global USERS, APPOINTMENTS
    USERS = {}
    for u in PLAIN_USERS:
        encrypted_personal = {
            "full_name": encrypt_value(u["full_name"]),
            "email": encrypt_value(u["email"]),
        }

        USERS[u["username"]] = {
            "id": u["id"],
            "username": u["username"],
            "password_hash": generate_password_hash(u["password"]),
            "role": u["role"],
            "personal": encrypted_personal,
        }

        # Log encrypted data to show that it is not stored in clear text
        audit(f"Encrypted personal data for {u['username']}: {encrypted_personal}")

    APPOINTMENTS = PLAIN_APPOINTMENTS.copy()


def get_user_by_username(username: str):
    return USERS.get(username)
