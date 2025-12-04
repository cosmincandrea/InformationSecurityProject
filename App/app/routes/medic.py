import logging
from flask import Blueprint, render_template

from ..security import roles_required, get_current_user
from ..crypto_utils import decrypt_value
from .. import mock_db
from ..audit import audit


medic_bp = Blueprint("medic", __name__, url_prefix="/medic")


@medic_bp.route("/")
@roles_required("medic")
def medic_dashboard():
    
    user = get_current_user()

    # Patients assigned to this medic
    patient_ids = {a["patient_id"] for a in mock_db.APPOINTMENTS if a["medic_id"] == user["id"]}
    assigned_patients = []
    for u in mock_db.USERS.values():
        if u["id"] in patient_ids:
            decrypted_personal = {
                field: decrypt_value(value) for field, value in u["personal"].items()
            }
            assigned_patients.append({
                "id": u["id"],
                "username": u["username"],
                "full_name": decrypted_personal["full_name"],
                "email": decrypted_personal["email"],
            })

    # Next appointments = "scheduled" for this medic
    next_appts = [
        a for a in mock_db.APPOINTMENTS
        if a["medic_id"] == user["id"] and a["status"] == "scheduled"
    ]

    audit(f"Medic {user["username"]} accessed medic dashboard")

    return render_template(
        "medic_dashboard.html",
        patients=assigned_patients,
        appointments=next_appts,
    )
