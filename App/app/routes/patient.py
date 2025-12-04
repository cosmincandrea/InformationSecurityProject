import logging
from flask import Blueprint, render_template

from ..security import roles_required, get_current_user
from ..crypto_utils import decrypt_value
from .. import mock_db
from ..audit import audit


patient_bp = Blueprint("patient", __name__, url_prefix="/patient")


@patient_bp.route("/")
@roles_required("patient")
def patient_dashboard():
    """Patient page: personal data + appointment history."""
    user = get_current_user()

    # Decrypt personal data before displaying
    decrypted_personal = {
        field: decrypt_value(value) for field, value in user["personal"].items()
    }

    # Filter appointments for this patient
    patient_appts = [a for a in mock_db.APPOINTMENTS if a["patient_id"] == user["id"]]

    audit(f"Patient { user["username"]} accessed their dashboard")

    return render_template(
        "patient_dashboard.html",
        personal=decrypted_personal,
        appointments=patient_appts,
    )
