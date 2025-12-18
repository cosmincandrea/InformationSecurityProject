from flask import Blueprint, redirect, url_for

from ..security import get_current_user

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    
    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))

    if user["role"] == "patient":
        return redirect(url_for("patient.patient_dashboard"))
    if user["role"] == "medic":
        return redirect(url_for("medic.medic_dashboard"))
    if user["role"] == "admin":
        return redirect(url_for("admin.admin_dashboard"))

    return "Unknown role", 403
