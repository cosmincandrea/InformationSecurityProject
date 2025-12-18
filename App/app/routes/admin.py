import json
import logging
import os
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, flash

from ..security import roles_required, get_current_user
from .. import mock_db
from ..config import Config
from ..audit import audit


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def count_appointments_per_month():
    
    counts = {}
    for a in mock_db.APPOINTMENTS:
        month = a["date"][:7]  # 'YYYY-MM'
        counts[month] = counts.get(month, 0) + 1
    return counts


def perform_backup():
    
    backup_dir = Config.BACKUP_DIR
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(backup_dir, f"backup_{timestamp}.json")

    data = {
        "users": mock_db.USERS,
        "appointments": mock_db.APPOINTMENTS,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    audit(f"Backup created at {path}")
    return path


@admin_bp.route("/")
@roles_required("admin")
def admin_dashboard():
    user = get_current_user()
    report = count_appointments_per_month()
    audit("Admin %s accessed admin dashboard", user["username"])
    return render_template("admin_dashboard.html", report=report)


@admin_bp.route("/backup")
@roles_required("admin")
def admin_backup():
    path = perform_backup()
    audit("Backup Created")
    flash(f"Backup created at {path}", "success")
    return redirect(url_for("admin.admin_dashboard"))
