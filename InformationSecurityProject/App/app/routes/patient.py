import logging
from flask import Blueprint, render_template, flash
from mysql.connector import Error

from ..security import roles_required, get_current_user
from ..audit import audit
from ..db import get_db_connection 

# import Decryption Logic
from ..crypto_utils import decrypt_value

patient_bp = Blueprint("patient", __name__, url_prefix="/patient")

@patient_bp.route("/")
@roles_required("patient")
def patient_dashboard():
    # patient page: personal data + appointment history
    user = get_current_user()
    patient_id = user["id"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # fetch personal data -- query the DB directly to get the most up-to-date profile info
        user_query = "SELECT username, full_name, email FROM users WHERE id = %s"
        cursor.execute(user_query, (patient_id,))
        personal_data = cursor.fetchone()

        # decrypt personal data
        if personal_data:
            try:
                personal_data['full_name'] = decrypt_value(personal_data['full_name'])
                personal_data['email'] = decrypt_value(personal_data['email'])
            except Exception as e:
                logging.warning(f"Failed to decrypt personal data for patient {patient_id}: {e}")
                audit(f"Failed to decrypt personal data for patient {patient_id}: {e}")
                personal_data['full_name'] = "[Decryption Error]"
                personal_data['email'] = "[Decryption Error]"
 
        # fetch appointments for this patient -- JOIN with the users table again (aliased as 'm') to get the Medic's name
        appt_query = """
            SELECT 
                a.id, 
                a.date, 
                a.status, 
                a.details, 
                m.full_name AS medic_name
            FROM appointments a
            JOIN users m ON a.medic_id = m.id
            WHERE a.patient_id = %s
            ORDER BY a.date DESC
        """
        cursor.execute(appt_query, (patient_id,))
        patient_appts = cursor.fetchall()

        # decrypt Medic Names in Appointment History
        for appt in patient_appts:
            try:
                appt['medic_name'] = decrypt_value(appt['medic_name'])
            except Exception as e:
                # if the medic's name cannot be decrypted, show a fallback
                appt['medic_name'] = "Unknown Medic"

        audit(f"Patient {user['username']} accessed their dashboard")

        return render_template(
            "patient_dashboard.html",
            personal=personal_data,
            appointments=patient_appts,
        )

    except Error as e:
        audit(f"Could not load dashboard data. Database error: {e}")
        # return empty structures to prevent template crashes
        return render_template(
            "patient_dashboard.html", 
            personal={}, 
            appointments=[]
        )
        
    finally:
        # clean up database resources
        if cursor:
            cursor.close()
        if conn:
            conn.close()