import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
import mysql.connector
from mysql.connector import Error

from ..security import roles_required, get_current_user
from ..audit import audit
from ..db import get_db_connection 

# import encryption and decryption logic
from ..crypto_utils import encrypt_value, decrypt_value

medic_bp = Blueprint("medic", __name__, url_prefix="/medic")

def fetch_assigned_patients(medic_id):
    # fetch patients who have had appointments with this medic -- decrypts personal data (Name/Email) before returning
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # DISTINCT ensures query don't list the same patient multiple times
        query = """
            SELECT DISTINCT u.id, u.username, u.full_name, u.email
            FROM users u
            JOIN appointments a ON u.id = a.patient_id
            WHERE a.medic_id = %s AND u.role = 'patient'
        """ 
        cursor.execute(query, (medic_id,))
        patients = cursor.fetchall()

        # decryption loop (Patient Data)
        for p in patients:
            try:
                p['full_name'] = decrypt_value(p['full_name'])
                p['email'] = decrypt_value(p['email'])
            except Exception as e:
                audit(f"Failed to decrypt patient {p['id']}: {e}")
                p['full_name'] = "[Decryption Error]"
                p['email'] = "[Decryption Error]"

        return patients
    finally:
        cursor.close()
        conn.close()

def fetch_appointments(medic_id, status=None):
    # fetch appointments for the medic, optionally filtered by status -- decrypts the associated patient name AND appointment details
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if status:
            query = """
                SELECT a.*, u.full_name as patient_name 
                FROM appointments a
                JOIN users u ON a.patient_id = u.id
                WHERE a.medic_id = %s AND a.status = %s
                ORDER BY a.date ASC
            """
            cursor.execute(query, (medic_id, status))
        else:
            query = """
                SELECT a.*, u.full_name as patient_name 
                FROM appointments a
                JOIN users u ON a.patient_id = u.id
                WHERE a.medic_id = %s
                ORDER BY a.date ASC
            """
            cursor.execute(query, (medic_id,))
        
        appointments = cursor.fetchall()

        # decryption loop
        for a in appointments:
            # decrypt patient name
            try:
                a['patient_name'] = decrypt_value(a['patient_name'])
            except Exception as e:
                a['patient_name'] = "Unknown (Decryption Error)"

            # decrypt details
            try:
                if a['details']: 
                    a['details'] = decrypt_value(a['details'])
            except Exception as e:
                # fallback if decryption fails or data wasn't encrypted
                audit(f"Failed to decrypt details for appt {a['id']}: {e}")
                a['details'] = "[Encrypted Content]"

        return appointments
    finally:
        cursor.close()
        conn.close()

@medic_bp.route("/")
@roles_required("medic")
def medic_dashboard():
    user = get_current_user()
    medic_id = user["id"]

    try:
        # get patients and scheduled appointments
        assigned_patients = fetch_assigned_patients(medic_id)
        next_appts = fetch_appointments(medic_id, status="scheduled")
        
        audit(f"Medic {user['username']} accessed medic dashboard")
        
        return render_template(
            "medic_dashboard.html",
            patients=assigned_patients,
            appointments=next_appts,
        )
    except Error as e:
        audit(f"Database error: {e}", "danger")
        return render_template("medic_dashboard.html", patients=[], appointments=[])


@medic_bp.route("/appointment/create", methods=["POST"])
@roles_required("medic")
def create_appointment():
    # create encrypt 'details' before saving
    user = get_current_user()
    medic_id = user["id"]
    
    patient_id = request.form.get("patient_id")
    date_str = request.form.get("date")
    details = request.form.get("details")
    
    if not patient_id or not date_str:
        audit("Patient and Date are required.", "warning")
        return redirect(url_for("medic.medic_dashboard"))

    try:
        enc_details = encrypt_value(details)
    except Exception as e:
        audit(f"Encryption failed: {e}", "danger")
        return redirect(url_for("medic.medic_dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # status and date are inserted as plain text
        query = """
            INSERT INTO appointments (patient_id, medic_id, date, status, details)
            VALUES (%s, %s, %s, 'scheduled', %s)
        """
        cursor.execute(query, (patient_id, medic_id, date_str, enc_details))
        conn.commit()
        
        audit(f"Medic {user['username']} created appointment for patient ID {patient_id}")
        flash("Appointment created successfully.", "success")
    except Error as e:
        flash(f"Error creating appointment: {e}", "danger")
        audit(f"Error creating appointment: {e}")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("medic.medic_dashboard"))


@medic_bp.route("/appointment/update/<int:appt_id>", methods=["POST"])
@roles_required("medic")
def update_appointment(appt_id):
    # update encrypt 'details' before updating
    user = get_current_user()
    
    new_status = request.form.get("status")
    new_details = request.form.get("details")
    
    try:
        enc_details = encrypt_value(new_details)
    except Exception as e:
        audit(f"Encryption failed: {e}")
        return redirect(url_for("medic.medic_dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # security check
        check_query = "SELECT id FROM appointments WHERE id = %s AND medic_id = %s"
        cursor.execute(check_query, (appt_id, user["id"]))
        if not cursor.fetchone():
            flash("Unauthorized: You cannot edit this appointment.", "danger")
            return redirect(url_for("medic.medic_dashboard"))

        # ppdate status (plain) and details (encrypted)
        update_query = """
            UPDATE appointments 
            SET status = %s, details = %s 
            WHERE id = %s
        """
        cursor.execute(update_query, (new_status, enc_details, appt_id))
        conn.commit()
        
        audit(f"Medic {user['username']} updated appointment ID {appt_id}")
        flash("Appointment updated.", "success")
    except Error as e:
        flash(f"Error updating appointment: {e}", "danger")
        audit(f"Error updating appointment: {e}")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("medic.medic_dashboard"))


@medic_bp.route("/appointment/delete/<int:appt_id>", methods=["POST"])
@roles_required("medic")
def delete_appointment(appt_id):
    # delete remove an appointment
    user = get_current_user()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # security check
        check_query = "SELECT id FROM appointments WHERE id = %s AND medic_id = %s"
        cursor.execute(check_query, (appt_id, user["id"]))
        if not cursor.fetchone():
            flash("Unauthorized: You cannot delete this appointment.", "danger")
            return redirect(url_for("medic.medic_dashboard"))

        delete_query = "DELETE FROM appointments WHERE id = %s"
        cursor.execute(delete_query, (appt_id,))
        conn.commit()
        
        audit(f"Medic {user['username']} deleted appointment ID {appt_id}")
        flash("Appointment deleted.", "success")
    except Error as e:
        flash(f"Error deleting appointment: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("medic.medic_dashboard"))