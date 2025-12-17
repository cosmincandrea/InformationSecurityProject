import json
import logging
import os
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from mysql.connector import Error
from werkzeug.security import generate_password_hash

# import your security/audit helpers
from ..security import roles_required, get_current_user
from ..audit import audit
from ..config import Config

# import the DB connection helper
from ..db import get_db_connection

# import encryption/decryption functions
from ..crypto_utils import encrypt_value, decrypt_value

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

def count_appointments_per_month_sql():
    # generates the report using SQL aggregation
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT DATE_FORMAT(date, '%Y-%m') as month, COUNT(*) as count 
            FROM appointments 
            GROUP BY month 
            ORDER BY month DESC
        """
        cursor.execute(query)
        results = cursor.fetchall()
        return {row['month']: row['count'] for row in results}
    finally:
        cursor.close()
        conn.close()

def perform_backup_sql():
    # dumps SQL tables to a JSON file (Data remains ENCRYPTED/HASHED)
    backup_dir = Config.BACKUP_DIR
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(backup_dir, f"backup_{timestamp}.json")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        cursor.execute("SELECT * FROM appointments")
        appointments = cursor.fetchall()
        
        data = {
            "users": users,
            "appointments": appointments,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
            
        return path
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/")
@roles_required("admin")
def admin_dashboard():
    # get operation: decrypts sensitive data (Name/Email) for display
    user = get_current_user()
    
    # get report
    report = count_appointments_per_month_sql()
    
    # get all users
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    users_list = []
    try:
        cursor.execute("SELECT * FROM users ORDER BY id ASC")
        raw_users = cursor.fetchall()
        
        # decryption logic for display
        for u in raw_users:
            try:
                u['full_name'] = decrypt_value(u['full_name'])
                u['email'] = decrypt_value(u['email'])
            except Exception as e:
                u['full_name'] = "[Decryption Error]"
                u['email'] = "[Decryption Error]"
            
            users_list.append(u)

    except Error as e:
        audit(f"Error fetching users: {e}")
    finally:
        cursor.close()
        conn.close()

    audit(f"Admin {user['username']} accessed admin dashboard")
    
    return render_template(
        "admin_dashboard.html", 
        report=report, 
        users=users_list
    )


@admin_bp.route("/user/create", methods=["POST"])
@roles_required("admin")
def create_user():
    # create hashes oassword + encrypts PII before inserting
    username = request.form.get("username")
    password = request.form.get("password") 
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    role = request.form.get("role")

    if not all([username, password, full_name, email, role]):
        flash("All fields are required.", "warning")
        return redirect(url_for("admin.admin_dashboard"))

    try:
        # encrypt personal data
        enc_full_name = encrypt_value(full_name)
        enc_email = encrypt_value(email)
        
        # hash password (irreversible - Standard Security Practice)
        hashed_password = generate_password_hash(password)
        
    except Exception as e:
        audit(f"Security processing failed: {e}")
        return redirect(url_for("admin.admin_dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            INSERT INTO users (username, password, full_name, email, role)
            VALUES (%s, %s, %s, %s, %s)
        """
        # Insert Hashed Password and Encrypted Fields
        cursor.execute(query, (username, hashed_password, enc_full_name, enc_email, role))
        conn.commit()
        
        audit(f"Admin created user: {username} (Role: {role})")
        flash(f"User {username} created successfully.", "success")
    except Error as e:
        flash(f"Error creating user: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/user/update/<int:user_id>", methods=["POST"])
@roles_required("admin")
def update_user(user_id):
    # update encrypts data before updating DB
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    role = request.form.get("role")
    
    try:
        enc_full_name = encrypt_value(full_name)
        enc_email = encrypt_value(email)
    except Exception as e:
        audit(f"Encryption failed: {e}")
        return redirect(url_for("admin.admin_dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            UPDATE users 
            SET full_name = %s, email = %s, role = %s 
            WHERE id = %s
        """
        cursor.execute(query, (enc_full_name, enc_email, role, user_id))
        conn.commit()
        
        audit(f"Admin updated user ID: {user_id}")
        flash("User updated successfully.", "success")
    except Error as e:
        audit(f"Error updating user: {e}")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/user/delete/<int:user_id>", methods=["POST"])
@roles_required("admin")
def delete_user(user_id):
    # delete remove a user
    current_user = get_current_user()
    if user_id == current_user["id"]:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        conn.commit()
        
        audit(f"Admin deleted user ID: {user_id}")
        flash("User deleted successfully.", "success")
    except Error as e:
        flash(f"Error deleting user: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin.admin_dashboard"))

@admin_bp.route("/backup")
@roles_required("admin")
def admin_backup():
    try:
        path = perform_backup_sql()
        audit(f"Backup Created at {path}")
        flash(f"Backup created successfully at {path}", "success")
    except Exception as e:
        flash(f"Backup failed: {e}", "danger")
        logging.error(f"Backup failed: {e}")
        
    return redirect(url_for("admin.admin_dashboard"))