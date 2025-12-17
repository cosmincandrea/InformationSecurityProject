import logging
import re
from flask import Blueprint, render_template, request, redirect, url_for, flash
import mysql.connector
from mysql.connector import Error

# import hashing verification
from werkzeug.security import check_password_hash

# import decryption logic
from ..crypto_utils import decrypt_value

from ..security import create_session, clear_session, get_current_user
from ..audit import audit
from ..db import get_db_connection 

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # input validation : allowed: a-z (lower), A-Z (upper), 0-9 (digits), _ (underscore)
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            flash("Invalid username format. Only letters, digits, and underscores allowed.", "warning")
            audit(f"Invalid username format attempt: {username}")
            return render_template("login.html")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # fetch user from MySQL
            query = "SELECT * FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            user = cursor.fetchone()

            # verify credentials
            authenticated = False
            
            if user:
                # assume the database now contains HASHED passwords (created by Admin)
                if user["password"] and check_password_hash(user["password"], password):
                    authenticated = True
                
            if not authenticated:
                audit(f"Failed login for username={username} from ip={request.remote_addr}")
                flash("Invalid username or password", "danger")
                return render_template("login.html")

            # decrypt PII for session
            try:
                user["full_name"] = decrypt_value(user["full_name"])
                user["email"] = decrypt_value(user["email"])
            except Exception as e:
                logging.warning(f"Decryption failed during login for {username}: {e}")
                audit(f"Decryption failed during login for {username}: {e}")

            # login success
            create_session(user)
            
            audit(f"User {user['username']} logged in successfully")
            
            # redirect based on role
            if user["role"] == "medic":
                return redirect(url_for("medic.medic_dashboard"))
            elif user["role"] == "patient":
                return redirect(url_for("patient.patient_dashboard"))
            elif user["role"] == "admin":
                return redirect(url_for("admin.admin_dashboard"))
            
            return redirect(url_for("main.index"))

        except Error as e:
            audit(f"Database error during login: {e}")
            flash("System error. Please try again later.", "danger")
            return render_template("login.html")
        
        finally:
            cursor.close()
            conn.close()

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    user = get_current_user()
    if user:
        audit(f"User {user['username']} logged out")
    
    clear_session()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.app_errorhandler(403)
def forbidden(error):
    return "403 Forbidden: you are not allowed to access this resource.", 403