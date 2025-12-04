import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash

from werkzeug.security import check_password_hash

from ..mock_db import get_user_by_username
from ..security import create_session, clear_session, get_current_user
from ..audit import audit


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = get_user_by_username(username)
        if not user or not check_password_hash(user["password_hash"], password):
            audit(f"Failed login for username={username} from ip={request.remote_addr}",level="WARNING")
            flash("Invalid username or password", "danger")
            return render_template("login.html")

        create_session(user)
        return redirect(url_for("main.index"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    user = get_current_user()
    if user:
        audit(f"User {user["username"]} logged out")
    clear_session()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.app_errorhandler(403)
def forbidden(error):
    return "403 Forbidden: you are not allowed to access this resource.", 403
