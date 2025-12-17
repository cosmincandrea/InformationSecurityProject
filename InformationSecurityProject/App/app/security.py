import logging
import secrets
from functools import wraps
from flask import session, redirect, url_for, flash, abort, request
from mysql.connector import Error

from .audit import audit
# import DB connection helper
from .db import get_db_connection

# keep active tokens in memory for this simple single-instance app
ACTIVE_TOKENS = {}

def get_user_by_username_sql(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # we select specific fields to avoid leaking sensitive info unnecessarily
        query = "SELECT id, username, role, full_name, email, password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        return user
    except Error as e:
        logging.error(f"Database error fetching user {username}: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def create_session(user: dict):
    # generates a secure token, maps it to the user, and sets the Flask session
    token = secrets.token_urlsafe(32)
    ACTIVE_TOKENS[user["username"]] = token

    session["username"] = user["username"]
    session["role"] = user["role"]
    session["token"] = token

    audit(f"User {user['username']} logged in with token={token}")

def clear_session():
    # invalidates the server-side token and clears the client-side session
    username = session.get("username")
    if username:
        ACTIVE_TOKENS.pop(username, None)
        audit(f"Session cleared for {username}")
    session.clear()

def get_current_user():
    # validates the session token and fetches the fresh user object from DB - returns None if session is invalid or user doesn't exist
    username = session.get("username")
    token = session.get("token")

    if not username or not token:
        return None

    # verify token matches active server-side token (Prevents Session Hijacking via old tokens)
    expected_token = ACTIVE_TOKENS.get(username)
    if expected_token is None or expected_token != token:
        audit(f"Invalid or expired token for {username}", level="WARNING")
        return None

    # fetch fresh user data from SQL (instead of mock_db)
    return get_user_by_username_sql(username)

def login_required(view_func):
    # decorator to ensure a user is logged in
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please log in to access this page.", "warning")
            audit("Unauthorized access prevented - a not logged in user tried to access the login page.")
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)
    return wrapper

def roles_required(*roles):
    # decorator to ensure logged-in user has a specific role  eg. usage: @roles_required('admin', 'medic')
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                flash("Please log in to access this page.", "warning")
                audit("Unauthorized access prevented - a not logged in user tried to access the login page.")
                return redirect(url_for("auth.login"))
            
            if user["role"] not in roles:
                audit(
                    f"Unauthorized access attempt by user={user['username']} role={user['role']} to {request.path}",
                    level="WARNING"
                )
                abort(403) # Forbidden
            
            return view_func(*args, **kwargs)
        return wrapper
    return decorator