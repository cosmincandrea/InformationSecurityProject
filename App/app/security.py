import logging
import secrets
from functools import wraps

from flask import session, redirect, url_for, flash, abort, request

from .mock_db import get_user_by_username
from .audit import audit




# In a real system server-side store
ACTIVE_TOKENS = {}


def create_session(user: dict):
    
    token = secrets.token_urlsafe(32)
    ACTIVE_TOKENS[user["username"]] = token

    session["username"] = user["username"]
    session["role"] = user["role"]
    session["token"] = token

    audit(f"User {user["username"]} logged with token={token}")


def clear_session():
    
    username = session.get("username")
    if username:
        ACTIVE_TOKENS.pop(username, None)
        audit(f"Session cleared for {username}")
    session.clear()


def get_current_user():
    
    username = session.get("username")
    token = session.get("token")

    if not username or not token:
        return None

    expected_token = ACTIVE_TOKENS.get(username)
    if expected_token is None or expected_token != token:
        audit(f"Invalid or expired token for {username}", level="WARNING")
        return None

    return get_user_by_username(username)


def login_required(view_func):
    

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)

    return wrapper


def roles_required(*roles):

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth.login"))
            if user["role"] not in roles:
                audit(f"Unauthorized access attempt by user={user["username"]} role={user["role"]} to {request.path}",level="WARNING")
                abort(403)
            return view_func(*args, **kwargs)

        return wrapper

    return decorator
