import logging
from flask import Flask

from .config import Config
from .mock_db import initialize_mock_db
from .routes.auth import auth_bp
from .routes.main import main_bp
from .routes.patient import patient_bp
from .routes.medic import medic_bp
from .routes.admin import admin_bp


def create_app():
    """Application factory: creates and configures the Flask app."""
    app = Flask(__name__, template_folder="templates")
    app.config.from_object(Config)

    # Basic logging configuration (this acts as our audit log)
    """logging.basicConfig(
        level=logging.ERROR,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )"""

    # Initialize our mock "database" (encrypts personal data)
    initialize_mock_db()

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(medic_bp)
    app.register_blueprint(admin_bp)

    return app
