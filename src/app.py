from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from src.config.settings import Config
from src.models.database import db
from src.api import auth_bp, orders_bp, admin_bp
from src.middleware.error_handler import register_error_handlers


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)

    CORS(app, origins=app.config["CORS_ORIGINS"])

    Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[app.config["RATE_LIMIT_DEFAULT"]],
    )

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(admin_bp)

    # Register error handlers
    register_error_handlers(app)

    return app
