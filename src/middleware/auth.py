from functools import wraps
from flask import request, jsonify, g

from src.services.auth_service import AuthService
from src.models.database import User


def require_auth(f):
    """Middleware to require JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            payload = AuthService.decode_token(token)
            user = User.query.get(payload["user_id"])
            if not user or not user.is_active:
                return jsonify({"error": "Invalid or expired token"}), 401
            g.current_user = user
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Middleware to require admin role."""
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if g.current_user.role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated
