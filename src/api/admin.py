from flask import Blueprint, jsonify

from src.middleware.auth import require_admin
from src.models.database import User, Order

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/users", methods=["GET"])
@require_admin
def list_users():
    """List all users (admin only)."""
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
    } for u in users])


@admin_bp.route("/stats", methods=["GET"])
@require_admin
def get_stats():
    """Get platform statistics (admin only)."""
    return jsonify({
        "total_users": User.query.count(),
        "total_orders": Order.query.count(),
    })
