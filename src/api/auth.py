from flask import Blueprint, request, jsonify
from marshmallow import Schema, fields, validate

from src.services.auth_service import AuthService

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


class RegisterSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8, max=128))


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True)


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account."""
    schema = RegisterSchema()
    errors = schema.validate(request.json or {})
    if errors:
        return jsonify({"errors": errors}), 400

    data = schema.load(request.json)

    try:
        user = AuthService.register_user(data["email"], data["password"])
        return jsonify({
            "message": "User registered successfully",
            "user_id": user.id,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 409


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate and receive a JWT token."""
    schema = LoginSchema()
    errors = schema.validate(request.json or {})
    if errors:
        return jsonify({"errors": errors}), 400

    data = schema.load(request.json)

    try:
        token = AuthService.authenticate(data["email"], data["password"])
        return jsonify({"token": token}), 200
    except ValueError:
        return jsonify({"error": "Invalid credentials"}), 401
