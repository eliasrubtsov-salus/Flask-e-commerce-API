import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from flask import current_app

from src.models.database import db, User


class AuthService:
    """Handles authentication and password management."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    @staticmethod
    def generate_token(user: User) -> str:
        """Generate a JWT token for a user."""
        payload = {
            "user_id": user.id,
            "email": user.email,
            "role": user.role,
            "exp": datetime.now(timezone.utc) + timedelta(
                minutes=current_app.config["JWT_EXPIRY_MINUTES"]
            ),
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")

    @staticmethod
    def decode_token(token: str) -> dict:
        """Decode and validate a JWT token."""
        return jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])

    @staticmethod
    def register_user(email: str, password: str) -> User:
        """Register a new user."""
        if User.query.filter_by(email=email).first():
            raise ValueError("Email already registered")

        user = User(
            email=email,
            password_hash=AuthService.hash_password(password),
        )
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate(email: str, password: str) -> str:
        """Authenticate a user and return a JWT token."""
        user = User.query.filter_by(email=email, is_active=True).first()
        if not user or not AuthService.verify_password(password, user.password_hash):
            raise ValueError("Invalid credentials")

        return AuthService.generate_token(user)
