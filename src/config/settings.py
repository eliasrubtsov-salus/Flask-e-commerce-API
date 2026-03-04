import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""

    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET = os.environ.get("JWT_SECRET")
    JWT_EXPIRY_MINUTES = int(os.environ.get("JWT_EXPIRY_MINUTES", "30"))

    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://app.example.com").split(",")

    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "100/hour")

    PAYMENT_API_URL = os.environ.get("PAYMENT_API_URL")
    PAYMENT_API_SECRET = os.environ.get("PAYMENT_API_SECRET")

    DEBUG = False
