# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from argon2 import PasswordHasher  # IMPORT INI!

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

# Argon2 hasher
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)