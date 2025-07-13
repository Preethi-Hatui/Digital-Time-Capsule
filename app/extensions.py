# app/extensions.py

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler

# ✅ Initialize Flask extensions
bcrypt = Bcrypt()                   # Password hashing
csrf = CSRFProtect()               # CSRF protection
db = SQLAlchemy()                  # ORM
login_manager = LoginManager()     # User session management
mail = Mail()                      # Email sending
migrate = Migrate()                # Database migrations
scheduler = BackgroundScheduler()  # Background task scheduler (APScheduler)

