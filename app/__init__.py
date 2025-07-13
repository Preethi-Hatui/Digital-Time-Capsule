import os
from datetime import datetime, timedelta
from flask import Flask
from dotenv import load_dotenv

from app.extensions import db, bcrypt, login_manager, migrate, mail, csrf, scheduler
from app.config import Config, TestingConfig

def create_app(testing=False):
    # 🔐 Load environment variables from .env
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object(TestingConfig if testing else Config)

    # 🔒 Session settings
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True

    # 🔌 Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    csrf.init_app(app)

    # 🔐 Login manager configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # 🧠 User loader
    from app.models import User, TimeCapsule, OTPAttempt

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # 🔁 Import scheduler job (before blueprint)
    from app.routes.capsule_routes import unlock_expired_capsules

    # 🧩 Register blueprints
    from app.routes.auth_routes import auth_bp
    from app.routes.capsule_routes import capsule_bp
    from app.routes.main_routes import main_bp
    from app.routes.admin_routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(capsule_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    # ⏰ Add UTC timestamp to templates
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    # 📁 Ensure essential directories exist
    required_dirs = [
        app.config.get('TEMP_FOLDER', 'app/temp'),
        os.path.join('app', 'static', 'uploads')
    ]
    for directory in required_dirs:
        try:
            os.makedirs(directory, exist_ok=True)
            app.logger.info(f"[Startup] Ensured directory exists: {directory}")
        except OSError as e:
            app.logger.warning(f"[Startup] Could not create directory '{directory}': {e}")

    # 🔄 Start scheduler in production/development only
    with app.app_context():
        if not testing:
            try:
                if not scheduler.running:
                    scheduler.add_job(
                        id='unlock_expired_capsules',
                        func=unlock_expired_capsules,
                        trigger='interval',
                        seconds=5,  # ✅ Now runs every 5 seconds,
                        replace_existing=True
                    )
                    scheduler.start()
                    app.logger.info("🔁 Scheduler started successfully.")
            except Exception as e:
                app.logger.error(f"❌ Failed to start scheduler: {str(e)}")

    return app
