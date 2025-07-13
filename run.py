# run.py

from flask.cli import FlaskGroup
from app import create_app
from app.extensions import db

# ✅ Initialize app via factory pattern
app = create_app()

# ✅ Set up Flask CLI group
cli = FlaskGroup(app)

# ✅ Custom command to create DB
@cli.command("create-db")
def create_db():
    """Create all database tables."""
    with app.app_context():
        db.create_all()
        print("✔ Database tables created successfully.")

# ✅ Entry point
if __name__ == '__main__':
    cli()
