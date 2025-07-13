import pytest
from app import create_app
from app.extensions import db as _db
from app.models import User

# ===========================
# Flask App Fixture (Module Scope)
# ===========================
@pytest.fixture(scope='module')
def app():
    """Create a Flask app configured for testing."""
    app = create_app(testing=True)
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost',  # Needed for url_for in tests
    })

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()

# ===========================
# Client Fixture
# ===========================
@pytest.fixture
def client(app):
    """Return a Flask test client."""
    return app.test_client()

# ===========================
# DB Fixture
# ===========================
@pytest.fixture
def db(app):
    """Return the SQLAlchemy DB object."""
    return _db

# ===========================
# Test User Fixture
# ===========================
@pytest.fixture
def test_user(db):
    """Create and return a test user."""
    user = User(username="testuser", email="test@example.com")
    user.set_password("testpassword")
    db.session.add(user)
    db.session.commit()
    return user
