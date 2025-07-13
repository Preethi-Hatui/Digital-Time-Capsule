import pytest
from flask import url_for
from datetime import datetime
from app.models import User

# =========================================
# ✅ Test: Home page loads
# =========================================
def test_home_page(client):
    response = client.get(url_for('main.home'))
    assert response.status_code == 200
    assert b'Digital Time Capsule' in response.data


# =========================================
# ✅ Test: Redirect unauthenticated dashboard access
# =========================================
def test_dashboard_access_unauthenticated(client):
    response = client.get(url_for('main.dashboard'), follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data or b'login' in response.data


# =========================================
# ✅ Test: Authenticated dashboard access after OTP
# =========================================
def test_dashboard_access_authenticated(client, test_user):
    # Step 1: Attempt login
    login_response = client.post(url_for('auth.login'), data={
        'email': test_user.email,
        'password': 'testpassword'  # Must match test_user fixture
    }, follow_redirects=True)

    assert login_response.status_code == 200
    assert b'OTP' in login_response.data or b'Enter OTP' in login_response.data

    # Step 2: Simulate OTP verified session
    with client.session_transaction() as sess:
        sess['user_id'] = test_user.id
        sess['authenticated'] = True
        sess['login_time'] = datetime.utcnow().timestamp()

    # Step 3: Access dashboard
    dashboard_response = client.get(url_for('main.dashboard'))
    assert dashboard_response.status_code == 200
    assert b'Dashboard' in dashboard_response.data or b'Welcome' in dashboard_response.data
