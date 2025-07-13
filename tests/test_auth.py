import pytest
from flask import url_for
from app.models import User


def test_register(client, db):
    """✅ Test user registration route."""
    response = client.post('/auth/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'securePassword1',
        'confirm_password': 'securePassword1'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert (
        b'Registration successful' in response.data or 
        b'Setup Two-Factor Authentication' in response.data
    )

    user = User.query.filter_by(email='new@example.com').first()
    assert user is not None


def test_login(client, test_user):
    """✅ Test login with valid credentials."""
    response = client.post(url_for('auth.login'), data={
        'email': 'test@example.com',
        'password': 'testpassword'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert (
        b'OTP Verification' in response.data or 
        b'Login successful' in response.data
    )


def test_2fa_setup(client, test_user):
    """✅ Test access to 2FA setup page after login."""
    client.post(url_for('auth.login'), data={
        'email': 'test@example.com',
        'password': 'testpassword'
    }, follow_redirects=True)

    response = client.get(url_for('auth.setup_2fa'))
    assert response.status_code == 200
    assert b'Setup Two-Factor Authentication' in response.data


def test_invalid_login(client):
    """✅ Test login with invalid credentials."""
    response = client.post(url_for('auth.login'), data={
        'email': 'wrong@example.com',
        'password': 'wrongpassword'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert (
        b'Invalid email or password' in response.data or 
        b'Login to Your Account' in response.data
    )
