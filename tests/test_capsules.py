import pytest
from flask import url_for
from datetime import datetime, timedelta
from io import BytesIO
from app.models import TimeCapsule
from app.extensions import db


def test_create_capsule(client, test_user):
    """✅ Test creating a new time capsule with a file upload."""
    # Login
    client.post(url_for('auth.login'), data={
        'email': 'test@example.com',
        'password': 'testpassword'
    })

    # Create capsule (future unlock time + file + mock OTP)
    response = client.post(url_for('capsule.create_capsule'), data={
        'capsule_name': 'My Test Capsule',
        'unlock_date': (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d'),
        'unlock_time': '12:00',
        'file': (BytesIO(b'Test file content'), 'test.txt'),
        'otp': '123456'  # Simulated OTP
    }, content_type='multipart/form-data', follow_redirects=True)

    assert response.status_code == 200
    assert b'Time capsule created successfully' in response.data

    capsule = TimeCapsule.query.filter_by(capsule_name='My Test Capsule').first()
    assert capsule is not None


def test_view_capsules(client, test_user, test_capsule):
    """✅ Test viewing all capsules for a logged-in user."""
    # Login
    client.post(url_for('auth.login'), data={
        'email': 'test@example.com',
        'password': 'testpassword'
    })

    response = client.get(url_for('capsule.view_capsules'))
    assert response.status_code == 200
    assert b'Test Capsule' in response.data


def test_unlock_capsule(client, test_user, test_capsule):
    """✅ Test unlocking a capsule after unlock datetime has passed."""
    # Login
    client.post(url_for('auth.login'), data={
        'email': 'test@example.com',
        'password': 'testpassword'
    })

    # Set unlock datetime to the past
    test_capsule.unlock_datetime = datetime.utcnow() - timedelta(minutes=5)
    db.session.commit()

    # Simulate unlock with OTP
    response = client.post(
        url_for('capsule.unlock_capsule', capsule_id=test_capsule.id),
        data={'otp': '123456'},  # Simulated OTP
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b'Capsule unlocked successfully' in response.data

    db.session.refresh(test_capsule)
    assert test_capsule.status == 'unlocked'
