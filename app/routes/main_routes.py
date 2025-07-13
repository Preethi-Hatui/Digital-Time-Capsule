from flask import Blueprint, render_template, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from app.models import TimeCapsule
from datetime import datetime, timedelta
from app.extensions import db
import traceback
import pytz

main_bp = Blueprint('main', __name__)
IST = pytz.timezone("Asia/Kolkata")


# ===========================
# 🏠 HOME PAGE (Public)
# ===========================
@main_bp.route('/')
def home():
    return render_template('main/home.html')


# ===========================
# 📊 DASHBOARD (Authenticated)
# ===========================
@main_bp.route('/dashboard')
@login_required
def dashboard():
    try:
        now_ist = datetime.now(IST)
        now_utc = now_ist.astimezone(pytz.utc)
        today_start = now_ist.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)

        # Fetch capsules belonging to the current user
        capsules = TimeCapsule.query.filter_by(user_id=current_user.id).order_by(
            TimeCapsule.unlock_datetime
        ).all()

        updated = False
        for capsule in capsules:
            unlock_time = capsule.unlock_datetime
            if unlock_time.tzinfo is None:
                unlock_time = pytz.utc.localize(unlock_time)

            # Update capsule status if unlocked
            if capsule.status == 'locked' and unlock_time <= now_utc:
                capsule.status = 'unlocked'
                updated = True

            # Assign IST version for template use
            capsule.unlock_time_ist = unlock_time.astimezone(IST)

        if updated:
            db.session.commit()

        # Capsule statistics
        capsule_count = len(capsules)
        pending_count = sum(1 for c in capsules if c.status == 'locked')
        unlocked_today = sum(
            1 for c in capsules
            if c.status == 'unlocked' and today_start <= c.unlock_datetime.astimezone(IST) < today_end
        )

        return render_template(
            'main/dashboard.html',
            capsules=capsules,
            capsule_count=capsule_count,
            pending_count=pending_count,
            unlocked_today=unlocked_today,
            now=now_ist
        )

    except Exception:
        user_id = getattr(current_user, 'id', 'unknown')
        current_app.logger.error(
            f"[Dashboard Error] User ID {user_id}:\n" + traceback.format_exc()
        )
        flash('Dashboard could not be loaded at the moment. Please try again shortly.', 'danger')
        return redirect(url_for('main.home'))
