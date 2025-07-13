from flask import current_app
from app.models import User, TimeCapsule
from app.extensions import db
from datetime import datetime, timedelta


class AdminService:
    @staticmethod
    def get_user_count():
        """Returns the total number of registered users."""
        try:
            return User.query.count()
        except Exception as e:
            current_app.logger.error(f"[AdminService] Error counting users: {e}")
            return 0

    @staticmethod
    def get_capsule_count():
        """Returns the total number of locked capsules."""
        try:
            return TimeCapsule.query.filter_by(status='locked').count()
        except Exception as e:
            current_app.logger.error(f"[AdminService] Error counting locked capsules: {e}")
            return 0

    @staticmethod
    def get_unlocked_capsule_count():
        """Returns the number of capsules unlocked today."""
        try:
            now = datetime.utcnow()
            start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = start_of_day + timedelta(days=1)

            return TimeCapsule.query.filter(
                TimeCapsule.status == 'unlocked',
                TimeCapsule.unlock_datetime >= start_of_day,
                TimeCapsule.unlock_datetime < end_of_day
            ).count()
        except Exception as e:
            current_app.logger.error(f"[AdminService] Error counting unlocked capsules today: {e}")
            return 0

    @staticmethod
    def get_all_users():
        """Fetches all users ordered by registration date (newest first)."""
        try:
            return User.query.order_by(User.created_at.desc()).all()
        except Exception as e:
            current_app.logger.error(f"[AdminService] Error fetching user list: {e}")
            return []

    @staticmethod
    def toggle_user_status(user_id):
        """
        Enables or disables a user account.
        Returns (success: bool, message: str)
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False, "User not found."

            user.is_active = not user.is_active
            db.session.commit()

            status = 'activated' if user.is_active else 'deactivated'
            return True, f"User '{user.username}' has been {status}."
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"[AdminService] Error toggling user status: {e}")
            return False, "Failed to update user status. Please try again."
