# app/routes/admin_routes.py

from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import User, TimeCapsule
from app.services.admin_service import AdminService
import traceback
from flask import current_app

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# ===============================
# 🔐 Admin Access Check
# ===============================
def admin_required():
    if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
        flash('Unauthorized access. Admins only.', 'danger')
        return False
    return True

# ===============================
# 📊 Admin Dashboard
# ===============================
@admin_bp.route('/dashboard')
@login_required
def dashboard():
    if not admin_required():
        return redirect(url_for('main.home'))

    try:
        user_count = AdminService.get_user_count()
        capsule_count = AdminService.get_capsule_count()
        unlocked_count = AdminService.get_unlocked_capsule_count()

        return render_template(
            'admin/dashboard.html',
            user_count=user_count,
            active_capsules=capsule_count,
            unlocked_today=unlocked_count
        )
    except Exception:
        current_app.logger.error("Admin dashboard error:\n" + traceback.format_exc())
        flash('Error loading admin dashboard.', 'danger')
        return redirect(url_for('main.home'))

# ===============================
# 👥 User Management
# ===============================
@admin_bp.route('/users')
@login_required
def user_management():
    if not admin_required():
        return redirect(url_for('main.home'))

    try:
        users = AdminService.get_all_users()
        return render_template('admin/users.html', users=users)
    except Exception:
        current_app.logger.error("User management error:\n" + traceback.format_exc())
        flash('Failed to load user list.', 'danger')
        return redirect(url_for('admin.dashboard'))

# ===============================
# 🚫 Toggle User Status (Active/Inactive)
# ===============================
@admin_bp.route('/user/<int:user_id>/toggle')
@login_required
def toggle_user(user_id):
    if not admin_required():
        return redirect(url_for('main.home'))

    try:
        success, message = AdminService.toggle_user_status(user_id)
        flash(message, 'success' if success else 'danger')
    except Exception:
        current_app.logger.error("Toggle user error:\n" + traceback.format_exc())
        flash("Something went wrong while updating user status.", "danger")

    return redirect(url_for('admin.user_management'))
