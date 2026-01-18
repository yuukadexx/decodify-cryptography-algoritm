# routes/main.py
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app import db

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    from models.cipher_models import CipherUsage, UserProgress
    
    # Get user progress
    progress = UserProgress.query.filter_by(user_id=current_user.id).first()
    
    # Calculate completed ciphers
    cipher_usages = CipherUsage.query.filter_by(user_id=current_user.id).count()
    total_ciphers = 15  # Total ciphers available
    
    return render_template('dashboard.html', 
                         username=current_user.username,
                         user_level=progress.level,
                         user_xp=progress.xp,
                         completed_ciphers=cipher_usages,
                         total_ciphers=total_ciphers,
                         streak_days=progress.current_streak)