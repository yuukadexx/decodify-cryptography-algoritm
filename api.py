# app.py - VERSI YANG SUDAH DIPISAH
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
import os
import secrets
import json
import random
import re
from datetime import datetime, date, timedelta
from collections import Counter

# Import models yang sudah dipisah
from models import db, User, UserActivity, UserProgress, Achievement, UserAchievement, CipherUsage, QuizQuestion, QuizAttempt, Challenge, ChallengeAttempt, GlossaryTerm, GlossaryCategory, UserBookmark, SearchHistory

# =============== INISIALISASI APLIKASI ===============
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# Inisialisasi database dengan models yang sudah dipisah
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Anda harus login terlebih dahulu untuk mengakses halaman ini.'
login_manager.login_message_category = 'warning'

# Argon2 hasher 
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# =============== UTILITAS ===============
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def secure_logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Anda sudah logout.', 'info')
            return redirect(url_for('index'))
        
        if request.method != 'POST':
            flash('Gunakan tombol logout (POST).', 'warning')
            return redirect(url_for('dashboard'))
        
        token = request.form.get('token')
        if not token or token != session.get('logout_token'):
            flash('Akses tidak valid. Gunakan tombol logout yang disediakan.', 'danger')
            return redirect(url_for('dashboard'))
        
        session.pop('logout_token', None)
        return f(*args, **kwargs)
    return decorated_function

# =============== CIPHER UTILITIES ===============
def caesar_encrypt(text, shift):
    """Enkripsi teks menggunakan Caesar Cipher"""
    result = ""
    shift = shift % 26
    
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26
            result += chr(base + shifted)
        else:
            result += char
    
    return result

def caesar_decrypt(text, shift):
    """Dekripsi teks yang dienkripsi dengan Caesar Cipher"""
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(plaintext, key):
    """Encrypt plaintext using Vigenere cipher"""
    result = []
    key = key.upper()
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            result.append(encrypted_char)
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

def vigenere_decrypt(ciphertext, key):
    """Decrypt ciphertext using Vigenere cipher"""
    result = []
    key = key.upper()
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            result.append(decrypted_char)
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

# ... (semua cipher utility functions tetap di sini)
# (Karena functions ini pendek dan berkaitan dengan logic aplikasi, biarkan di app.py)

# =============== FUNGSI HELPER ===============
def get_user_progress(user_id):
    """Get or create user progress"""
    progress = UserProgress.query.filter_by(user_id=user_id).first()
    if not progress:
        progress = UserProgress(user_id=user_id)
        db.session.add(progress)
        db.session.commit()
    return progress

def update_user_xp(user_id, xp_earned, activity_type="quiz"):
    """Update user XP and check level up"""
    progress = get_user_progress(user_id)
    
    old_level = progress.level
    progress.xp += xp_earned
    
    new_level = (progress.xp // 100) + 1
    if new_level > old_level:
        progress.level = new_level
        activity = UserActivity(
            user_id=user_id,
            activity_type='level_up',
            description=f'Level up dari {old_level} ke {new_level}!',
            xp_gained=xp_earned
        )
        db.session.add(activity)
    
    activity = UserActivity(
        user_id=user_id,
        activity_type=activity_type,
        description=f'Mendapatkan {xp_earned} XP dari {activity_type}',
        xp_gained=xp_earned
    )
    db.session.add(activity)
    
    today = date.today()
    if progress.last_active_date != today:
        if (today - progress.last_active_date).days == 1:
            progress.current_streak += 1
        else:
            progress.current_streak = 1
        progress.last_active_date = today
    
    db.session.commit()
    return progress

def log_cipher_usage(user_id, cipher_name):
    """Log cipher usage for statistics"""
    usage = CipherUsage.query.filter_by(user_id=user_id, cipher_name=cipher_name).first()
    if usage:
        usage.usage_count += 1
        usage.last_used = datetime.now()
    else:
        usage = CipherUsage(
            user_id=user_id,
            cipher_name=cipher_name,
            usage_count=1
        )
        db.session.add(usage)
    
    progress = get_user_progress(user_id)
    progress.encryptions_performed += 1
    db.session.commit()

# =============== ROUTES ===============
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/tutorials')
def tutorials():
    """Halaman utama tutorial"""
    if current_user.is_authenticated:
        progress = get_user_progress(current_user.id)
        return render_template('tutorials.html',
                             username=current_user.username,
                             user_level=progress.level,
                             user_xp=progress.xp,
                             is_premium=False)
    else:
        return render_template('tutorials.html',
                             username='Guest',
                             user_level=1,
                             user_xp=0,
                             is_premium=False)

@app.route('/tutorials/dasar')
def tutorials_dasar():
    return render_template('tutorial_category.html', 
                          category='Dasar Kriptografi',
                          description='Konsep dasar, sejarah, dan terminologi penting untuk pemula')

# ... (semua routes lainnya tetap di sini)
# (Jaga semua routes di app.py karena ini adalah entry point utama)

# =============== DATABASE INITIALIZATION ===============
def init_glossary_data():
    """Initialize glossary terms database"""
    print("📚 Inisialisasi data glossary...")
    
    if GlossaryCategory.query.count() == 0:
        categories = [
            {'name': 'Kriptografi Modern', 'icon': 'microchip', 'description': 'Algoritma dan teknik kriptografi era komputer'},
            {'name': 'Kriptografi Klasik', 'icon': 'landmark', 'description': 'Cipher tradisional sebelum era digital'},
            # ... (isi categories lainnya)
        ]
        
        for i, cat_data in enumerate(categories):
            category = GlossaryCategory(
                name=cat_data['name'],
                description=cat_data['description'],
                icon=cat_data['icon'],
                display_order=i
            )
            db.session.add(category)
        
        db.session.commit()
        print(f"✅ {len(categories)} kategori glossary ditambahkan")
    
    # ... (sisanya sama)

def init_quiz_data():
    """Initialize quiz questions for ciphers"""
    if QuizQuestion.query.filter_by(cipher_name='vigenere').count() == 0:
        vigenere_questions = [
            {
                'question': 'Apa yang dimaksud dengan Vigenere Cipher?',
                'option_a': 'Cipher substitusi monoalfabetik',
                'option_b': 'Cipher substitusi polyalfabetik menggunakan kunci',
                'option_c': 'Cipher transposisi sederhana',
                'option_d': 'Cipher modern berbasis kunci publik',
                'correct_answer': 'B',
                'explanation': 'Vigenere Cipher adalah cipher substitusi polyalfabetik yang menggunakan kata kunci untuk multiple shift values.',
                'difficulty': 'easy',
                'xp_reward': 15
            },
            # ... (isi questions lainnya)
        ]
        
        for q in vigenere_questions:
            question = QuizQuestion(
                cipher_name='vigenere',
                question=q['question'],
                option_a=q['option_a'],
                option_b=q['option_b'],
                option_c=q['option_c'],
                option_d=q['option_d'],
                correct_answer=q['correct_answer'],
                explanation=q['explanation'],
                difficulty=q['difficulty'],
                xp_reward=q['xp_reward']
            )
            db.session.add(question)
    
    # ... (sisanya sama)

def initialize_database():
    """Initialize database dengan data default"""
    print("🔧 Inisialisasi database...")
    with app.app_context():
        db.create_all()
        print("✅ Tabel database dibuat")
        
        init_quiz_data()
        print("✅ Data quiz ditambahkan")

        init_glossary_data()
        print("✅ Data glossary ditambahkan")
        
        if Achievement.query.count() == 0:
            achievements = [
                Achievement(
                    name='Caesar Novice',
                    description='Selesaikan quiz Caesar Cipher pertama',
                    icon='fas fa-crown',
                    xp_reward=50,
                    requirement='complete_caesar_quiz'
                ),
                # ... (isi achievements lainnya)
            ]
            
            for a in achievements:
                db.session.add(a)
            
            db.session.commit()
            print("✅ Data achievements ditambahkan")
    
    print("🎉 Database berhasil diinisialisasi!")

# =============== MAIN ENTRY POINT ===============
if __name__ == '__main__':
    initialize_database()
    app.run(debug=True, host='0.0.0.0', port=5000)