import base64
import hashlib
import time
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import secrets
import bcrypt
import json
import math
import random
import re
import smtplib
import os
import numpy as np 
from flask_mail import Mail, Message
from email.mime.text import MIMEText
from datetime import datetime, date, timedelta
from collections import Counter
from flask_cors import CORS

from utils.modern_crypto import aes_decrypt, aes_encrypt, des_decrypt, des_encrypt
from utils.rsa import ciphertext_to_string, generate_keypair, rsa_decrypt, rsa_encrypt


# =============== INISIALISASI APLIKASI ===============
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config.update(
    MAIL_SERVER='sandbox.smtp.mailtrap.io',
    MAIL_PORT=2525,
    MAIL_USERNAME='8af2cb84cfc5b6',         
    MAIL_PASSWORD='d1620a3c08deea',       
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_DEFAULT_SENDER=('DecoDify', 'noreply@decodify.com')
)
mail = Mail(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

# Inisialisasi ekstensi
db = SQLAlchemy(app)

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

def send_reset_email(user_email, reset_token):
    """Kirim email reset password"""
    reset_url = url_for('reset_password', token=reset_token, _external=True)
    
    # HTML template email
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #6366f1, #8b5cf6, #ec4899); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }}
            .button {{ display: inline-block; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Reset Password DecoDify</h1>
            </div>
            <div class="content">
                <h2>Halo!</h2>
                <p>Kami menerima permintaan reset password untuk akun DecoDify Anda.</p>
                <p>Klik tombol di bawah ini untuk membuat password baru:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" class="button">Reset Password</a>
                </div>
                
                <p>Atau copy link berikut ke browser Anda:</p>
                <p style="background: #e2e8f0; padding: 10px; border-radius: 5px; word-break: break-all;">
                    {reset_url}
                </p>
                
                <p><strong>⚠️ Link ini akan kadaluarsa dalam 1 jam.</strong></p>
                
                <p>Jika Anda tidak meminta reset password, abaikan email ini.</p>
                
                <div class="footer">
                    <p>Terima kasih,<br>Tim DecoDify</p>
                    <p style="font-size: 12px; color: #94a3b8;">
                        Email ini dikirim secara otomatis. Mohon tidak membalas email ini.
                    </p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Text version untuk email client sederhana
    text_content = f"""
    Reset Password DecoDify
    
    Klik link berikut untuk reset password:
    {reset_url}
    
    Link akan kadaluarsa dalam 1 jam.
    
    Jika Anda tidak meminta reset password, abaikan email ini.
    
    Terima kasih,
    Tim DecoDify
    """
    
    try:
        msg = Message(
            subject="Reset Password - DecoDify",
            recipients=[user_email],
            html=html_content,
            body=text_content
        )
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
        
# =============== MODELS ===============
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    def set_password(self, password):
        """Hash password menggunakan Argon2"""
        self.password_hash = ph.hash(password)
    
    def check_password(self, password):
        """Verifikasi password dengan Argon2"""
        try:
            ph.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    cipher_name = db.Column(db.String(50))
    xp_gained = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    user = db.relationship('User', backref=db.backref('activities', lazy=True))

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    level = db.Column(db.Integer, default=1)
    xp = db.Column(db.Integer, default=0)
    challenges_completed = db.Column(db.Integer, default=0)
    encryptions_performed = db.Column(db.Integer, default=0)
    learning_time_minutes = db.Column(db.Integer, default=0)
    current_streak = db.Column(db.Integer, default=0)
    last_active_date = db.Column(db.Date, default=db.func.current_date())
    
    user = db.relationship('User', backref=db.backref('progress', uselist=False))

class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    icon = db.Column(db.String(50))
    xp_reward = db.Column(db.Integer, default=100)
    requirement = db.Column(db.String(100))

class UserAchievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievement.id'), nullable=False)
    unlocked_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    user = db.relationship('User', backref=db.backref('user_achievements', lazy=True))
    achievement = db.relationship('Achievement', backref=db.backref('user_achievements', lazy=True))

class CipherUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cipher_name = db.Column(db.String(50), nullable=False)
    usage_count = db.Column(db.Integer, default=0)
    last_used = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    user = db.relationship('User', backref=db.backref('cipher_usages', lazy=True))

class QuizQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cipher_name = db.Column(db.String(50), nullable=False)
    question = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200))
    option_b = db.Column(db.String(200))
    option_c = db.Column(db.String(200))
    option_d = db.Column(db.String(200))
    correct_answer = db.Column(db.String(1), nullable=False)
    explanation = db.Column(db.String(1000))
    difficulty = db.Column(db.String(20), default='medium')
    xp_reward = db.Column(db.Integer, default=10)

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cipher_name = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, default=0)
    total_questions = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    user = db.relationship('User', backref=db.backref('quiz_attempts', lazy=True))

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cipher_name = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    ciphertext = db.Column(db.String(500), nullable=False)
    plaintext = db.Column(db.String(500), nullable=False)
    hint = db.Column(db.String(200))
    difficulty = db.Column(db.String(20), default='easy')
    xp_reward = db.Column(db.Integer, default=25)
    category = db.Column(db.String(50))

class ChallengeAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, default=0)
    
    user = db.relationship('User', backref=db.backref('challenge_attempts', lazy=True))
    challenge = db.relationship('Challenge', backref=db.backref('attempts', lazy=True))

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

def caesar_crack(ciphertext):
    """Bruteforce Caesar Cipher"""
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        results.append({
            'shift': shift,
            'text': decrypted
        })
    return results

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

def vigenere_analyze(ciphertext):
    """Analisis sederhana untuk Vigenere Cipher"""
    ciphertext_clean = ''.join(c for c in ciphertext.upper() if c.isalpha())
    
    if not ciphertext_clean:
        return {
            'length': 0,
            'alphabetic_chars': 0,
            'top_5_chars': [],
            'warning': 'Teks tidak mengandung huruf alfabet'
        }
    
    freq = Counter(ciphertext_clean)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    
    n = len(ciphertext_clean)
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0
    
    estimated_length = 0
    if ic > 0:
        expected_ic_english = 0.067
        expected_ic_random = 0.038
        estimated_length = int((0.027 * n) / ((n - 1) * ic - expected_ic_random * n + expected_ic_english))
        estimated_length = max(1, min(estimated_length, 20))
    
    sequences = {}
    for length in range(3, 7):
        for i in range(len(ciphertext_clean) - length + 1):
            sequence = ciphertext_clean[i:i + length]
            positions = [m.start() for m in re.finditer(re.escape(sequence), ciphertext_clean)]
            
            if len(positions) > 1:
                sequences[sequence] = {
                    'sequence': sequence,
                    'positions': positions,
                    'occurrences': len(positions)
                }
    
    repeating_sequences = sorted(
        sequences.values(), 
        key=lambda x: x['occurrences'], 
        reverse=True
    )[:10]
    
    return {
        'length': len(ciphertext),
        'alphabetic_chars': n,
        'top_5_chars': sorted_freq[:5],
        'index_of_coincidence': round(ic, 4),
        'estimated_key_length': estimated_length,
        'repeating_sequences': repeating_sequences,
        'most_common_letter': sorted_freq[0][0] if sorted_freq else None,
        'english_ic_comparison': round(ic / 0.067, 2) if ic > 0 else 0
    }

# Playfair Cipher Utilities
def prepare_playfair_key(key):
    """Persiapan kunci untuk Playfair Cipher"""
    key = ''.join(filter(str.isalpha, key.upper()))
    key = key.replace('J', 'I')
    
    unique_chars = []
    for char in key:
        if char not in unique_chars:
            unique_chars.append(char)
    
    return ''.join(unique_chars)

def create_playfair_matrix(key):
    """Buat matriks 5x5 untuk Playfair Cipher"""
    prepared_key = prepare_playfair_key(key)
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    
    matrix_chars = []
    used_chars = set()
    
    for char in prepared_key:
        if char not in used_chars:
            matrix_chars.append(char)
            used_chars.add(char)
    
    for char in alphabet:
        if char not in used_chars:
            matrix_chars.append(char)
            used_chars.add(char)
    
    return [matrix_chars[i:i+5] for i in range(0, 25, 5)]

def find_char_position(matrix, char):
    """Cari posisi karakter dalam matriks Playfair"""
    char = char.upper().replace('J', 'I')
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return (row, col)
    return None

def prepare_playfair_text(text, mode='encrypt'):
    """Persiapan teks untuk Playfair Cipher"""
    text = ''.join(filter(str.isalpha, text.upper()))
    text = text.replace('J', 'I')
    
    digraphs = []
    i = 0
    
    while i < len(text):
        if i + 1 < len(text):
            a = text[i]
            b = text[i + 1]
            
            if a == b:
                digraphs.append(a + 'X')
                i += 1
            else:
                digraphs.append(a + b)
                i += 2
        else:
            digraphs.append(text[i] + 'X')
            i += 1
    
    if mode == 'decrypt' and digraphs:
        last_digraph = digraphs[-1]
        if last_digraph.endswith('X'):
            digraphs[-1] = last_digraph[0]
            if len(last_digraph) > 1 and last_digraph[1] == 'X':
                digraphs[-1] = last_digraph[0]
    
    return digraphs

def playfair_encrypt_decrypt(text, key, mode='encrypt'):
    """Enkripsi atau dekripsi menggunakan Playfair Cipher"""
    matrix = create_playfair_matrix(key)
    digraphs = prepare_playfair_text(text, mode)
    
    result = ''
    
    for digraph in digraphs:
        if len(digraph) < 2:
            result += digraph
            continue
        
        char1, char2 = digraph[0], digraph[1]
        pos1 = find_char_position(matrix, char1)
        pos2 = find_char_position(matrix, char2)
        
        if not pos1 or not pos2:
            result += digraph
            continue
        
        row1, col1 = pos1
        row2, col2 = pos2
        
        if row1 == row2:
            if mode == 'encrypt':
                new_col1 = (col1 + 1) % 5
                new_col2 = (col2 + 1) % 5
            else:
                new_col1 = (col1 - 1) % 5
                new_col2 = (col2 - 1) % 5
            new_char1 = matrix[row1][new_col1]
            new_char2 = matrix[row2][new_col2]
        
        elif col1 == col2:
            if mode == 'encrypt':
                new_row1 = (row1 + 1) % 5
                new_row2 = (row2 + 1) % 5
            else:
                new_row1 = (row1 - 1) % 5
                new_row2 = (row2 - 1) % 5
            new_char1 = matrix[new_row1][col1]
            new_char2 = matrix[new_row2][col2]
        
        else:
            new_char1 = matrix[row1][col2]
            new_char2 = matrix[row2][col1]
        
        result += new_char1 + new_char2
    
    return result

def playfair_encrypt(plaintext, key):
    """Enkripsi teks menggunakan Playfair Cipher"""
    return playfair_encrypt_decrypt(plaintext, key, 'encrypt')

def playfair_decrypt(ciphertext, key):
    """Dekripsi teks yang dienkripsi dengan Playfair Cipher"""
    return playfair_encrypt_decrypt(ciphertext, key, 'decrypt')

def analyze_playfair_key(key):
    """Analisis kunci Playfair"""
    prepared_key = prepare_playfair_key(key)
    matrix = create_playfair_matrix(key)
    
    return {
        'original_key': key,
        'prepared_key': prepared_key,
        'key_length': len(prepared_key),
        'unique_chars': len(set(prepared_key)),
        'matrix': matrix
    }

# Bruteforce Utilities
def calculate_english_score(text):
    """Hitung score berdasarkan frekuensi karakter bahasa Inggris"""
    common_chars = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    score = 0
    text_upper = text.upper()
    
    score += text.count(' ') * 2
    
    for i, char in enumerate(common_chars):
        if char in text_upper:
            score += (26 - i) * text_upper.count(char)
    
    return score

def bruteforce_caesar(ciphertext):
    """Bruteforce Caesar Cipher"""
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = calculate_english_score(decrypted)
        results.append({
            'shift': shift,
            'text': decrypted,
            'score': score
        })
    
    results.sort(key=lambda x: x['score'], reverse=True)
    return results

# Substitution Cipher Utilities
def substitution_encrypt(text, key):
    """Encrypt text using Substitution Cipher"""
    result = []
    
    # Validate key
    if len(key) != 26 or not key.isalpha():
        raise ValueError("Key must be 26 uppercase letters (A-Z)")
    
    # Create encryption mapping
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encrypt_map = {alphabet[i]: key[i] for i in range(26)}
    
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            char_upper = char.upper()
            if char_upper in encrypt_map:
                encrypted_char = encrypt_map[char_upper]
                result.append(encrypted_char if is_upper else encrypted_char.lower())
            else:
                result.append(char)
        else:
            result.append(char)
    
    return ''.join(result)

def substitution_decrypt(text, key):
    """Decrypt text using Substitution Cipher"""
    result = []
    
    # Validate key
    if len(key) != 26 or not key.isalpha():
        raise ValueError("Key must be 26 uppercase letters (A-Z)")
    
    # Create decryption mapping
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decrypt_map = {key[i]: alphabet[i] for i in range(26)}
    
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            char_upper = char.upper()
            if char_upper in decrypt_map:
                decrypted_char = decrypt_map[char_upper]
                result.append(decrypted_char if is_upper else decrypted_char.lower())
            else:
                result.append(char)
        else:
            result.append(char)
    
    return ''.join(result)

def generate_substitution_key(keyword=""):
    """Generate substitution key from keyword or random"""
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    if keyword:
        # Remove duplicates while preserving order
        unique_keyword = ""
        for char in keyword.upper():
            if char.isalpha() and char not in unique_keyword:
                unique_keyword += char
        
        # Fill remaining letters
        remaining = [c for c in alphabet if c not in unique_keyword]
        random.shuffle(remaining)
        return unique_keyword + ''.join(remaining)
    else:
        # Generate random key
        chars = list(alphabet)
        random.shuffle(chars)
        return ''.join(chars)

def analyze_frequency(text):
    """Analyze character frequency in text"""
    text_upper = ''.join(c.upper() for c in text if c.isalpha())
    
    if not text_upper:
        return {
            'total_chars': 0,
            'frequency': {},
            'sorted_frequency': [],
            'most_common': []
        }
    
    total_chars = len(text_upper)
    freq = {}
    
    for char in text_upper:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate percentages
    freq_percent = {char: (count / total_chars * 100) for char, count in freq.items()}
    
    # Sort by frequency
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    
    # Get top 5
    top_5 = sorted_freq[:5] if len(sorted_freq) >= 5 else sorted_freq
    
    # English letter frequencies for comparison
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
        'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
        'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
        'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
        'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
    }
    
    return {
        'total_chars': total_chars,
        'frequency': freq_percent,
        'sorted_frequency': [(char, count, freq_percent[char]) for char, count in sorted_freq],
        'most_common': top_5,
        'english_frequency': english_freq
    }

# Transposition Cipher Utilities
def rail_fence_encrypt(text, rails):
    """Encrypt text using Rail Fence cipher"""
    # Clean text for encryption
    text_clean = ''.join(c for c in text)
    
    if rails < 2 or rails > 10:
        raise ValueError("Rails must be between 2 and 10")
    
    # Create fence
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    for char in text_clean:
        fence[rail].append(char)
        rail += direction
        
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    # Build ciphertext
    result = []
    for rail in fence:
        result.extend(rail)
    
    return ''.join(result)

def rail_fence_decrypt(ciphertext, rails):
    """Decrypt text using Rail Fence cipher"""
    if rails < 2 or rails > 10:
        raise ValueError("Rails must be between 2 and 10")
    
    # Create fence pattern
    fence = [[None] * len(ciphertext) for _ in range(rails)]
    
    rail = 0
    direction = 1
    for i in range(len(ciphertext)):
        fence[rail][i] = '*'
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    # Fill fence with ciphertext
    index = 0
    for i in range(rails):
        for j in range(len(ciphertext)):
            if fence[i][j] == '*' and index < len(ciphertext):
                fence[i][j] = ciphertext[index]
                index += 1
    
    # Read the fence
    result = []
    rail = 0
    direction = 1
    for i in range(len(ciphertext)):
        if fence[rail][i] is not None:
            result.append(fence[rail][i])
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    return ''.join(result)

def columnar_transposition_encrypt(text, key):
    """Encrypt text using Columnar Transposition"""
    # Clean key
    key_clean = key.upper().replace(' ', '')
    if not key_clean:
        raise ValueError("Key cannot be empty")
    
    # Determine column order
    columns = len(key_clean)
    rows = (len(text) + columns - 1) // columns
    
    # Create grid
    grid = [[''] * columns for _ in range(rows)]
    
    # Fill grid row by row
    text_index = 0
    for r in range(rows):
        for c in range(columns):
            if text_index < len(text):
                grid[r][c] = text[text_index]
                text_index += 1
            else:
                grid[r][c] = 'X'  # Padding
    
    # Determine column order based on key
    key_order = [(key_clean[i], i) for i in range(columns)]
    key_order.sort(key=lambda x: x[0])
    
    # Read columns in key order
    result = []
    for _, col_index in key_order:
        for r in range(rows):
            result.append(grid[r][col_index])
    
    return ''.join(result)

def columnar_transposition_decrypt(ciphertext, key):
    """Decrypt text using Columnar Transposition"""
    # Clean key
    key_clean = key.upper().replace(' ', '')
    if not key_clean:
        raise ValueError("Key cannot be empty")
    
    columns = len(key_clean)
    rows = len(ciphertext) // columns
    
    # Determine column order
    key_order = [(key_clean[i], i) for i in range(columns)]
    key_order.sort(key=lambda x: x[0])
    
    # Create grid
    grid = [[''] * columns for _ in range(rows)]
    
    # Fill grid column by column in key order
    ciphertext_index = 0
    for _, col_index in key_order:
        for r in range(rows):
            if ciphertext_index < len(ciphertext):
                grid[r][col_index] = ciphertext[ciphertext_index]
                ciphertext_index += 1
    
    # Read grid row by row
    result = []
    for r in range(rows):
        for c in range(columns):
            result.append(grid[r][c])
    
    # Remove padding
    plaintext = ''.join(result).rstrip('X')
    return plaintext

def route_cipher_encrypt(text, rows, cols, pattern='column'):
    """Encrypt text using Route Cipher"""
    # Clean text
    text_clean = text.replace(' ', '').upper()
    
    # Create grid
    grid = [[''] * cols for _ in range(rows)]
    
    # Fill grid
    text_index = 0
    for r in range(rows):
        for c in range(cols):
            if text_index < len(text_clean):
                grid[r][c] = text_clean[text_index]
                text_index += 1
            else:
                grid[r][c] = 'X'  # Padding
    
    result = []
    
    if pattern == 'column':
        # Read column by column
        for c in range(cols):
            for r in range(rows):
                result.append(grid[r][c])
    elif pattern == 'row':
        # Read row by row
        for r in range(rows):
            for c in range(cols):
                result.append(grid[r][c])
    elif pattern == 'spiral':
        # Read in spiral pattern
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1
        
        while top <= bottom and left <= right:
            # Right
            for c in range(left, right + 1):
                result.append(grid[top][c])
            top += 1
            
            # Down
            for r in range(top, bottom + 1):
                result.append(grid[r][right])
            right -= 1
            
            # Left
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append(grid[bottom][c])
                bottom -= 1
            
            # Up
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append(grid[r][left])
                left += 1
    
    return ''.join(result)

def route_cipher_decrypt(ciphertext, rows, cols, pattern='column'):
    """Decrypt text using Route Cipher"""
    # Create empty grid
    grid = [[''] * cols for _ in range(rows)]
    
    ciphertext_chars = list(ciphertext)
    
    if pattern == 'column':
        # Fill column by column
        for c in range(cols):
            for r in range(rows):
                if ciphertext_chars:
                    grid[r][c] = ciphertext_chars.pop(0)
    elif pattern == 'row':
        # Fill row by row
        for r in range(rows):
            for c in range(cols):
                if ciphertext_chars:
                    grid[r][c] = ciphertext_chars.pop(0)
    elif pattern == 'spiral':
        # Fill in spiral pattern
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1
        
        while top <= bottom and left <= right and ciphertext_chars:
            # Right
            for c in range(left, right + 1):
                if ciphertext_chars:
                    grid[top][c] = ciphertext_chars.pop(0)
            top += 1
            
            # Down
            for r in range(top, bottom + 1):
                if ciphertext_chars:
                    grid[r][right] = ciphertext_chars.pop(0)
            right -= 1
            
            # Left
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if ciphertext_chars:
                        grid[bottom][c] = ciphertext_chars.pop(0)
                bottom -= 1
            
            # Up
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if ciphertext_chars:
                        grid[r][left] = ciphertext_chars.pop(0)
                left += 1
    
    # Read grid row by row
    result = []
    for r in range(rows):
        for c in range(cols):
            result.append(grid[r][c])
    
    # Remove padding
    plaintext = ''.join(result).rstrip('X')
    return plaintext

def spiral_cipher_encrypt(text, size):
    """Encrypt text using Spiral Cipher"""
    text_clean = text.replace(' ', '').upper()
    
    # Create empty grid
    grid = [[''] * size for _ in range(size)]
    
    # Fill grid in spiral pattern (clockwise, from outside in)
    top, bottom = 0, size - 1
    left, right = 0, size - 1
    text_index = 0
    
    while top <= bottom and left <= right and text_index < len(text_clean):
        # Right
        for c in range(left, right + 1):
            if text_index < len(text_clean):
                grid[top][c] = text_clean[text_index]
                text_index += 1
        top += 1
        
        # Down
        for r in range(top, bottom + 1):
            if text_index < len(text_clean):
                grid[r][right] = text_clean[text_index]
                text_index += 1
        right -= 1
        
        # Left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if text_index < len(text_clean):
                    grid[bottom][c] = text_clean[text_index]
                    text_index += 1
            bottom -= 1
        
        # Up
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if text_index < len(text_clean):
                    grid[r][left] = text_clean[text_index]
                    text_index += 1
            left += 1
    
    # Read grid row by row for ciphertext
    result = []
    for r in range(size):
        for c in range(size):
            if grid[r][c]:
                result.append(grid[r][c])
            else:
                result.append('X')  # Padding
    
    return ''.join(result)

def spiral_cipher_decrypt(ciphertext, size):
    """Decrypt text using Spiral Cipher"""
    # Create empty grid
    grid = [[''] * size for _ in range(size)]
    
    # Fill grid row by row with ciphertext
    ciphertext_chars = list(ciphertext)
    for r in range(size):
        for c in range(size):
            if ciphertext_chars:
                grid[r][c] = ciphertext_chars.pop(0)
    
    # Read grid in spiral pattern
    result = []
    top, bottom = 0, size - 1
    left, right = 0, size - 1
    
    while top <= bottom and left <= right:
        # Right
        for c in range(left, right + 1):
            result.append(grid[top][c])
        top += 1
        
        # Down
        for r in range(top, bottom + 1):
            result.append(grid[r][right])
        right -= 1
        
        # Left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                result.append(grid[bottom][c])
            bottom -= 1
        
        # Up
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(grid[r][left])
            left += 1
    
    # Remove padding and return
    plaintext = ''.join(result).rstrip('X')
    return plaintext

# =============== HILL CIPHER UTILITIES ===============
def prepare_hill_text(text, block_size):
    """Persiapan teks untuk Hill Cipher"""
    # Hanya huruf kapital
    text = ''.join(c.upper() for c in text if c.isalpha())
    
    # Padding jika panjang tidak kelipatan block_size
    if len(text) % block_size != 0:
        padding_needed = block_size - (len(text) % block_size)
        text += 'X' * padding_needed
    
    return text

def convert_text_to_numbers(text):
    """Konversi teks ke angka (A=0, B=1, ..., Z=25)"""
    return [ord(char) - 65 for char in text]

def convert_numbers_to_text(numbers):
    """Konversi angka ke teks"""
    return ''.join(chr(num + 65) for num in numbers)

def validate_hill_key(matrix):
    """Validasi matriks kunci Hill Cipher"""
    size = len(matrix)
    
    # Cek apakah matriks persegi
    if any(len(row) != size for row in matrix):
        return False, "Matriks harus persegi"
    
    # Cek semua elemen antara 0-25
    for row in matrix:
        for val in row:
            if not (0 <= val <= 25):
                return False, "Semua elemen matriks harus antara 0-25"
    
    # Hitung determinan
    det = calculate_matrix_determinant(matrix)
    
    # Cek apakah determinan coprime dengan 26
    if not is_coprime(det, 26):
        return False, f"Determinan ({det}) harus coprime dengan 26"
    
    return True, "Matriks valid"

def calculate_matrix_determinant(matrix):
    """Hitung determinan matriks"""
    size = len(matrix)
    
    if size == 2:
        # 2x2 matrix: ad - bc
        a, b = matrix[0][0], matrix[0][1]
        c, d = matrix[1][0], matrix[1][1]
        return (a * d - b * c) % 26
    
    elif size == 3:
        # 3x3 matrix: a(ei - fh) - b(di - fg) + c(dh - eg)
        a, b, c = matrix[0][0], matrix[0][1], matrix[0][2]
        d, e, f = matrix[1][0], matrix[1][1], matrix[1][2]
        g, h, i = matrix[2][0], matrix[2][1], matrix[2][2]
        
        return (a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)) % 26
    
    return 0

def is_coprime(a, b):
    """Cek apakah dua bilangan coprime (GCD = 1)"""
    while b != 0:
        a, b = b, a % b
    return a == 1

def mod_inverse(a, m=26):
    """Cari invers modulo m"""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def calculate_matrix_mod_inverse(matrix):
    """Hitung invers matriks modulo 26"""
    size = len(matrix)
    
    # Hitung determinan
    det = calculate_matrix_determinant(matrix)
    if det < 0:
        det += 26
    
    # Cari invers determinan
    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        return None
    
    if size == 2:
        # Invers matriks 2x2
        a, b = matrix[0][0], matrix[0][1]
        c, d = matrix[1][0], matrix[1][1]
        
        # Matriks adjoint
        adj = [[d, -b], [-c, a]]
        
        # Kalikan dengan invers determinan
        inv_matrix = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                inv_matrix[i][j] = (adj[i][j] * det_inv) % 26
                if inv_matrix[i][j] < 0:
                    inv_matrix[i][j] += 26
        
        return inv_matrix
    
    elif size == 3:
        # Invers matriks 3x3 lebih kompleks
        a, b, c = matrix[0][0], matrix[0][1], matrix[0][2]
        d, e, f = matrix[1][0], matrix[1][1], matrix[1][2]
        g, h, i = matrix[2][0], matrix[2][1], matrix[2][2]
        
        # Matriks kofaktor
        cofactor = [
            [(e*i - f*h) % 26, (f*g - d*i) % 26, (d*h - e*g) % 26],
            [(c*h - b*i) % 26, (a*i - c*g) % 26, (b*g - a*h) % 26],
            [(b*f - c*e) % 26, (c*d - a*f) % 26, (a*e - b*d) % 26]
        ]
        
        # Transpose (adjoint)
        adj = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        for row in range(3):
            for col in range(3):
                adj[col][row] = cofactor[row][col]
        
        # Kalikan dengan invers determinan
        inv_matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        for row in range(3):
            for col in range(3):
                inv_matrix[row][col] = (adj[row][col] * det_inv) % 26
        
        return inv_matrix
    
    return None

def matrix_multiply(matrix, vector):
    """Perkalian matriks dengan vektor modulo 26"""
    size = len(matrix)
    result = [0] * size
    
    for i in range(size):
        for j in range(size):
            result[i] += matrix[i][j] * vector[j]
        result[i] %= 26
    
    return result

def hill_encrypt(plaintext, key_matrix):
    """Enkripsi teks menggunakan Hill Cipher"""
    # Persiapkan teks
    size = len(key_matrix)
    prepared_text = prepare_hill_text(plaintext, size)
    
    # Konversi teks ke angka
    numbers = convert_text_to_numbers(prepared_text)
    
    # Enkripsi per blok
    encrypted_numbers = []
    for i in range(0, len(numbers), size):
        block = numbers[i:i+size]
        encrypted_block = matrix_multiply(key_matrix, block)
        encrypted_numbers.extend(encrypted_block)
    
    # Konversi kembali ke teks
    return convert_numbers_to_text(encrypted_numbers)

def hill_decrypt(ciphertext, key_matrix):
    """Dekripsi teks menggunakan Hill Cipher"""
    # Persiapkan teks
    size = len(key_matrix)
    prepared_text = prepare_hill_text(ciphertext, size)
    
    # Cari invers matriks
    inv_matrix = calculate_matrix_mod_inverse(key_matrix)
    if inv_matrix is None:
        raise ValueError("Matriks tidak invertible modulo 26")
    
    # Konversi teks ke angka
    numbers = convert_text_to_numbers(prepared_text)
    
    # Dekripsi per blok
    decrypted_numbers = []
    for i in range(0, len(numbers), size):
        block = numbers[i:i+size]
        decrypted_block = matrix_multiply(inv_matrix, block)
        decrypted_numbers.extend(decrypted_block)
    
    # Konversi kembali ke teks
    return convert_numbers_to_text(decrypted_numbers)

def analyze_hill_key(matrix):
    """Analisis matriks kunci Hill Cipher"""
    size = len(matrix)
    det = calculate_matrix_determinant(matrix)
    valid, message = validate_hill_key(matrix)
    
    return {
        'size': f"{size}x{size}",
        'determinant': det,
        'is_valid': valid,
        'message': message,
        'invertible': mod_inverse(det, 26) is not None,
        'matrix': matrix
    }

# =============== FUNGSI HELPER ===============
def get_user_progress(user_id):
    """Get or create user progress"""
    progress = UserProgress.query.filter_by(user_id=user_id).first()
    if not progress:
        progress = UserProgress(user_id=user_id)
        db.session.add(progress)
        db.session.commit()
    return progress

def get_chatbot_response(user_message):
    # Load response database
    with open('chatbot_responses.json', 'r', encoding='utf-8') as f:
        responses = json.load(f)
    
    # Simple keyword matching
    user_message_lower = user_message.lower()
    
    # Check for specific keywords
    for key, response in responses.items():
        keywords = key.split()
        matches = sum(1 for keyword in keywords if keyword in user_message_lower)
        
        # If at least 60% of keywords match
        if matches >= len(keywords) * 0.6:
            return response
    
    # Return default response if no match
    return responses.get('default', {
        'answer': 'Maaf, saya belum memahami pertanyaan Anda. Silakan tanyakan tentang kriptografi atau keamanan sistem.',
        'follow_up': ['konsep dasar kriptografi', 'algoritma rsa', 'fungsi hash'],
        'tags': ['help']
    })

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

# =============== MIDDLEWARE ===============
@app.before_request
def security_headers():
    protected_routes = [
        'substitution', 'transposition', 'playfair', 'hill', 'rsa', 'hash_func',
        'aes_page', 'des_page', 'triple_des_page', 'dashboard', 'profile', 'logout', 'quiz', 'chatbot'
    ]
    
    if request.endpoint in protected_routes:
        if not current_user.is_authenticated:
            if request.is_json or request.path.startswith('/api/'):
                return {'error': 'Unauthorized. Login required.'}, 401
            flash('Anda harus login terlebih dahulu!', 'danger')
            return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# =============== ROUTES ===============
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('Semua field harus diisi!', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Password tidak cocok!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email sudah terdaftar!', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        progress = UserProgress(user_id=new_user.id)
        db.session.add(progress)
        db.session.commit()
        
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            session.permanent = True
            session['logout_token'] = secrets.token_urlsafe(32)
            
            progress = get_user_progress(user.id)
            progress.learning_time_minutes += 1
            
            activity = UserActivity(
                user_id=user.id,
                activity_type='login',
                description='User login ke sistem'
            )
            db.session.add(activity)
            db.session.commit()
            
            # Handle AJAX request
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'message': 'Login berhasil!',
                    'redirect': url_for('dashboard')
                })
            
            flash('Login berhasil!', 'success')
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            # Handle AJAX request for error
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': 'Username atau password salah!'
                }), 401
            
            flash('Username atau password salah!', 'danger')
    
    return render_template('login.html')

# =============== PASSWORD RESET ROUTES ===============
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Halaman lupa password"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Harap masukkan alamat email', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Cari user berdasarkan email
        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                # Generate reset token (simpan di database atau session)
                reset_token = secrets.token_urlsafe(32)
                
                # Simpan token di session dengan expiry time (1 jam)
                session['reset_token'] = reset_token
                session['reset_user_id'] = user.id
                session['reset_expiry'] = datetime.now().timestamp() + 3600  # 1 jam
                
                # Log aktivitas
                activity = UserActivity(
                    user_id=user.id,
                    activity_type='password_reset_request',
                    description='Mengirim permintaan reset password',
                    xp_gained=0
                )
                db.session.add(activity)
                db.session.commit()
                
                # Untuk demo, kita tampilkan token di console
                print(f"RESET TOKEN untuk {email}: {reset_token}")
                
                # In production, you would send an email here:
                # send_reset_email(email, reset_token)
                
                flash('Link reset password telah dikirim ke email Anda!', 'success')
                return render_template('forgot_password.html', success=True, email=email)
                
            except Exception as e:
                print(f"Error: {e}")
                flash('Terjadi kesalahan saat mengirim email reset. Silakan coba lagi.', 'danger')
        else:
            # Untuk keamanan, tetap tampilkan pesan sukses meski email tidak ditemukan
            flash('Jika email terdaftar, link reset akan dikirim.', 'info')
            return render_template('forgot_password.html', success=True)
    
    return render_template('forgot_password.html', success=False)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Halaman reset password dengan token"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Verifikasi token dari session
    stored_token = session.get('reset_token')
    user_id = session.get('reset_user_id')
    expiry_time = session.get('reset_expiry')
    
    if (not stored_token or not user_id or not expiry_time or 
        stored_token != token or 
        datetime.now().timestamp() > expiry_time):
        flash('Token reset password tidak valid atau telah kadaluarsa.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('Harap isi semua field.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        if password != confirm_password:
            flash('Password tidak cocok.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        if len(password) < 6:
            flash('Password minimal 6 karakter.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        try:
            # Update password
            user.set_password(password)
            
            # Hapus token dari session
            session.pop('reset_token', None)
            session.pop('reset_user_id', None)
            session.pop('reset_expiry', None)
            
            # Log aktivitas
            activity = UserActivity(
                user_id=user.id,
                activity_type='password_reset',
                description='Password berhasil direset',
                xp_gained=0
            )
            db.session.add(activity)
            db.session.commit()
            
            flash('Password berhasil direset! Silakan login dengan password baru.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error resetting password: {e}")
            flash('Terjadi kesalahan saat reset password. Silakan coba lagi.', 'danger')
    
    return render_template('reset_password.html', token=token, email=user.email)

@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    """API endpoint untuk reset password (AJAX)"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email harus diisi'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            
            # Simpan di session
            session['reset_token'] = reset_token
            session['reset_user_id'] = user.id
            session['reset_expiry'] = datetime.now().timestamp() + 3600
            
            # Log aktivitas
            activity = UserActivity(
                user_id=user.id,
                activity_type='password_reset_request',
                description='Mengirim permintaan reset password',
                xp_gained=0
            )
            db.session.add(activity)
            db.session.commit()
            
            # Untuk demo, return token di response
            return jsonify({
                'success': True,
                'message': 'Link reset password telah dikirim',
                'email': email,
                'token': reset_token,  # In production, remove this line
                'reset_url': url_for('reset_password', token=reset_token, _external=True)
            })
        else:
            # Untuk keamanan, tetap return sukses
            return jsonify({
                'success': True,
                'message': 'Jika email terdaftar, link reset akan dikirim',
                'email': email
            })
            
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({'success': False, 'error': 'Terjadi kesalahan server'}), 500

@app.route('/api/verify-reset-token', methods=['POST'])
def api_verify_reset_token():
    """API endpoint untuk verifikasi reset token"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        stored_token = session.get('reset_token')
        user_id = session.get('reset_user_id')
        expiry_time = session.get('reset_expiry')
        
        if (not stored_token or not user_id or not expiry_time or 
            stored_token != token or 
            datetime.now().timestamp() > expiry_time):
            return jsonify({'success': False, 'error': 'Token tidak valid atau telah kadaluarsa'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User tidak ditemukan'}), 404
        
        return jsonify({
            'success': True,
            'email': user.email,
            'valid': True
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/support')
def support():
    """Halaman support/help"""
    return render_template('support.html')

@app.route('/tanya_jawab')
def tanya_jawab():
    user_data = {
        'username': session.get('username', 'Pengguna'),
        'user_level': session.get('level', 1),
        'user_xp': session.get('xp', 0),
        'completed_ciphers': session.get('completed_ciphers', 0)
    }

    return render_template('tanya_jawab.html', **user_data)

@app.route('/api/chatbot', methods=['POST'])
def chatbot_api():
    try:
        data = request.json
        user_message = data.get('message', '').strip().lower()
        user_id = session.get('user_id', 'anonymous')
        
        # Log the question
        log_question(user_id, user_message)
        
        # Get bot response
        bot_response = get_chatbot_response(user_message)
        
        # Update statistics
        update_chat_stats(user_id)
        
        return jsonify({
            'success': True,
            'response': bot_response['answer'],
            'follow_up': bot_response.get('follow_up', []),
            'tags': bot_response.get('tags', [])
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'response': 'Maaf, terjadi kesalahan. Silakan coba lagi.'
        }), 500

# API untuk chat history
@app.route('/api/chat-history', methods=['GET'])
def chat_history():
    user_id = session.get('user_id', 'anonymous')
    history = get_user_chat_history(user_id)
    
    return jsonify({
        'success': True,
        'history': history[:50]  # Limit to 50 messages
    })

# API untuk statistics
@app.route('/api/chat-stats', methods=['GET'])
def chat_stats():
    stats = get_chat_statistics()
    
    return jsonify({
        'success': True,
        'stats': stats
    })

@app.route('/logout', methods=['POST'])
@secure_logout_required
def logout():
    user_id = current_user.id
    logout_user()
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('index'))

@app.route('/tutorials')
def tutorials():
    return render_template('tutorials.html')

@app.route('/tutorial/<tutorial_id>/detail')
def tutorial_detail(tutorial_id):
    """Halaman detail tutorial"""
    # Logika untuk mengambil data tutorial dari database
    tutorial_data = get_tutorial_by_id(tutorial_id)
    return render_template('tutorial_detail.html', tutorial=tutorial_data)

@app.route('/glossary')
def glossary():
    return render_template('glossary.html')

@app.route('/video-courses')
def video_courses():
    return render_template('video-courses.html')

@app.route('/learning-path')
def learning_path():
    return render_template('learning-path.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if 'logout_token' not in session:
        session['logout_token'] = secrets.token_urlsafe(32)
    
    progress = get_user_progress(current_user.id)
    cipher_usages = CipherUsage.query.filter_by(user_id=current_user.id).count()
    total_ciphers = 15
    
    return render_template('dashboard.html', 
                         username=current_user.username, 
                         logout_token=session['logout_token'],
                         user_level=progress.level,
                         user_xp=progress.xp,
                         completed_ciphers=cipher_usages,
                         total_ciphers=total_ciphers,
                         streak_days=progress.current_streak)

@app.route('/profile')
@login_required
def profile():
    progress = get_user_progress(current_user.id)
    
    user_data = {
        'username': current_user.username,
        'email': current_user.email,
        'full_name': current_user.username,
        'user_level': progress.level,
        'xp_points': progress.xp,
        'streak_days': progress.current_streak,
        'completed_ciphers': CipherUsage.query.filter_by(user_id=current_user.id).count(),
        'total_ciphers': 20,
        'is_premium': False,
        'premium_expiry': None,
        'bio': 'Penggemar kriptografi yang sedang belajar enkripsi modern.',
        'skills': ['Kriptografi Dasar', 'Enkripsi Caesar', 'Analisis Cipher'],
        'join_date': 'Januari 2024'
    }
    return render_template('profile.html', **user_data)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    return jsonify({'success': True, 'message': 'Profile updated'})

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/premium')
def premium():
    return render_template('premium.html')

@app.route('/premium/upgrade', methods=['POST'])
@login_required
def upgrade_premium():
    """Handle premium upgrade payment"""
    
    # Get selected plan from form
    plan = request.form.get('plan')
    
    # Validate plan
    valid_plans = ['monthly', 'yearly', 'lifetime']
    if plan not in valid_plans:
        flash('Pilih paket yang valid', 'error')
        return redirect(url_for('premium'))
    
    # In production, here you would:
    # 1. Process payment via payment gateway
    # 2. Update user premium status in database
    # 3. Send confirmation email
    
    # For demo purposes, just upgrade user
    current_user.is_premium = True
    
    # Set expiration based on plan
    if plan == 'monthly':
        expires = datetime.utcnow() + timedelta(days=30)
    elif plan == 'yearly':
        expires = datetime.utcnow() + timedelta(days=365)
    else:  # lifetime
        expires = datetime.utcnow() + timedelta(days=365*10)  # 10 years
    
    # Tambahkan field premium_expires ke model User jika belum ada
    if not hasattr(User, 'premium_expires'):
        # Untuk demo, kita tambahkan langsung ke session
        session['premium_expires'] = expires.isoformat()
    
    # Beri bonus XP untuk upgrading
    progress = get_user_progress(current_user.id)
    if progress:
        progress.xp += 500
        db.session.commit()
    
    # Log the upgrade
    activity = UserActivity(
        user_id=current_user.id,
        activity_type='premium_upgrade',
        description=f'Upgraded to {plan} premium plan',
        xp_gained=500
    )
    db.session.add(activity)
    db.session.commit()
    
    flash('🎉 Upgrade berhasil! Selamat menikmati fitur premium!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/leaderboard')
def leaderboard():
    return render_template('leaderboard.html')

@app.route('/achievements')
@login_required
def achievements():
    return render_template('achievements.html')

@app.route('/community')
@login_required
def community():
    return render_template('community.html')

# =============== CIPHER PAGES ===============
@app.route('/caesar')
def caesar():
    if current_user.is_authenticated:
        progress = get_user_progress(current_user.id)
        return render_template('caesar.html',
                             username=current_user.username,
                             user_level=progress.level,
                             user_xp=progress.xp)
    else:
        return render_template('caesar.html',
                             username='Guest',
                             user_level=1,
                             user_xp=0)

@app.route('/vigenere')
def vigenere():
    if current_user.is_authenticated:
        progress = get_user_progress(current_user.id)
        return render_template('vigenere.html',
                             username=current_user.username,
                             user_level=progress.level,
                             user_xp=progress.xp)
    else:
        return render_template('vigenere.html',
                             username='Guest',
                             user_level=1,
                             user_xp=0)

@app.route('/bruteforce')
def bruteforce_page():
    if current_user.is_authenticated:
        progress = get_user_progress(current_user.id)
        return render_template('bruteforce.html',
                             username=current_user.username,
                             user_level=progress.level,
                             user_xp=progress.xp)
    else:
        return render_template('bruteforce.html',
                             username='Guest',
                             user_level=1,
                             user_xp=0)

# Fitur Premium
@app.route('/substitution')
@login_required
def substitution():
    progress = get_user_progress(current_user.id)
    return render_template('substitution.html',
                            user_level=progress.level,
                            user_xp=progress.xp)


@app.route('/transposition')
@login_required
def transposition():
    """Transposition Cipher page"""
    progress = get_user_progress(current_user.id)
    return render_template('transposition.html',
                         user_level=progress.level,
                         user_xp=progress.xp)

@app.route('/playfair')
@login_required
def playfair():
    """Playfair Cipher page"""
    progress = get_user_progress(current_user.id)
    return render_template('playfair.html',
                         username=current_user.username,
                         user_level=progress.level,
                         user_xp=progress.xp)

@app.route('/hill')
@login_required
def hill():
    """Hill Cipher page"""
    progress = get_user_progress(current_user.id)
    return render_template('hill.html',
                         username=current_user.username,
                         user_level=progress.level,
                         user_xp=progress.xp)

@app.route('/rsa')
@login_required
def rsa():
    return render_template('rsa.html')

@app.route('/hash')
@login_required
def hash_func():
    return render_template('hash.html')

@app.route('/aes')
@login_required
def aes_page():
    return render_template('aes.html')

@app.route('/des')
@login_required
def des_page():
    return render_template('des.html')

@app.route('/triple-des')
@login_required
def triple_des_page():
    return render_template('triple_des.html')

# ============ RSA ENDPOINTS ============
@app.route('/api/rsa/generate', methods=['POST'])
@login_required
def api_rsa_generate():
    try:
        public_key, private_key = generate_keypair(bits=16)
        
        return jsonify({
            'success': True,
            'public_key': list(public_key),
            'private_key': list(private_key)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@app.route('/api/rsa/encrypt', methods=['POST'])
@login_required
def api_rsa_encrypt():
    try:
        data = request.get_json()
        text = data.get('text', '')
        public_key = tuple(data.get('public_key', []))
        
        ciphertext = rsa_encrypt(text, public_key)
        ciphertext_string = ciphertext_to_string(ciphertext)
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext,
            'ciphertext_string': ciphertext_string
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@app.route('/api/rsa/decrypt', methods=['POST'])
@login_required
def api_rsa_decrypt():
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext', [])
        private_key = tuple(data.get('private_key', []))
        
        plaintext = rsa_decrypt(ciphertext, private_key)
        
        return jsonify({
            'success': True,
            'plaintext': plaintext
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ============== AES ENDPOINTS ===============

# Tambahkan endpoint ini
@app.route('/api/aes', methods=['POST'])
@login_required
def api_aes():
    """AES Encryption/Decryption endpoint"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        key = data.get('key', '')
        mode = data.get('mode', 'encrypt')
        
        if not text or not key:
            return jsonify({
                'success': False,
                'error': 'Text dan key harus diisi'
            }), 400
        
        if len(key) < 16:
            return jsonify({
                'success': False,
                'error': 'Key minimal 16 karakter'
            }), 400
        
        if mode == 'encrypt':
            ciphertext, iv = aes_encrypt(text, key)
            return jsonify({
                'success': True,
                'result': ciphertext,
                'iv': iv,
                'mode': 'encrypt'
            })
        else:  # decrypt
            iv = data.get('iv', '')
            if not iv:
                return jsonify({
                    'success': False,
                    'error': 'IV diperlukan untuk dekripsi'
                }), 400
            
            plaintext = aes_decrypt(text, key, iv)
            return jsonify({
                'success': True,
                'result': plaintext,
                'mode': 'decrypt'
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    
# ================ DES ENDPOINTS ===============
@app.route('/api/des', methods=['POST'])
@login_required
def api_des():
    """DES Encryption/Decryption endpoint"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        key = data.get('key', '')
        mode = data.get('mode', 'encrypt')
        
        if not text or not key:
            return jsonify({
                'error': 'Text dan key harus diisi'
            }), 400
        
        if len(key) != 8:
            return jsonify({
                'error': 'Key harus 8 karakter untuk DES'
            }), 400
        
        if mode == 'encrypt':
            ciphertext, iv = des_encrypt(text, key)
            return jsonify({
                'result': ciphertext,
                'iv': iv
            })
        else:  # decrypt
            iv = data.get('iv', '')
            if not iv:
                return jsonify({
                    'error': 'IV diperlukan untuk dekripsi'
                }), 400
            
            plaintext = des_decrypt(text, key, iv)
            return jsonify({
                'result': plaintext
            })
        
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 400


def des_encrypt(plaintext, key):
    """Encrypt dengan DES-CBC mode"""
    try:
        # Convert key ke bytes (8 bytes)
        key_bytes = key.encode('utf-8')[:8]
        if len(key_bytes) < 8:
            key_bytes = key_bytes.ljust(8, b'\0')
        
        # Generate IV random (8 bytes untuk DES)
        iv = get_random_bytes(8)
        
        # Create cipher dengan mode CBC
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        
        # Pad plaintext ke kelipatan 8 bytes (DES block size)
        # PERBAIKAN: Gunakan pad dari Crypto.Util.Padding, BUKAN np.pad!
        padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_text)
        
        # Convert ke base64 agar bisa ditampilkan
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        
        return ciphertext_b64, iv_b64
        
    except Exception as e:
        raise Exception(f"Enkripsi gagal: {str(e)}")


def des_decrypt(ciphertext_b64, key, iv_b64):
    """Decrypt dengan DES-CBC mode"""
    try:
        # Convert key ke bytes (8 bytes)
        key_bytes = key.encode('utf-8')[:8]
        if len(key_bytes) < 8:
            key_bytes = key_bytes.ljust(8, b'\0')
        
        # Decode dari base64
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        
        # Create cipher dengan IV yang sama
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        
        # Decrypt
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Unpad
        plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
        
        return plaintext
        
    except Exception as e:
        raise Exception(f"Dekripsi gagal: {str(e)}")

# ================ TRIPLE DES ENDPOINTS ===============
@app.route('/api/triple-des', methods=['POST'])
@login_required
def api_triple_des():
    """Triple DES (3DES) Encryption/Decryption endpoint"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        key = data.get('key', '')
        mode = data.get('mode', 'encrypt')
        
        if not text or not key:
            return jsonify({'error': 'Text dan key harus diisi'}), 400
        
        # 3DES mendukung key 16 bytes (2-key) atau 24 bytes (3-key)
        if len(key) not in [16, 24]:
            return jsonify({'error': 'Key harus 16 atau 24 karakter untuk Triple DES'}), 400
        
        if mode == 'encrypt':
            ciphertext, iv = triple_des_encrypt(text, key)
            return jsonify({
                'result': ciphertext,
                'iv': iv
            })
        else:  # decrypt
            iv = data.get('iv', '')
            if not iv:
                return jsonify({'error': 'IV diperlukan untuk dekripsi'}), 400
            
            plaintext = triple_des_decrypt(text, key, iv)
            return jsonify({
                'result': plaintext
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


def triple_des_encrypt(plaintext, key):
    """Encrypt dengan Triple DES (3DES) CBC mode"""
    try:
        # Convert key ke bytes
        key_bytes = key.encode('utf-8')
        
        # Adjust key length untuk 3DES
        # 2-key 3DES: 16 bytes (128 bit)
        # 3-key 3DES: 24 bytes (192 bit)
        if len(key_bytes) == 16:
            # 2-key 3DES
            key_bytes = key_bytes[:16]
        elif len(key_bytes) == 24:
            # 3-key 3DES
            key_bytes = key_bytes[:24]
        else:
            # Pad atau truncate ke 16 bytes
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\0')
            else:
                key_bytes = key_bytes[:16]
        
        # Generate IV random (8 bytes untuk DES/3DES)
        iv = get_random_bytes(8)
        
        # Create cipher dengan mode CBC
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
        
        # Pad plaintext ke kelipatan 8 bytes (DES block size)
        padded_text = pad(plaintext.encode('utf-8'), DES3.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_text)
        
        # Convert ke base64
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        
        return ciphertext_b64, iv_b64
        
    except Exception as e:
        raise Exception(f"Enkripsi gagal: {str(e)}")


def triple_des_decrypt(ciphertext_b64, key, iv_b64):
    """Decrypt dengan Triple DES (3DES) CBC mode"""
    try:
        # Convert key ke bytes
        key_bytes = key.encode('utf-8')
        
        # Adjust key length
        if len(key_bytes) == 16:
            key_bytes = key_bytes[:16]
        elif len(key_bytes) == 24:
            key_bytes = key_bytes[:24]
        else:
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\0')
            else:
                key_bytes = key_bytes[:16]
        
        # Decode dari base64
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        
        # Create cipher dengan IV yang sama
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
        
        # Decrypt
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Unpad
        plaintext = unpad(padded_plaintext, DES3.block_size).decode('utf-8')
        
        return plaintext
        
    except Exception as e:
        raise Exception(f"Dekripsi gagal: {str(e)}")

# =============== Argon2 Endpoint ==============
@app.route('/api/hash/generate', methods=['POST'])
def generate_hashes():
    """Generate berbagai jenis hash dari input text"""
    data = request.json
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    # Encode text ke bytes
    text_bytes = text.encode('utf-8')
    
    hashes = {
        'md5': hashlib.md5(text_bytes).hexdigest(),
        'sha1': hashlib.sha1(text_bytes).hexdigest(),
        'sha256': hashlib.sha256(text_bytes).hexdigest(),
        'sha512': hashlib.sha512(text_bytes).hexdigest(),
        'sha3_256': hashlib.sha3_256(text_bytes).hexdigest(),
        'blake2b': hashlib.blake2b(text_bytes).hexdigest()
    }
    
    return jsonify({'hashes': hashes})


@app.route('/api/hash/bcrypt', methods=['POST'])
def hash_bcrypt():
    """Hash password menggunakan Bcrypt"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Bcrypt hashing
    start_time = time.time()
    rounds = 12  # Cost factor
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    end_time = time.time()
    
    processing_time = (end_time - start_time) * 1000  # Convert to ms
    
    return jsonify({
        'algorithm': 'bcrypt',
        'hash': hashed.decode('utf-8'),
        'rounds': rounds,
        'time_ms': round(processing_time, 2),
        'info': f'Bcrypt menggunakan adaptive hashing dengan {rounds} rounds. '
                f'Semakin besar rounds, semakin lambat dan aman. '
                f'Processing time: {processing_time:.2f}ms'
    })


@app.route('/api/hash/argon2', methods=['POST'])
def hash_argon2():
    """Hash password menggunakan Argon2 dengan parameter lengkap"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Argon2 hashing
    start_time = time.time()
    hashed = ph.hash(password)
    end_time = time.time()
    
    processing_time = (end_time - start_time) * 1000  # Convert to ms
    
    return jsonify({
        'algorithm': 'argon2',
        'hash': hashed,
        'parameters': {
            'time_cost': 3,
            'memory_cost': '64 MB',
            'parallelism': 4,
            'hash_length': 32,
            'salt_length': 16
        },
        'time_ms': round(processing_time, 2),
        'info': f'Argon2 adalah pemenang Password Hashing Competition 2015. '
                f'Menggunakan memory-hard function untuk resist GPU/ASIC attacks. '
                f'Processing time: {processing_time:.2f}ms'
    })


@app.route('/api/hash/compare-algos', methods=['POST'])
def compare_algorithms():
    """Bandingkan Bcrypt vs Argon2 - REQUIREMENT DOSEN"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Hash dengan Bcrypt
    bcrypt_start = time.time()
    rounds = 12
    bcrypt_salt = bcrypt.gensalt(rounds=rounds)
    bcrypt_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt_salt)
    bcrypt_time = (time.time() - bcrypt_start) * 1000
    
    # Hash dengan Argon2
    argon2_start = time.time()
    argon2_hash = ph.hash(password)
    argon2_time = (time.time() - argon2_start) * 1000
    
    # Determine faster algorithm
    faster = 'Bcrypt' if bcrypt_time < argon2_time else 'Argon2'
    
    return jsonify({
        'bcrypt': {
            'hash': bcrypt_hash.decode('utf-8'),
            'time': f'{bcrypt_time:.2f}ms',
            'rounds': rounds
        },
        'argon2': {
            'hash': argon2_hash,
            'time': f'{argon2_time:.2f}ms',
            'params': 'time=3, mem=64MB, parallel=4'
        },
        'recommendation': f'Argon2 lebih direkomendasikan untuk aplikasi modern karena '
                         f'resistance terhadap GPU/ASIC attacks lebih baik. '
                         f'Bcrypt masih aman untuk mayoritas use case. '
                         f'{faster} lebih cepat dalam test ini.'
    })


@app.route('/api/hash/password-strength', methods=['POST'])
def check_password_strength():
    """Cek kekuatan password dengan analisis angka - REQUIREMENT DOSEN"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    score = 0
    max_score = 10
    feedback = []
    
    # Cek panjang
    length = len(password)
    if length >= 12:
        score += 3
        feedback.append('✅ Panjang bagus (≥12 karakter)')
    elif length >= 8:
        score += 2
        feedback.append('⚠️ Panjang cukup (8-11 karakter)')
    else:
        score += 1
        feedback.append('❌ Terlalu pendek (<8 karakter)')
    
    # Cek huruf besar
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append('✅ Mengandung huruf besar')
    else:
        feedback.append('❌ Tidak ada huruf besar')
    
    # Cek huruf kecil
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append('✅ Mengandung huruf kecil')
    else:
        feedback.append('❌ Tidak ada huruf kecil')
    
    # Cek angka
    has_numbers = bool(re.search(r'\d', password))
    if has_numbers:
        score += 1
        feedback.append('✅ Mengandung angka')
    else:
        feedback.append('❌ Tidak ada angka')
    
    # Cek karakter spesial
    if re.search(r'[!@#$%^&*()_+=\-\[\]{};:\'",.<>?/\\|`~]', password):
        score += 2
        feedback.append('✅ Mengandung karakter spesial')
    else:
        feedback.append('❌ Tidak ada karakter spesial')
    
    # Cek variasi
    unique_chars = len(set(password))
    if unique_chars >= length * 0.7:
        score += 1
        feedback.append('✅ Variasi karakter tinggi')
    else:
        feedback.append('⚠️ Banyak karakter berulang')
    
    # Cek pola umum
    common_patterns = ['123', '234', 'abc', 'qwerty', 'password', 'admin']
    has_pattern = any(pattern in password.lower() for pattern in common_patterns)
    if has_pattern:
        score -= 2
        feedback.append('❌ Mengandung pola umum (weak!)')
    else:
        score += 1
        feedback.append('✅ Tidak ada pola umum')
    
    # REQUIREMENT DOSEN: ANALISIS ANGKA DETAIL
    numbers_found = re.findall(r'\d+', password)
    digit_chars = [c for c in password if c.isdigit()]
    total_digits = len(digit_chars)
    
    # Deteksi urutan angka (123, 456, dll)
    has_sequence = False
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            nums = [int(password[i]), int(password[i+1]), int(password[i+2])]
            if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                has_sequence = True
                break
    
    # Deteksi angka berulang (111, 222, dll)
    has_repeated_digits = bool(re.search(r'(\d)\1{2,}', password))
    
    number_analysis = {
        'contains_numbers': has_numbers,
        'total_numbers': len(numbers_found),
        'numbers_found': numbers_found,
        'total_digits': total_digits,
        'percentage': (total_digits / length * 100) if length > 0 else 0,
        'has_sequence': has_sequence,
        'has_repeated_digits': has_repeated_digits
    }
    
    # Tentukan strength
    if score >= 8:
        strength = 'Sangat Kuat'
    elif score >= 6:
        strength = 'Kuat'
    elif score >= 4:
        strength = 'Sedang'
    elif score >= 2:
        strength = 'Lemah'
    else:
        strength = 'Sangat Lemah'
    
    return jsonify({
        'strength': strength,
        'score': max(0, score),
        'max_score': max_score,
        'feedback': feedback,
        'number_analysis': number_analysis
    })


@app.route('/api/hash/compare', methods=['POST'])
def compare_hashes():
    """Bandingkan hash dari dua text"""
    data = request.json
    text1 = data.get('text1', '')
    text2 = data.get('text2', '')
    algorithm = data.get('algorithm', 'sha256')
    
    if not text1 or not text2:
        return jsonify({'error': 'Both texts are required'}), 400
    
    # Generate hash berdasarkan algoritma
    hash_func = getattr(hashlib, algorithm, hashlib.sha256)
    hash1 = hash_func(text1.encode('utf-8')).hexdigest()
    hash2 = hash_func(text2.encode('utf-8')).hexdigest()
    
    return jsonify({
        'hash1': hash1,
        'hash2': hash2,
        'match': hash1 == hash2,
        'algorithm': algorithm.upper()
    })


@app.route('/api/hash/verify-bcrypt', methods=['POST'])
def verify_bcrypt():
    """Verifikasi password dengan Bcrypt hash"""
    data = request.json
    password = data.get('password', '')
    hashed = data.get('hash', '')
    
    if not password or not hashed:
        return jsonify({'error': 'Password and hash are required'}), 400
    
    try:
        is_valid = bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        return jsonify({'valid': is_valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/hash/verify-argon2', methods=['POST'])
def verify_argon2():
    """Verifikasi password dengan Argon2 hash"""
    data = request.json
    password = data.get('password', '')
    hashed = data.get('hash', '')
    
    if not password or not hashed:
        return jsonify({'error': 'Password and hash are required'}), 400
    
    try:
        ph.verify(hashed, password)
        return jsonify({'valid': True})
    except Exception:
        return jsonify({'valid': False})
 
# =============== API ENDPOINTS ===============

@app.route('/api/user/score')
@login_required
def get_user_score():
    """Get current user score and level"""
    progress = get_user_progress(current_user.id)
    return jsonify({
        'level': progress.level,
        'xp': progress.xp,
        'challenges_completed': progress.challenges_completed,
        'encryptions_performed': progress.encryptions_performed,
        'learning_time': progress.learning_time_minutes,
        'current_streak': progress.current_streak
    })

@app.route('/api/caesar', methods=['POST'])
def api_caesar():
    data = request.get_json()
    text = data.get('text', '')
    shift = int(data.get('shift', 3))
    mode = data.get('mode', 'encrypt')
    
    try:
        if mode == 'encrypt':
            result = caesar_encrypt(text, shift)
        else:
            result = caesar_decrypt(text, shift)
        
        if current_user.is_authenticated:
            log_cipher_usage(current_user.id, 'caesar')
        
        return jsonify({
            'success': True,
            'result': result,
            'shift': shift,
            'mode': mode
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/vigenere', methods=['POST'])
def api_vigenere():
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    try:
        clean_key = key.upper().replace(' ', '')
        if not clean_key or not re.match('^[A-Z]+$', clean_key):
            return jsonify({
                'success': False,
                'error': 'Kunci hanya boleh mengandung huruf A-Z'
            }), 400
        
        if mode == 'encrypt':
            result = vigenere_encrypt(text, clean_key)
        else:
            result = vigenere_decrypt(text, clean_key)
        
        key_stream = ''
        key_index = 0
        key_length = len(clean_key)
        for char in text:
            if char.isalpha():
                key_stream += clean_key[key_index % key_length]
                key_index += 1
            else:
                key_stream += ' '
        
        if current_user.is_authenticated:
            log_cipher_usage(current_user.id, 'vigenere')
        
        return jsonify({
            'success': True,
            'result': result,
            'key': clean_key,
            'key_stream': key_stream[:100],
            'mode': mode,
            'stats': {
                'text_length': len(text),
                'key_length': key_length,
                'alphabetic_chars': sum(1 for c in text if c.isalpha())
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/vigenere/analyze', methods=['POST'])
def api_vigenere_analyze():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    
    try:
        analysis = vigenere_analyze(ciphertext)
        return jsonify({
            'success': True,
            'analysis': analysis
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/transposition', methods=['POST'])
@login_required
def api_transposition():
    """API endpoint for Transposition Cipher operations"""
    data = request.get_json()
    text = data.get('text', '')
    mode = data.get('mode', 'encrypt')
    cipher_type = data.get('type', 'railfence')
    
    try:
        result = ''
        steps = []
        stats = {
            'text_length': len(text),
            'alphabetic_chars': sum(1 for c in text if c.isalpha())
        }
        
        if cipher_type == 'railfence':
            rails = int(data.get('rails', 3))
            rail_mode = data.get('railMode', 'zigzag')
            
            if mode == 'encrypt':
                result = rail_fence_encrypt(text, rails)
                steps = [
                    f"Text input: {text}",
                    f"Number of rails: {rails}",
                    f"Writing text in zigzag pattern across {rails} rails",
                    f"Reading text rail by rail",
                    f"Ciphertext: {result}"
                ]
                stats['rails'] = rails
                stats['note'] = f"Rail Fence cipher with {rails} rails"
            else:
                result = rail_fence_decrypt(text, rails)
                steps = [
                    f"Ciphertext input: {text}",
                    f"Number of rails: {rails}",
                    f"Reconstructing zigzag pattern",
                    f"Reading text in original order",
                    f"Plaintext: {result}"
                ]
                stats['rails'] = rails
            
        elif cipher_type == 'columnar':
            key = data.get('key', 'SECRET')
            order = data.get('order', 'keyword')
            
            if mode == 'encrypt':
                result = columnar_transposition_encrypt(text, key)
                steps = [
                    f"Text input: {text}",
                    f"Key: {key}",
                    f"Writing text in columns based on key length",
                    f"Reading columns in alphabetical order of key",
                    f"Ciphertext: {result}"
                ]
                stats['key'] = key
                stats['key_length'] = len(key)
                stats['note'] = f"Columnar transposition with key '{key}'"
            else:
                result = columnar_transposition_decrypt(text, key)
                steps = [
                    f"Ciphertext input: {text}",
                    f"Key: {key}",
                    f"Placing ciphertext into columns in key order",
                    f"Reading text row by row",
                    f"Plaintext: {result}"
                ]
                stats['key'] = key
                stats['key_length'] = len(key)
            
        elif cipher_type == 'route':
            rows = int(data.get('rows', 3))
            cols = int(data.get('cols', 4))
            pattern = data.get('pattern', 'column')
            
            if mode == 'encrypt':
                result = route_cipher_encrypt(text, rows, cols, pattern)
                steps = [
                    f"Text input: {text}",
                    f"Grid size: {rows}×{cols}",
                    f"Writing text into grid row by row",
                    f"Reading grid using {pattern} pattern",
                    f"Ciphertext: {result}"
                ]
                stats['rows'] = rows
                stats['cols'] = cols
                stats['grid_size'] = f"{rows}×{cols}"
                stats['pattern'] = pattern
                stats['note'] = f"Route cipher with {rows}×{cols} grid, {pattern} pattern"
            else:
                result = route_cipher_decrypt(text, rows, cols, pattern)
                steps = [
                    f"Ciphertext input: {text}",
                    f"Grid size: {rows}×{cols}",
                    f"Filling grid using {pattern} pattern",
                    f"Reading grid row by row",
                    f"Plaintext: {result}"
                ]
                stats['rows'] = rows
                stats['cols'] = cols
            
        elif cipher_type == 'spiral':
            size = int(data.get('size', 4))
            direction = data.get('direction', 'clockwise')
            
            if mode == 'encrypt':
                result = spiral_cipher_encrypt(text, size)
                steps = [
                    f"Text input: {text}",
                    f"Grid size: {size}×{size}",
                    f"Writing text in spiral pattern ({direction})",
                    f"Reading grid row by row",
                    f"Ciphertext: {result}"
                ]
                stats['size'] = size
                stats['grid_size'] = f"{size}×{size}"
                stats['direction'] = direction
                stats['note'] = f"Spiral cipher with {size}×{size} grid"
            else:
                result = spiral_cipher_decrypt(text, size)
                steps = [
                    f"Ciphertext input: {text}",
                    f"Grid size: {size}×{size}",
                    f"Filling grid row by row",
                    f"Reading grid in spiral pattern",
                    f"Plaintext: {result}"
                ]
                stats['size'] = size
                stats['grid_size'] = f"{size}×{size}"
        
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown transposition type: {cipher_type}'
            }), 400
        
        # Log usage
        log_cipher_usage(current_user.id, 'transposition')
        
        # Add result stats
        stats['result_length'] = len(result)
        
        return jsonify({
            'success': True,
            'result': result,
            'type': cipher_type,
            'mode': mode,
            'steps': steps,
            'stats': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/bruteforce', methods=['POST'])
def api_bruteforce():
    data = request.get_json()
    text = data.get('text', '')
    
    try:
        if not text.strip():
            return jsonify({
                'success': False,
                'error': 'Masukkan ciphertext terlebih dahulu!'
            }), 400
        
        results = bruteforce_caesar(text)
        
        if current_user.is_authenticated:
            log_cipher_usage(current_user.id, 'bruteforce')
        
        return jsonify({
            'success': True,
            'results': results,
            'statistics': {
                'total_shifts': 26,
                'top_shift': results[0]['shift'] if results else -1,
                'top_score': results[0]['score'] if results else 0,
                'ciphertext_length': len(text)
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/bruteforce/manual', methods=['POST'])
def api_bruteforce_manual():
    data = request.get_json()
    text = data.get('text', '')
    shift = int(data.get('shift', 0))
    
    try:
        if not text.strip():
            return jsonify({
                'success': False,
                'error': 'Masukkan ciphertext terlebih dahulu!'
            }), 400
        
        if shift < 0 or shift > 25:
            return jsonify({
                'success': False,
                'error': 'Shift harus antara 0-25'
            }), 400
        
        decrypted = caesar_decrypt(text, shift)
        score = calculate_english_score(decrypted)
        
        return jsonify({
            'success': True,
            'result': decrypted,
            'shift': shift,
            'score': score,
            'stats': {
                'plaintext_length': len(decrypted),
                'confidence': min(100, (score / 1000) * 100)
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/substitution', methods=['POST'])
@login_required
def api_substitution():
    """API endpoint for Substitution Cipher operations"""
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    keyword = data.get('keyword', '')
    
    try:
        # Generate key if needed
        if not key and keyword:
            key = generate_substitution_key(keyword)
        elif not key:
            key = generate_substitution_key()
        
        # Validate key
        if len(key) != 26 or not key.isalpha():
            return jsonify({
                'success': False,
                'error': 'Key must be 26 uppercase letters (A-Z)'
            }), 400
        
        key = key.upper()  # Ensure key is uppercase
        
        # Perform encryption/decryption
        if mode == 'encrypt':
            result = substitution_encrypt(text, key)
        else:
            result = substitution_decrypt(text, key)
        
        # Log usage
        log_cipher_usage(current_user.id, 'substitution')
        
        # Analyze frequency for the result
        analysis = analyze_frequency(result)
        
        return jsonify({
            'success': True,
            'result': result,
            'key': key,
            'mode': mode,
            'analysis': analysis,
            'stats': {
                'text_length': len(text),
                'result_length': len(result),
                'alphabetic_chars': sum(1 for c in text if c.isalpha()),
                'key_valid': True
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/substitution/generate-key', methods=['POST'])
@login_required
def api_generate_substitution_key():
    """Generate a substitution key"""
    data = request.get_json()
    keyword = data.get('keyword', '')
    
    try:
        key = generate_substitution_key(keyword)
        
        return jsonify({
            'success': True,
            'key': key,
            'keyword': keyword if keyword else 'random'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/substitution/analyze', methods=['POST'])
@login_required
def api_analyze_substitution():
    """Analyze text for frequency analysis"""
    data = request.get_json()
    text = data.get('text', '')
    
    try:
        analysis = analyze_frequency(text)
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/playfair', methods=['POST'])
@login_required
def api_playfair():
    """API endpoint for Playfair Cipher operations"""
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', 'PLAYFAIR')
    mode = data.get('mode', 'encrypt')
    
    try:
        if mode == 'encrypt':
            result = playfair_encrypt(text, key)
        elif mode == 'decrypt':
            result = playfair_decrypt(text, key)
        else:
            return jsonify({
                'success': False,
                'error': 'Mode harus "encrypt" atau "decrypt"'
            }), 400
        
        # Log usage
        log_cipher_usage(current_user.id, 'playfair')
        
        # Create matrix for display
        matrix = create_playfair_matrix(key)
        
        # Prepare digraphs for visualization
        clean_text = ''.join(filter(str.isalpha, text.upper()))
        clean_text = clean_text.replace('J', 'I')
        
        # Check for same letters and add padding
        prepared_text = []
        i = 0
        while i < len(clean_text):
            if i + 1 < len(clean_text):
                if clean_text[i] == clean_text[i + 1]:
                    prepared_text.append(clean_text[i] + 'X')
                    i += 1
                else:
                    prepared_text.append(clean_text[i] + clean_text[i + 1])
                    i += 2
            else:
                prepared_text.append(clean_text[i] + 'X')
                i += 1
        
        # Calculate stats
        alphabetic_chars = sum(1 for c in text if c.isalpha())
        
        return jsonify({
            'success': True,
            'result': result,
            'key': key,
            'mode': mode,
            'matrix': matrix,
            'prepared_text': prepared_text[:10],  # First 10 digraphs only
            'stats': {
                'text_length': len(text),
                'alphabetic_chars': alphabetic_chars,
                'digraphs': len(prepared_text),
                'key_length': len(prepare_playfair_key(key)),
                'result_length': len(result),
                'matrix_size': '5x5',
                'unique_key_chars': len(set(prepare_playfair_key(key)))
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/playfair/matrix', methods=['POST'])
@login_required
def api_playfair_matrix():
    """API untuk mendapatkan matriks Playfair"""
    data = request.get_json()
    key = data.get('key', 'PLAYFAIR')
    
    try:
        matrix = create_playfair_matrix(key)
        analysis = analyze_playfair_key(key)
        
        return jsonify({
            'success': True,
            'matrix': matrix,
            'analysis': analysis
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/hill', methods=['POST'])
@login_required
def api_hill():
    """API endpoint for Hill Cipher operations"""
    data = request.get_json()
    text = data.get('text', '')
    key_matrix = data.get('key_matrix', [])
    mode = data.get('mode', 'encrypt')
    
    try:
        # Validasi input
        if not text:
            return jsonify({'success': False, 'error': 'Masukkan teks terlebih dahulu!'}), 400
        
        if not key_matrix:
            return jsonify({'success': False, 'error': 'Masukkan matriks kunci!'}), 400
        
        # Validasi matriks
        is_valid, message = validate_hill_key(key_matrix)
        if not is_valid:
            return jsonify({'success': False, 'error': message}), 400
        
        # Eksekusi enkripsi/dekripsi
        if mode == 'encrypt':
            result = hill_encrypt(text, key_matrix)
        elif mode == 'decrypt':
            result = hill_decrypt(text, key_matrix)
        else:
            return jsonify({'success': False, 'error': 'Mode harus "encrypt" atau "decrypt"'}), 400
        
        # Log penggunaan
        log_cipher_usage(current_user.id, 'hill')
        
        # Analisis matriks
        analysis = analyze_hill_key(key_matrix)
        
        # Visualisasi proses
        size = len(key_matrix)
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        
        # Contoh perhitungan untuk blok pertama
        process_steps = []
        if len(clean_text) >= size:
            block = clean_text[:size]
            block_numbers = convert_text_to_numbers(block)
            
            if mode == 'encrypt':
                encrypted_block = matrix_multiply(key_matrix, block_numbers)
                process_steps.append({
                    'block': block,
                    'block_numbers': block_numbers,
                    'matrix': key_matrix,
                    'result_numbers': encrypted_block,
                    'result_text': convert_numbers_to_text(encrypted_block)
                })
            else:
                inv_matrix = calculate_matrix_mod_inverse(key_matrix)
                if inv_matrix:
                    decrypted_block = matrix_multiply(inv_matrix, block_numbers)
                    process_steps.append({
                        'block': block,
                        'block_numbers': block_numbers,
                        'inverse_matrix': inv_matrix,
                        'result_numbers': decrypted_block,
                        'result_text': convert_numbers_to_text(decrypted_block)
                    })
        
        return jsonify({
            'success': True,
            'result': result,
            'mode': mode,
            'matrix_size': size,
            'analysis': analysis,
            'process_steps': process_steps,
            'stats': {
                'text_length': len(text),
                'clean_text_length': len(clean_text),
                'result_length': len(result),
                'blocks': len(clean_text) // size + (1 if len(clean_text) % size != 0 else 0),
                'determinant': analysis['determinant'],
                'invertible': analysis['invertible']
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/hill/validate', methods=['POST'])
@login_required
def api_validate_hill_matrix():
    """API untuk validasi matriks Hill Cipher"""
    data = request.get_json()
    key_matrix = data.get('key_matrix', [])
    
    try:
        is_valid, message = validate_hill_key(key_matrix)
        analysis = analyze_hill_key(key_matrix)
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'message': message,
            'analysis': analysis
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/hill/inverse', methods=['POST'])
@login_required
def api_calculate_matrix_inverse():
    """API untuk menghitung invers matriks"""
    data = request.get_json()
    key_matrix = data.get('key_matrix', [])
    
    try:
        inv_matrix = calculate_matrix_mod_inverse(key_matrix)
        
        if inv_matrix is None:
            return jsonify({
                'success': False,
                'error': 'Matriks tidak invertible modulo 26'
            }), 400
        
        return jsonify({
            'success': True,
            'inverse_matrix': inv_matrix,
            'original_matrix': key_matrix,
            'determinant': calculate_matrix_determinant(key_matrix)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/quiz/hill/challenges')
@login_required
def get_hill_challenges():
    """Get Hill cipher challenges"""
    challenges = Challenge.query.filter_by(cipher_name='hill').all()
    challenges_data = []
    for c in challenges:
        challenges_data.append({
            'id': c.id,
            'title': c.title,
            'description': c.description,
            'content': c.ciphertext,
            'plaintext': c.plaintext,
            'hint': c.hint,
            'difficulty': c.difficulty,
            'xp': c.xp_reward,
            'category': c.category,
            'key_matrix': c.plaintext if c.category == 'matrix' else None
        })
    return jsonify(challenges_data)

@app.route('/api/challenge/hill/submit', methods=['POST'])
@login_required
def submit_hill_challenge():
    """Submit Hill cipher challenge answer"""
    data = request.get_json()
    challenge_id = data.get('challengeId')
    user_answer = data.get('answer', '').strip().upper()
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'error': 'Challenge not found'}), 404
    
    if challenge.cipher_name != 'hill':
        return jsonify({'success': False, 'error': 'Invalid cipher challenge'}), 400
    
    existing_attempt = ChallengeAttempt.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if existing_attempt and existing_attempt.completed:
        return jsonify({'success': False, 'error': 'Challenge already completed'}), 400
    
    is_correct = False
    
    if challenge.category == 'encryption':
        # Untuk enkripsi, bandingkan dengan ciphertext
        is_correct = (user_answer == challenge.ciphertext.upper())
    elif challenge.category == 'decryption':
        # Untuk dekripsi, bandingkan dengan plaintext
        is_correct = (user_answer == challenge.plaintext.upper())
    elif challenge.category == 'matrix':
        # Untuk matriks, evaluasi sebagai array
        try:
            # Coba parse sebagai matriks
            import ast
            user_matrix = ast.literal_eval(user_answer)
            correct_matrix = ast.literal_eval(challenge.plaintext)
            
            # Bandingkan matriks
            is_correct = (str(user_matrix) == str(correct_matrix))
        except:
            # Jika gagal parse, bandingkan string biasa
            is_correct = (user_answer == challenge.plaintext.upper())
    elif challenge.category == 'analysis':
        # Untuk analisis, toleransi lebih longgar
        is_correct = (user_answer.replace(' ', '') == challenge.plaintext.replace(' ', '').upper())
    else:
        is_correct = (user_answer == challenge.plaintext.upper())
    
    if existing_attempt:
        existing_attempt.attempts += 1
        if is_correct and not existing_attempt.completed:
            existing_attempt.completed = True
            existing_attempt.completed_at = datetime.now()
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    else:
        attempt = ChallengeAttempt(
            user_id=current_user.id,
            challenge_id=challenge_id,
            attempts=1,
            completed=is_correct,
            completed_at=datetime.now() if is_correct else None
        )
        db.session.add(attempt)
        if is_correct:
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'isCorrect': is_correct,
        'xpEarned': challenge.xp_reward if is_correct else 0,
        'correctAnswer': challenge.plaintext.upper() if challenge.category == 'decryption' else challenge.ciphertext.upper(),
        'hint': challenge.hint if not is_correct else '',
        'totalXP': get_user_progress(current_user.id).xp,
        'message': '🎉 Jawaban benar! Anda mendapatkan ' + str(challenge.xp_reward) + ' XP!' if is_correct else '❌ Jawaban salah. Coba lagi!'
    })

# =============== QUIZ DATA INITIALIZATION ===============
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
            {
                'question': 'Siapa yang pertama kali mendeskripsikan Vigenere Cipher?',
                'option_a': 'Blaise de Vigenère',
                'option_b': 'Giovan Battista Bellaso',
                'option_c': 'Julius Caesar',
                'option_d': 'Alan Turing',
                'correct_answer': 'B',
                'explanation': 'Meski bernama Vigenere, cipher ini pertama kali dideskripsikan oleh Giovan Battista Bellaso pada tahun 1553.',
                'difficulty': 'medium',
                'xp_reward': 20
            },
            {
                'question': 'Berapa jumlah kemungkinan kunci untuk Vigenere Cipher dengan panjang kunci 5?',
                'option_a': '26',
                'option_b': '26^5 (11,881,376)',
                'option_c': '5^26',
                'option_d': 'Tidak terbatas',
                'correct_answer': 'B',
                'explanation': 'Setiap posisi dalam kunci memiliki 26 kemungkinan (A-Z), jadi untuk kunci panjang 5 ada 26^5 = 11,881,376 kemungkinan.',
                'difficulty': 'medium',
                'xp_reward': 20
            },
            {
                'question': 'Mengapa Vigenere Cipher disebut "le chiffre indéchiffrable"?',
                'option_a': 'Karena tidak mungkin dipecahkan',
                'option_b': 'Karena tetap tak terpecahkan selama 300 tahun',
                'option_c': 'Karena menggunakan matematika kuantum',
                'option_d': 'Karena hanya penemu yang tahu caranya',
                'correct_answer': 'B',
                'explanation': 'Vigenere Cipher dijuluki "cipher tak terpecahkan" karena bertahan tanpa terpecahkan selama sekitar 300 tahun.',
                'difficulty': 'easy',
                'xp_reward': 15
            },
            {
                'question': 'Dengan kunci "KEY", apa hasil enkripsi "HELLO" menggunakan Vigenere Cipher?',
                'option_a': 'RIJVS',
                'option_b': 'KHOOR',
                'option_c': 'OLSSV',
                'option_d': 'DHZZL',
                'correct_answer': 'A',
                'explanation': 'H(7) + K(10) = R(17), E(4) + E(4) = I(8), L(11) + Y(24) = J(9), L(11) + K(10) = V(21), O(14) + E(4) = S(18) → RIJVS',
                'difficulty': 'hard',
                'xp_reward': 25
            }
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
    
    if QuizQuestion.query.filter_by(cipher_name='caesar').count() == 0:
        caesar_questions = [
            {
                'question': 'Berapa jumlah kemungkinan kunci dalam Caesar Cipher?',
                'option_a': '25',
                'option_b': '26', 
                'option_c': '27',
                'option_d': 'Tidak terbatas',
                'correct_answer': 'A',
                'explanation': 'Caesar Cipher hanya memiliki 25 kemungkinan kunci yang valid (shift 1-25). Shift 0 tidak mengubah teks.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Jika shift = 3, huruf "X" akan menjadi?',
                'option_a': 'A',
                'option_b': 'B',
                'option_c': 'C',
                'option_d': 'Z',
                'correct_answer': 'B',
                'explanation': 'X (24) + 3 = 27, 27 mod 26 = 1 → B',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Siapa yang pertama kali menggunakan Caesar Cipher?',
                'option_a': 'Albert Einstein',
                'option_b': 'Julius Caesar',
                'option_c': 'Alan Turing',
                'option_d': 'Leonardo da Vinci',
                'correct_answer': 'B',
                'explanation': 'Julius Caesar (100-44 SM) menggunakan cipher ini untuk mengamankan pesan militer Romawi.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
        ]
        for q in caesar_questions:
            question = QuizQuestion(
                cipher_name='caesar',
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
    
    if QuizQuestion.query.filter_by(cipher_name='substitution').count() == 0:
        substitution_questions = [
            {
                'question': 'Apa yang dimaksud dengan Substitution Cipher?',
                'option_a': 'Cipher yang mengganti setiap huruf dengan huruf lain berdasarkan tabel substitusi',
                'option_b': 'Cipher yang menggeser setiap huruf sejumlah posisi tertentu',
                'option_c': 'Cipher yang menggunakan multiple keys untuk enkripsi',
                'option_d': 'Cipher yang mengacak posisi huruf tanpa mengubah huruf itu sendiri',
                'correct_answer': 'A',
                'explanation': 'Substitution Cipher mengganti setiap huruf plaintext dengan huruf ciphertext berdasarkan tabel substitusi yang tetap.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Berapa banyak kemungkinan key untuk Substitution Cipher?',
                'option_a': '26 (jumlah huruf alphabet)',
                'option_b': '26! (faktorial dari 26)',
                'option_c': '2²⁶ (2 pangkat 26)',
                'option_d': '26²⁶ (26 pangkat 26)',
                'correct_answer': 'B',
                'explanation': 'Substitution Cipher memiliki 26! kemungkinan key karena setiap huruf harus dipetakan ke huruf yang berbeda (permutasi).',
                'difficulty': 'medium',
                'xp_reward': 15
            },
            {
                'question': 'Teknik apa yang efektif untuk memecahkan Substitution Cipher?',
                'option_a': 'Brute force attack',
                'option_b': 'Frequency analysis',
                'option_c': 'Timing attack',
                'option_d': 'Man-in-the-middle attack',
                'correct_answer': 'B',
                'explanation': 'Frequency analysis efektif karena pola frekuensi huruf dalam bahasa tetap terlihat meski sudah dienkripsi.',
                'difficulty': 'medium',
                'xp_reward': 15
            },
            {
                'question': 'Apa kelemahan utama Substitution Cipher?',
                'option_a': 'Key yang terlalu pendek',
                'option_b': 'Mudah dipecahkan dengan frequency analysis',
                'option_c': 'Hanya bisa mengenkripsi teks pendek',
                'option_d': 'Tidak bisa mendukung huruf besar dan kecil',
                'correct_answer': 'B',
                'explanation': 'Kelemahan utama adalah kerentanannya terhadap frequency analysis karena pola statistik bahasa tetap ada.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Apa perbedaan antara Monoalphabetic dan Polyalphabetic Substitution?',
                'option_a': 'Monoalphabetic menggunakan satu alphabet, Polyalphabetic menggunakan multiple alphabets',
                'option_b': 'Monoalphabetic lebih aman daripada Polyalphabetic',
                'option_c': 'Polyalphabetic hanya bisa mengenkripsi angka',
                'option_d': 'Tidak ada perbedaan, keduanya sama',
                'correct_answer': 'A',
                'explanation': 'Monoalphabetic menggunakan satu mapping tetap, sedangkan Polyalphabetic menggunakan multiple mappings secara bergantian.',
                'difficulty': 'hard',
                'xp_reward': 20
            },
            {
                'question': 'Contoh cipher apa yang termasuk Substitution Cipher?',
                'option_a': 'Caesar Cipher',
                'option_b': 'Rail Fence Cipher',
                'option_c': 'Columnar Transposition',
                'option_d': 'Playfair Cipher',
                'correct_answer': 'A',
                'explanation': 'Caesar Cipher adalah bentuk paling sederhana dari Substitution Cipher.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Dalam bahasa Inggris, huruf apa yang paling sering muncul?',
                'option_a': 'E',
                'option_b': 'T',
                'option_c': 'A',
                'option_d': 'O',
                'correct_answer': 'A',
                'explanation': 'Huruf E muncul sekitar 12.7% dari semua huruf dalam teks bahasa Inggris.',
                'difficulty': 'medium',
                'xp_reward': 15
            },
            {
                'question': 'Bagaimana cara kerja Keyword Cipher?',
                'option_a': 'Keyword digunakan sebagai awal dari cipher alphabet, diikuti oleh sisa huruf',
                'option_b': 'Keyword menentukan jumlah shift untuk setiap huruf',
                'option_c': 'Keyword diulang-ulang untuk mencocokkan panjang plaintext',
                'option_d': 'Keyword di-reverse untuk membuat cipher alphabet',
                'correct_answer': 'A',
                'explanation': 'Keyword Cipher menggunakan keyword unik sebagai awal cipher alphabet, kemudian sisa huruf ditambahkan dalam urutan normal.',
                'difficulty': 'medium',
                'xp_reward': 15
            }
        ]
        
        for q in substitution_questions:
            question = QuizQuestion(
                cipher_name='substitution',
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
    
    if QuizQuestion.query.filter_by(cipher_name='transposition').count() == 0:
        transposition_questions = [
            {
                'question': 'Apa yang dimaksud dengan Transposition Cipher?',
                'option_a': 'Cipher yang mengganti setiap huruf dengan huruf lain',
                'option_b': 'Cipher yang mengacak posisi huruf tanpa mengubah huruf itu sendiri',
                'option_c': 'Cipher yang menggunakan kunci matematis kompleks',
                'option_d': 'Cipher yang mengubah huruf menjadi angka',
                'correct_answer': 'B',
                'explanation': 'Transposition Cipher mengacak urutan huruf (posisi) tanpa mengubah huruf itu sendiri.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Contoh cipher transposition tertua adalah?',
                'option_a': 'Skytale cipher dari Sparta',
                'option_b': 'Caesar cipher dari Romawi',
                'option_c': 'Vigenère cipher dari Prancis',
                'option_d': 'RSA cipher dari Amerika',
                'correct_answer': 'A',
                'explanation': 'Skytale cipher digunakan oleh Sparta sekitar 400 SM untuk mengirim pesan rahasia dalam perang.',
                'difficulty': 'medium',
                'xp_reward': 15
            },
            {
                'question': 'Bagaimana cara kerja Rail Fence Cipher?',
                'option_a': 'Menulis teks dalam pola zigzag pada multiple rails',
                'option_b': 'Menggeser setiap huruf beberapa posisi',
                'option_c': 'Mengganti huruf berdasarkan tabel substitusi',
                'option_d': 'Menggunakan kunci untuk multiple alphabets',
                'correct_answer': 'A',
                'explanation': 'Rail Fence menulis teks dalam pola zigzag, kemudian membaca per baris untuk mendapatkan ciphertext.',
                'difficulty': 'easy',
                'xp_reward': 10
            },
            {
                'question': 'Apa parameter utama dalam Columnar Transposition?',
                'option_a': 'Jumlah rails',
                'option_b': 'Keyword untuk menentukan urutan kolom',
                'option_c': 'Ukuran spiral',
                'option_d': 'Jumlah shift',
                'correct_answer': 'B',
                'explanation': 'Keyword menentukan jumlah kolom dan urutan pembacaan kolom dalam Columnar Transposition.',
                'difficulty': 'medium',
                'xp_reward': 15
            },
            {
                'question': 'Mengapa Transposition Cipher rentan terhadap kriptanalisis?',
                'option_a': 'Karena frekuensi karakter tetap sama seperti plaintext',
                'option_b': 'Karena hanya memiliki 26 kemungkinan kunci',
                'option_c': 'Karena menggunakan matematika sederhana',
                'option_d': 'Karena mudah diimplementasikan',
                'correct_answer': 'A',
                'explanation': 'Karena hanya mengubah posisi, frekuensi karakter tetap sama - ini membantu kriptanalis.',
                'difficulty': 'hard',
                'xp_reward': 20
            },
            {
                'question': 'Apa perbedaan utama antara Substitution dan Transposition cipher?',
                'option_a': 'Substitution mengubah huruf, Transposition mengubah posisi',
                'option_b': 'Substitution lebih aman daripada Transposition',
                'option_c': 'Transposition lebih tua daripada Substitution',
                'option_d': 'Tidak ada perbedaan',
                'correct_answer': 'A',
                'explanation': 'Substitution mengubah identitas huruf, Transposition hanya mengubah posisinya.',
                'difficulty': 'medium',
                'xp_reward': 15
            },
            {
                'question': 'Dengan 3 rails, apa hasil enkripsi "HELLO" menggunakan Rail Fence?',
                'options': [
                    'HOLEL',
                    'HLOEL',
                    'HELLO',
                    'OLLEH'
                ],
                'correct_answer': 'A',
                'explanation': 'H dan L di rail 1, E dan O di rail 2, L di rail 3 → dibaca: H O L E L',
                'difficulty': 'hard',
                'xp_reward': 20
            },
            {
                'question': 'Teknik apa yang efektif untuk memecahkan Transposition Cipher?',
                'options': [
                    'Anagram solving dan pattern analysis',
                    'Brute force semua kemungkinan shift',
                    'Frequency analysis sederhana',
                    'Dictionary attack saja'
                ],
                'correct_answer': 'A',
                'explanation': 'Anagram solving mencari permutasi yang membentuk kata-kata bermakna, pattern analysis mencari pola dalam ciphertext.',
                'difficulty': 'medium',
                'xp_reward': 15
            }
        ]
        
        for q in transposition_questions:
            question = QuizQuestion(
                cipher_name='transposition',
                question=q['question'],
                option_a=q.get('options', [''])[0] if 'options' in q else q.get('option_a', ''),
                option_b=q.get('options', [''])[1] if 'options' in q else q.get('option_b', ''),
                option_c=q.get('options', [''])[2] if 'options' in q else q.get('option_c', ''),
                option_d=q.get('options', [''])[3] if 'options' in q else q.get('option_d', ''),
                correct_answer=q['correct_answer'],
                explanation=q['explanation'],
                difficulty=q['difficulty'],
                xp_reward=q['xp_reward']
            )
            db.session.add(question)

        # Tambahkan setelah quiz transposition
    if QuizQuestion.query.filter_by(cipher_name='playfair').count() == 0:
        playfair_questions = [
            {
                'question': 'Playfair Cipher menggunakan matriks berapa?',
                'option_a': '4x4',
                'option_b': '5x5',
                'option_c': '6x6',
                'option_d': '7x7',
                'correct_answer': 'B',
                'explanation': 'Playfair Cipher menggunakan matriks 5x5 untuk mengakomodasi 26 huruf alfabet (I dan J digabung).',
                'difficulty': 'easy',
                'xp_reward': 15
            },
            {
                'question': 'Bagaimana Playfair menangani huruf J?',
                'option_a': 'Diabaikan',
                'option_b': 'Diganti dengan I',
                'option_c': 'Ditempatkan di sel terpisah',
                'option_d': 'Tidak diperbolehkan dalam teks',
                'correct_answer': 'B',
                'explanation': 'Dalam Playfair Cipher, huruf J diganti dengan I karena matriks 5x5 hanya memiliki 25 sel.',
                'difficulty': 'easy',
                'xp_reward': 15
            },
            {
                'question': 'Apa yang dilakukan jika dua huruf dalam digraph sama?',
                'option_a': 'Diabaikan salah satu',
                'option_b': 'Ditambahkan X di antaranya',
                'option_c': 'Diganti dengan Z',
                'option_d': 'Digeser satu posisi',
                'correct_answer': 'B',
                'explanation': 'Jika dua huruf sama, Playfair menyisipkan X (atau Q) di antaranya untuk membentuk digraph yang valid.',
                'difficulty': 'medium',
                'xp_reward': 20
            },
            {
                'question': 'Bagaimana enkripsi jika dua huruf berada di baris yang sama?',
                'option_a': 'Tukar kolom',
                'option_b': 'Geser kanan',
                'option_c': 'Geser kiri',
                'option_d': 'Tetap sama',
                'correct_answer': 'B',
                'explanation': 'Jika dalam baris yang sama, ambil huruf di kanan masing-masing (wrap-around jika di kolom terakhir).',
                'difficulty': 'medium',
                'xp_reward': 20
            },
            {
                'question': 'Siapa yang menemukan Playfair Cipher?',
                'option_a': 'Charles Wheatstone',
                'option_b': 'Lord Playfair',
                'option_c': 'Julius Caesar',
                'option_d': 'Blaise de Vigenère',
                'correct_answer': 'A',
                'explanation': 'Ditemukan oleh Charles Wheatstone pada 1854, namun dipopulerkan oleh Lord Playfair.',
                'difficulty': 'easy',
                'xp_reward': 15
            },
            {
                'question': 'Mengapa Playfair lebih aman daripada Caesar Cipher?',
                'option_a': 'Mengenkripsi per digraph, bukan per huruf',
                'option_b': 'Menggunakan matriks yang kompleks',
                'option_c': 'Memiliki kunci yang sangat panjang',
                'option_d': 'Menggunakan matematika kuantum',
                'correct_answer': 'A',
                'explanation': 'Playfair mengenkripsi pasangan huruf (digraph), sehingga frekuensi huruf tunggal sulit dianalisis.',
                'difficulty': 'medium',
                'xp_reward': 20
            },
            {
                'question': 'Apa yang dilakukan jika panjang plaintext ganjil?',
                'option_a': 'Dihapus huruf terakhir',
                'option_b': 'Ditambahkan X di akhir',
                'option_c': 'Digandakan huruf terakhir',
                'option_d': 'Ditambahkan spasi',
                'correct_answer': 'B',
                'explanation': 'Jika panjang ganjil, tambahkan X (atau Q) di akhir untuk membuat digraph lengkap.',
                'difficulty': 'easy',
                'xp_reward': 15
            },
            {
                'question': 'Berapa kemungkinan matriks Playfair yang berbeda?',
                'option_a': '25! (15.5×10²⁴)',
                'option_b': '26! (4×10²⁶)',
                'option_c': '25²⁵',
                'option_d': 'Tidak terbatas',
                'correct_answer': 'A',
                'explanation': 'Matriks 5x5 memiliki 25! kemungkinan pengaturan yang berbeda.',
                'difficulty': 'hard',
                'xp_reward': 25
            }
        ]
        
        for q in playfair_questions:
            question = QuizQuestion(
                cipher_name='playfair',
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

        if QuizQuestion.query.filter_by(cipher_name='hill').count() == 0:
            hill_questions = [
                {
                    'question': 'Apa yang dimaksud dengan Hill Cipher?',
                    'option_a': 'Cipher substitusi menggunakan kata kunci',
                    'option_b': 'Cipher blok yang menggunakan aljabar linear dan matriks',
                    'option_c': 'Cipher transposisi yang mengacak posisi huruf',
                    'option_d': 'Cipher modern berbasis kunci publik',
                    'correct_answer': 'B',
                    'explanation': 'Hill Cipher adalah cipher blok yang menggunakan perkalian matriks untuk enkripsi dan dekripsi.',
                    'difficulty': 'easy',
                    'xp_reward': 15
                },
                {
                    'question': 'Siapa yang menemukan Hill Cipher?',
                    'option_a': 'Lester S. Hill',
                    'option_b': 'Giovan Battista Bellaso',
                    'option_c': 'Blaise de Vigenère',
                    'option_d': 'Claude Shannon',
                    'correct_answer': 'A',
                    'explanation': 'Hill Cipher ditemukan oleh Lester S. Hill pada tahun 1929.',
                    'difficulty': 'easy',
                    'xp_reward': 15
                },
                {
                    'question': 'Syarat apa yang harus dipenuhi oleh matriks kunci Hill Cipher?',
                    'option_a': 'Determinan harus genap',
                    'option_b': 'Determinan harus ganjil',
                    'option_c': 'Determinan harus coprime dengan 26',
                    'option_d': 'Determinan harus prima',
                    'correct_answer': 'C',
                    'explanation': 'Determinan matriks kunci harus coprime dengan 26 (gcd(det, 26) = 1) agar matriks invertible modulo 26.',
                    'difficulty': 'medium',
                    'xp_reward': 20
                },
                {
                    'question': 'Jika menggunakan matriks 2x2, berapa karakter yang dienkripsi sekaligus?',
                    'option_a': '1 karakter',
                    'option_b': '2 karakter',
                    'option_c': '3 karakter',
                    'option_d': '4 karakter',
                    'correct_answer': 'B',
                    'explanation': 'Hill Cipher dengan matriks nxn akan mengenkripsi blok n karakter sekaligus.',
                    'difficulty': 'easy',
                    'xp_reward': 15
                },
                {
                    'question': 'Apa kelemahan utama Hill Cipher?',
                    'option_a': 'Hanya bisa mengenkripsi angka',
                    'option_b': 'Vulnerable terhadap known-plaintext attack',
                    'option_c': 'Key space terlalu kecil',
                    'option_d': 'Tidak bisa mendukung huruf kecil',
                    'correct_answer': 'B',
                    'explanation': 'Hill Cipher rentan terhadap known-plaintext attack karena matriks kunci dapat ditemukan dengan aljabar linear.',
                    'difficulty': 'medium',
                    'xp_reward': 20
                },
                {
                    'question': 'Bagaimana cara mendapatkan matriks invers untuk dekripsi?',
                    'option_a': 'Transpose matriks kunci',
                    'option_b': 'Hitung invers modulo 26',
                    'option_c': 'Reverse urutan karakter kunci',
                    'option_d': 'Geser setiap elemen matriks',
                    'correct_answer': 'B',
                    'explanation': 'Dekripsi membutuhkan invers matriks modulo 26, bukan sekedar transpose.',
                    'difficulty': 'medium',
                    'xp_reward': 20
                },
                {
                    'question': 'Apa yang terjadi jika panjang teks bukan kelipatan ukuran matriks?',
                    'option_a': 'Enkripsi gagal',
                    'option_b': 'Ditambahkan padding karakter',
                    'option_c': 'Ukuran matriks disesuaikan',
                    'option_d': 'Hanya karakter pertama yang dienkripsi',
                    'correct_answer': 'B',
                    'explanation': 'Karakter padding (biasanya X) ditambahkan untuk membuat panjang teks kelipatan ukuran matriks.',
                    'difficulty': 'easy',
                    'xp_reward': 15
                },
                {
                    'question': 'Berapa banyak kemungkinan matriks kunci 2x2 untuk Hill Cipher?',
                    'option_a': '26⁴ (456,976)',
                    'option_b': '26! (4×10²⁶)',
                    'option_c': 'Semua matriks invertible modulo 26',
                    'option_d': 'Tidak terbatas',
                    'correct_answer': 'C',
                    'explanation': 'Hanya matriks yang invertible modulo 26 yang dapat digunakan, jumlahnya lebih sedikit dari 26⁴.',
                    'difficulty': 'hard',
                    'xp_reward': 25
                }
            ]
            
            for q in hill_questions:
                question = QuizQuestion(
                    cipher_name='hill',
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
            
    db.session.commit()

def init_challenges_data():
    """Initialize challenges for ciphers"""
    
    if Challenge.query.filter_by(cipher_name='vigenere').count() == 0:
        vigenere_challenges = [
            {
                'title': 'Vigenere Basic Encryption',
                'description': 'Encrypt the message "ATTACKATDAWN" using Vigenere cipher with key "LEMON"',
                'plaintext': 'ATTACKATDAWN',
                'ciphertext': vigenere_encrypt('ATTACKATDAWN', 'LEMON'),
                'hint': 'Key: LEMON. Each letter shifts according to corresponding key letter.',
                'difficulty': 'easy',
                'xp_reward': 15,
                'category': 'encryption'
            },
            {
                'title': 'Vigenere Decryption Challenge',
                'description': 'Decrypt the ciphertext "LXFOPVEFRNHR" which was encrypted with key "LEMON"',
                'plaintext': 'ATTACKATDAWN',
                'ciphertext': 'LXFOPVEFRNHR',
                'hint': 'Key: LEMON. Remember to reverse the shift for each letter.',
                'difficulty': 'medium',
                'xp_reward': 25,
                'category': 'decryption'
            },
            {
                'title': 'Vigenere with Spaces',
                'description': 'Encrypt "HELLO WORLD" using key "KEY"',
                'plaintext': 'HELLO WORLD',
                'ciphertext': vigenere_encrypt('HELLO WORLD', 'KEY'),
                'hint': 'Non-alphabetic characters (like spaces) remain unchanged.',
                'difficulty': 'easy',
                'xp_reward': 15,
                'category': 'encryption'
            },
            {
                'title': 'Vigenere Mixed Case',
                'description': 'Decrypt "Ri vs u amk" encrypted with key "CODE"',
                'plaintext': 'Hello World',
                'ciphertext': 'Ri vs u amk',
                'hint': 'Key: CODE. Case is preserved during encryption/decryption.',
                'difficulty': 'medium',
                'xp_reward': 25,
                'category': 'decryption'
            },
            {
                'title': 'Vigenere Long Text',
                'description': 'Encrypt the message "CRYPTOGRAPHY IS FUN" with key "SECRET"',
                'plaintext': 'CRYPTOGRAPHY IS FUN',
                'ciphertext': vigenere_encrypt('CRYPTOGRAPHY IS FUN', 'SECRET'),
                'hint': 'Key repeats: SECRETSECRETSEC...',
                'difficulty': 'medium',
                'xp_reward': 20,
                'category': 'encryption'
            }
        ]
        
        for c in vigenere_challenges:
            challenge = Challenge(
                cipher_name='vigenere',
                title=c['title'],
                description=c['description'],
                ciphertext=c['ciphertext'],
                plaintext=c['plaintext'],
                hint=c['hint'],
                difficulty=c['difficulty'],
                xp_reward=c['xp_reward'],
                category=c['category']
            )
            db.session.add(challenge)
    
    # Caesar Challenges
    if Challenge.query.filter_by(cipher_name='caesar').count() == 0:
        caesar_challenges = [
            {
                'title': 'Decrypt Pesan Rahasia',
                'description': 'Decrypt pesan berikut dengan shift = 3',
                'ciphertext': 'KHOOR ZRUOG',
                'plaintext': 'HELLO WORLD',
                'hint': 'Shift 3 berarti setiap huruf digeser 3 posisi ke kiri',
                'difficulty': 'easy',
                'xp_reward': 25,
                'category': 'decryption'
            },
            {
                'title': 'Cari Shift yang Digunakan',
                'description': 'Plaintext "CRYPTO" dienkripsi menjadi "FUBSWR". Berapa shift?',
                'ciphertext': 'FUBSWR',
                'plaintext': 'CRYPTO',
                'hint': 'C→F adalah pergeseran 3',
                'difficulty': 'easy',
                'xp_reward': 30,
                'category': 'analysis'
            },
        ]
        for c in caesar_challenges:
            challenge = Challenge(
                cipher_name='caesar',
                title=c['title'],
                description=c['description'],
                ciphertext=c['ciphertext'],
                plaintext=c['plaintext'],
                hint=c['hint'],
                difficulty=c['difficulty'],
                xp_reward=c['xp_reward'],
                category=c['category']
            )
            db.session.add(challenge)
    
    if Challenge.query.filter_by(cipher_name='substitution').count() == 0:
        substitution_challenges = [
            {
                'title': 'Basic Substitution Decryption',
                'description': 'Decrypt this ciphertext using the key: QWERTYUIOPASDFGHJKLZXCVBNM',
                'ciphertext': substitution_encrypt('HELLO WORLD', 'QWERTYUIOPASDFGHJKLZXCVBNM'),
                'plaintext': 'HELLO WORLD',
                'hint': 'Key: Q→A, W→B, E→C, R→D, T→E, Y→F, U→G, I→H, O→I, P→J, A→K, S→L, D→M, F→N, G→O, H→P, J→Q, K→R, L→S, Z→T, X→U, C→V, V→W, B→X, N→Y, M→Z',
                'difficulty': 'easy',
                'xp_reward': 25,
                'category': 'decryption'
            },
            {
                'title': 'Keyword Cipher Challenge',
                'description': 'Decrypt this message encrypted with keyword "SECRET"',
                'ciphertext': substitution_encrypt('CRYPTOGRAPHY IS FUN', 'SECRTABDFGHIJKLMNOPQUVWXYZ'),
                'plaintext': 'CRYPTOGRAPHY IS FUN',
                'hint': 'Keyword "SECRET" gives key: S E C R T A B D F G H I J K L M N O P Q U V W X Y Z',
                'difficulty': 'medium',
                'xp_reward': 50,
                'category': 'decryption'
            },
            {
                'title': 'Frequency Analysis Practice',
                'description': 'Use frequency analysis to decrypt this message',
                'ciphertext': 'QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD',
                'plaintext': 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG',
                'hint': 'Look for the most common letters - they might be E, T, or A',
                'difficulty': 'hard',
                'xp_reward': 75,
                'category': 'frequency_analysis'
            },
            {
                'title': 'Create Your Own Cipher',
                'description': 'Encrypt "SUCCESS" using key: AZERTYUIOPQSDFGHJKLMWXCVBN',
                'ciphertext': substitution_encrypt('SUCCESS', 'AZERTYUIOPQSDFGHJKLMWXCVBN'),
                'plaintext': 'SUCCESS',
                'hint': 'A→A, Z→B, E→C, R→D, T→E, Y→F, U→G, I→H, O→I, P→J, Q→K, S→L, D→M, F→N, G→O, H→P, J→Q, K→R, L→S, M→T, W→U, X→V, C→W, V→X, B→Y, N→Z',
                'difficulty': 'easy',
                'xp_reward': 30,
                'category': 'encryption'
            }
        ]
        
        for c in substitution_challenges:
            challenge = Challenge(
                cipher_name='substitution',
                title=c['title'],
                description=c['description'],
                ciphertext=c['ciphertext'],
                plaintext=c['plaintext'],
                hint=c['hint'],
                difficulty=c['difficulty'],
                xp_reward=c['xp_reward'],
                category=c['category']
            )
            db.session.add(challenge)
    
    if Challenge.query.filter_by(cipher_name='transposition').count() == 0:
        transposition_challenges = [
            {
                'title': 'Rail Fence Decryption Challenge',
                'description': 'Decrypt ciphertext yang dienkripsi dengan Rail Fence (3 rails)',
                'ciphertext': rail_fence_encrypt('HELLO', 3),
                'plaintext': 'HELLO',
                'hint': 'Gunakan 3 rails, pattern zigzag',
                'difficulty': 'easy',
                'xp_reward': 25,
                'category': 'decryption'
            },
            {
                'title': 'Columnar Transposition',
                'description': 'Encrypt teks berikut dengan keyword "CRYPTO"',
                'ciphertext': columnar_transposition_encrypt('WE ARE DISCOVERED', 'CRYPTO'),
                'plaintext': 'WE ARE DISCOVERED',
                'hint': 'Buat tabel 6 kolom (sesuai panjang keyword), baca per kolom berdasarkan urutan alfabet keyword',
                'difficulty': 'medium',
                'xp_reward': 50,
                'category': 'encryption'
            },
            {
                'title': 'Route Cipher Analysis',
                'description': 'Tebak plaintext dari ciphertext Route cipher 3×4 grid (column pattern)',
                'ciphertext': route_cipher_encrypt('ATTACK AT DAWN', 3, 4, 'column'),
                'plaintext': 'ATTACK AT DAWN',
                'hint': 'Coba baca per kolom',
                'difficulty': 'hard',
                'xp_reward': 75,
                'category': 'analysis'
            },
            {
                'title': 'Spiral Cipher',
                'description': 'Encrypt "CRYPTOGRAPHY" dengan spiral 4×4 searah jarum jam',
                'ciphertext': spiral_cipher_encrypt('CRYPTOGRAPHY', 4),
                'plaintext': 'CRYPTOGRAPHY',
                'hint': 'Isi grid 4×4 dengan spiral dari luar ke dalam searah jarum jam',
                'difficulty': 'medium',
                'xp_reward': 50,
                'category': 'encryption'
            }
        ]
        
        for c in transposition_challenges:
            challenge = Challenge(
                cipher_name='transposition',
                title=c['title'],
                description=c['description'],
                ciphertext=c['ciphertext'],
                plaintext=c['plaintext'],
                hint=c['hint'],
                difficulty=c['difficulty'],
                xp_reward=c['xp_reward'],
                category=c['category']
            )
            db.session.add(challenge)
    
    if Challenge.query.filter_by(cipher_name='playfair').count() == 0:
        playfair_challenges = [
            {
                'title': 'Playfair Basic Encryption',
                'description': 'Encrypt "HELLO WORLD" using Playfair cipher with key "PLAYFAIR"',
                'plaintext': 'HELLO WORLD',
                'ciphertext': playfair_encrypt('HELLO WORLD', 'PLAYFAIR'),
                'hint': 'Key: PLAYFAIR. Perhatikan bahwa "LL" dipisahkan dengan X.',
                'difficulty': 'easy',
                'xp_reward': 30,
                'category': 'encryption'
            },
            {
                'title': 'Playfair Decryption Challenge',
                'description': 'Decrypt "BM OD ZB XD NA BE KU DM UI XM MO UV IF" with key "PLAYFAIR EXAMPLE"',
                'plaintext': 'HIDE THE GOLD IN THE TREE STUMP',
                'ciphertext': 'BM OD ZB XD NA BE KU DM UI XM MO UV IF',
                'hint': 'Key: PLAYFAIR EXAMPLE. Ini adalah contoh klasik Playfair Cipher.',
                'difficulty': 'medium',
                'xp_reward': 50,
                'category': 'decryption'
            },
            {
                'title': 'Playfair Same Letter Handling',
                'description': 'Encrypt "BALLOON" using key "MONARCHY"',
                'plaintext': 'BALLOON',
                'ciphertext': playfair_encrypt('BALLOON', 'MONARCHY'),
                'hint': 'Huruf "L" berurutan akan dipisahkan dengan X menjadi "LX".',
                'difficulty': 'medium',
                'xp_reward': 40,
                'category': 'encryption'
            },
            {
                'title': 'Playfair Key Analysis',
                'description': 'Encrypt "CRYPTOGRAPHY" using key "KEYWORD"',
                'plaintext': 'CRYPTOGRAPHY',
                'ciphertext': playfair_encrypt('CRYPTOGRAPHY', 'KEYWORD'),
                'hint': 'Key: KEYWORD. Perhatikan bahwa "WORD" dihilangkan huruf duplikat.',
                'difficulty': 'easy',
                'xp_reward': 30,
                'category': 'encryption'
            },
            {
                'title': 'Military Playfair',
                'description': 'Decrypt "KX VY EZ TH" encrypted with key "MILITARY"',
                'plaintext': 'ATTACK NOW',
                'ciphertext': playfair_encrypt('ATTACK NOW', 'MILITARY'),
                'hint': 'Key: MILITARY. "TT" dipisahkan menjadi "TX T".',
                'difficulty': 'hard',
                'xp_reward': 60,
                'category': 'decryption'
            }
        ]
        
        for c in playfair_challenges:
            challenge = Challenge(
                cipher_name='playfair',
                title=c['title'],
                description=c['description'],
                ciphertext=c['ciphertext'],
                plaintext=c['plaintext'],
                hint=c['hint'],
                difficulty=c['difficulty'],
                xp_reward=c['xp_reward'],
                category=c['category']
            )
            db.session.add(challenge)  
    
    if Challenge.query.filter_by(cipher_name='hill').count() == 0:
        hill_challenges = [
            {
                'title': 'Hill Cipher Basic 2x2',
                'description': 'Encrypt "HELLO" using 2x2 matrix [[7, 8], [11, 11]]',
                'plaintext': 'HELLO',
                'ciphertext': hill_encrypt('HELLO', [[7, 8], [11, 11]]),
                'hint': 'Matriks 2x2: [[7, 8], [11, 11]]. Determinannya harus coprime dengan 26.',
                'difficulty': 'easy',
                'xp_reward': 30,
                'category': 'encryption'
            },
            {
                'title': 'Hill Decryption Challenge',
                'description': 'Decrypt "XMKDV" using inverse of matrix [[7, 8], [11, 11]]',
                'plaintext': 'HELLO',
                'ciphertext': 'XMKDV',
                'hint': 'Gunakan invers matriks modulo 26. Determinannya adalah 7*11 - 8*11 = -11 mod 26 = 15.',
                'difficulty': 'medium',
                'xp_reward': 50,
                'category': 'decryption'
            },
            {
                'title': 'Hill 3x3 Encryption',
                'description': 'Encrypt "CRYPTOGRAPHY" using 3x3 matrix [[6, 24, 1], [13, 16, 10], [20, 17, 15]]',
                'plaintext': 'CRYPTOGRAPHY',
                'ciphertext': hill_encrypt('CRYPTOGRAPHY', [[6, 24, 1], [13, 16, 10], [20, 17, 15]]),
                'hint': 'Matriks 3x3 harus invertible modulo 26. Enkripsi 3 karakter sekaligus.',
                'difficulty': 'hard',
                'xp_reward': 75,
                'category': 'encryption'
            },
            {
                'title': 'Matrix Inversion Practice',
                'description': 'Find the inverse of matrix [[3, 3], [2, 5]] modulo 26',
                'plaintext': '[[15, 17], [20, 9]]',
                'ciphertext': 'Inverse matrix challenge',
                'hint': 'Determinannya 3*5 - 3*2 = 9. Invers determinan mod 26 adalah 3 (karena 9*3=27≡1 mod 26).',
                'difficulty': 'hard',
                'xp_reward': 60,
                'category': 'matrix'
            },
            {
                'title': 'Known-plaintext Attack',
                'description': 'Given plaintext "CRYPTO" and ciphertext "XUQJHI", find the 2x2 key matrix',
                'plaintext': '[[2, 3], [1, 4]]',
                'ciphertext': 'XUQJHI',
                'hint': 'Solve linear equations: [2,17] * K = [23,20] and [15,19] * K = [16,7] mod 26',
                'difficulty': 'hard',
                'xp_reward': 80,
                'category': 'analysis'
            }
        ]
        
        for c in hill_challenges:
            challenge = Challenge(
                cipher_name='hill',
                title=c['title'],
                description=c['description'],
                ciphertext=c['ciphertext'],
                plaintext=c['plaintext'],
                hint=c['hint'],
                difficulty=c['difficulty'],
                xp_reward=c['xp_reward'],
                category=c['category']
            )
            db.session.add(challenge)

    db.session.commit()

# =============== QUIZ API ROUTES ===============
@app.route('/api/quiz/hill/questions')
@login_required
def get_hill_quiz():
    """Get Hill cipher quiz questions"""
    questions = QuizQuestion.query.filter_by(cipher_name='hill').all()
    quiz_data = []
    for q in questions:
        quiz_data.append({
            'id': q.id,
            'question': q.question,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d],
            'correct': ['A', 'B', 'C', 'D'].index(q.correct_answer),
            'explanation': q.explanation,
            'difficulty': q.difficulty,
            'points': q.xp_reward
        })
    return jsonify(quiz_data)

@app.route('/api/quiz/caesar/questions')
def get_caesar_quiz():
    questions = QuizQuestion.query.filter_by(cipher_name='caesar').all()
    quiz_data = []
    for q in questions:
        quiz_data.append({
            'id': q.id,
            'question': q.question,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d],
            'correct': ['A', 'B', 'C', 'D'].index(q.correct_answer),
            'explanation': q.explanation,
            'difficulty': q.difficulty,
            'points': q.xp_reward
        })
    return jsonify(quiz_data)

@app.route('/api/quiz/vigenere/questions')
def get_vigenere_quiz():
    questions = QuizQuestion.query.filter_by(cipher_name='vigenere').all()
    quiz_data = []
    for q in questions:
        quiz_data.append({
            'id': q.id,
            'question': q.question,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d],
            'correct': ['A', 'B', 'C', 'D'].index(q.correct_answer),
            'explanation': q.explanation,
            'difficulty': q.difficulty,
            'points': q.xp_reward
        })
    return jsonify(quiz_data)

@app.route('/api/quiz/bruteforce/questions', methods=['GET'])
def get_bruteforce_quiz():
    quiz_data = [
        {
            'id': 1,
            'question': 'Berapa jumlah maksimal percobaan yang dibutuhkan untuk brute force Caesar Cipher?',
            'options': ['26', '52', '128', '256'],
            'correct': 0,
            'explanation': 'Caesar Cipher hanya memiliki 26 kemungkinan shift (0-25), jadi maksimal 26 percobaan.',
            'difficulty': 'easy',
            'points': 10
        },
        {
            'id': 2,
            'question': 'Mengapa brute force efektif untuk Caesar Cipher?',
            'options': [
                'Karena key space-nya kecil (hanya 26)',
                'Karena algoritmanya kompleks',
                'Karena menggunakan multiple keys',
                'Karena ciphertext-nya panjang'
            ],
            'correct': 0,
            'explanation': 'Brute force efektif ketika key space kecil. Caesar Cipher hanya punya 26 kemungkinan.',
            'difficulty': 'easy',
            'points': 10
        },
        {
            'id': 3,
            'question': 'Teknik apa yang digunakan untuk menentukan plaintext mana yang benar dari hasil brute force?',
            'options': [
                'Frequency analysis dan dictionary attack',
                'Only frequency analysis',
                'Only dictionary attack',
                'Random selection'
            ],
            'correct': 0,
            'explanation': 'Frequency analysis melihat distribusi huruf, dictionary attack mencari kata-kata umum.',
            'difficulty': 'medium',
            'points': 15
        },
    ]
    return jsonify(quiz_data)

@app.route('/api/quiz/caesar/challenges')
def get_caesar_challenges():
    challenges = Challenge.query.filter_by(cipher_name='caesar').all()
    challenges_data = []
    for c in challenges:
        challenges_data.append({
            'id': c.id,
            'title': c.title,
            'description': c.description,
            'ciphertext': c.ciphertext,
            'plaintext': c.plaintext,
            'hint': c.hint,
            'difficulty': c.difficulty,
            'xp': c.xp_reward,
            'category': c.category
        })
    return jsonify(challenges_data)

@app.route('/api/quiz/vigenere/challenges')
def get_vigenere_challenges():
    challenges = Challenge.query.filter_by(cipher_name='vigenere').all()
    challenges_data = []
    for c in challenges:
        challenges_data.append({
            'id': c.id,
            'title': c.title,
            'description': c.description,
            'ciphertext': c.ciphertext,
            'plaintext': c.plaintext,
            'hint': c.hint,
            'difficulty': c.difficulty,
            'xp': c.xp_reward,
            'category': c.category
        })
    return jsonify(challenges_data)

@app.route('/api/quiz/bruteforce/challenges', methods=['GET'])
def get_bruteforce_challenges():
    challenges = [
        {
            'id': 1,
            'title': 'Level 1: Dasar Caesar Cipher',
            'description': 'Coba pecahkan ciphertext dengan shift kecil',
            'content': 'IFMMP XPSME',
            'category': 'decryption',
            'difficulty': 'easy',
            'xp': 50,
            'hint': 'Shift antara 1-5',
            'answer': 'HELLO WORLD',
            'expected_shift': 1
        },
        {
            'id': 2,
            'title': 'Level 2: Kalimat Lengkap',
            'description': 'Decrypt kalimat dengan shift yang tidak diketahui',
            'content': 'OLSSV DVYSK HUK AOL TVYL',
            'category': 'decryption',
            'difficulty': 'medium',
            'xp': 100,
            'hint': 'Pikirkan tentang kata-kata umum bahasa Inggris',
            'answer': 'HELLO WORLD AND THE MOON',
            'expected_shift': 7
        },
    ]
    return jsonify(challenges)

@app.route('/api/quiz/submit', methods=['POST'])
@login_required
def submit_quiz():
    data = request.get_json()
    answers = data.get('answers', [])
    cipher_name = data.get('cipher', 'caesar')
    
    score = 0
    total_questions = len(answers)
    xp_earned = 0
    detailed_results = []
    
    for answer in answers:
        question_id = answer.get('questionId')
        selected_option = answer.get('selectedOption')
        
        if question_id is None or selected_option is None:
            continue
            
        question = QuizQuestion.query.get(question_id)
        if not question:
            continue
        
        correct_answer_index = ['A', 'B', 'C', 'D'].index(question.correct_answer)
        is_correct = (selected_option == correct_answer_index)
        
        if is_correct:
            score += 1
            xp_earned += question.xp_reward
        
        detailed_results.append({
            'questionId': question_id,
            'isCorrect': is_correct,
            'correctAnswer': correct_answer_index,
            'explanation': question.explanation,
            'points': question.xp_reward if is_correct else 0
        })
    
    if xp_earned > 0:
        update_user_xp(current_user.id, xp_earned, "quiz_completed")
    
    attempt = QuizAttempt(
        user_id=current_user.id,
        cipher_name=cipher_name,
        score=score,
        total_questions=total_questions
    )
    db.session.add(attempt)
    db.session.commit()
    
    percentage = (score / total_questions * 100) if total_questions > 0 else 0
    
    return jsonify({
        'success': True,
        'score': score,
        'totalQuestions': total_questions,
        'percentage': round(percentage, 1),
        'xpEarned': xp_earned,
        'totalXP': get_user_progress(current_user.id).xp,
        'level': get_user_progress(current_user.id).level,
        'detailedResults': detailed_results
    })

# =============== QUIZ API ROUTES ===============

@app.route('/api/quiz/transposition/questions')
@login_required
def get_transposition_quiz():
    """Get transposition cipher quiz questions"""
    questions = QuizQuestion.query.filter_by(cipher_name='transposition').all()
    quiz_data = []
    for q in questions:
        quiz_data.append({
            'id': q.id,
            'question': q.question,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d],
            'correct': ['A', 'B', 'C', 'D'].index(q.correct_answer),
            'explanation': q.explanation,
            'difficulty': q.difficulty,
            'points': q.xp_reward
        })
    return jsonify(quiz_data)

@app.route('/api/quiz/transposition/challenges')
@login_required
def get_transposition_challenges():
    """Get transposition cipher challenges"""
    challenges = Challenge.query.filter_by(cipher_name='transposition').all()
    challenges_data = []
    for c in challenges:
        challenges_data.append({
            'id': c.id,
            'title': c.title,
            'description': c.description,
            'content': c.ciphertext,
            'plaintext': c.plaintext,
            'hint': c.hint,
            'difficulty': c.difficulty,
            'xp': c.xp_reward,
            'category': c.category
        })
    return jsonify(challenges_data)

@app.route('/api/challenge/transposition/submit', methods=['POST'])
@login_required
def submit_transposition_challenge():
    """Submit transposition cipher challenge answer"""
    data = request.get_json()
    challenge_id = data.get('challengeId')
    user_answer = data.get('answer', '').strip().upper()
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'error': 'Challenge not found'}), 404
    
    # Check if this challenge belongs to transposition cipher
    if challenge.cipher_name != 'transposition':
        return jsonify({'success': False, 'error': 'Invalid cipher challenge'}), 400
    
    existing_attempt = ChallengeAttempt.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if existing_attempt and existing_attempt.completed:
        return jsonify({'success': False, 'error': 'Challenge already completed'}), 400
    
    is_correct = False
    if challenge.category == 'decryption':
        # For decryption, check if answer matches plaintext
        is_correct = (user_answer == challenge.plaintext.upper())
    elif challenge.category == 'encryption':
        # For encryption, check if answer matches ciphertext
        is_correct = (user_answer == challenge.ciphertext.upper())
    elif challenge.category == 'analysis':
        # For analysis, check if answer is close enough
        is_correct = (user_answer.replace(' ', '') == challenge.plaintext.replace(' ', '').upper())
    else:
        is_correct = (user_answer == challenge.plaintext.upper())
    
    if existing_attempt:
        existing_attempt.attempts += 1
        if is_correct and not existing_attempt.completed:
            existing_attempt.completed = True
            existing_attempt.completed_at = datetime.now()
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    else:
        attempt = ChallengeAttempt(
            user_id=current_user.id,
            challenge_id=challenge_id,
            attempts=1,
            completed=is_correct,
            completed_at=datetime.now() if is_correct else None
        )
        db.session.add(attempt)
        if is_correct:
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'isCorrect': is_correct,
        'xpEarned': challenge.xp_reward if is_correct else 0,
        'correctAnswer': challenge.plaintext.upper() if challenge.category == 'decryption' else challenge.ciphertext.upper(),
        'hint': challenge.hint if not is_correct else '',
        'totalXP': get_user_progress(current_user.id).xp,
        'message': '🎉 Jawaban benar! Anda mendapatkan ' + str(challenge.xp_reward) + ' XP!' if is_correct else '❌ Jawaban salah. Coba lagi!'
    })

@app.route('/api/challenge/submit', methods=['POST'])
@login_required
def submit_challenge():
    data = request.get_json()
    challenge_id = data.get('challengeId')
    user_answer = data.get('answer', '').strip().upper()
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'error': 'Challenge not found'}), 404
    
    existing_attempt = ChallengeAttempt.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if existing_attempt and existing_attempt.completed:
        return jsonify({'error': 'Challenge already completed'}), 400
    
    is_correct = False
    if challenge.category == 'decryption':
        is_correct = (user_answer == challenge.plaintext)
    elif challenge.category == 'analysis':
        try:
            user_shift = int(user_answer)
            decrypted = caesar_decrypt(challenge.ciphertext, user_shift)
            is_correct = (decrypted == challenge.plaintext)
        except:
            is_correct = False
    else:
        is_correct = (user_answer == challenge.plaintext)
    
    if existing_attempt:
        existing_attempt.attempts += 1
        if is_correct and not existing_attempt.completed:
            existing_attempt.completed = True
            existing_attempt.completed_at = datetime.now()
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    else:
        attempt = ChallengeAttempt(
            user_id=current_user.id,
            challenge_id=challenge_id,
            attempts=1,
            completed=is_correct,
            completed_at=datetime.now() if is_correct else None
        )
        db.session.add(attempt)
        if is_correct:
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    
    db.session.commit()
    
    return jsonify({
        'isCorrect': is_correct,
        'xpEarned': challenge.xp_reward if is_correct else 0,
        'correctAnswer': challenge.plaintext if challenge.category == 'decryption' else '',
        'hint': challenge.hint,
        'totalXP': get_user_progress(current_user.id).xp
    })

@app.route('/api/challenge/vigenere/submit', methods=['POST'])
@login_required
def submit_vigenere_challenge():
    data = request.get_json()
    challenge_id = data.get('challengeId')
    user_answer = data.get('answer', '').strip().upper()
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'error': 'Challenge not found'}), 404
    
    existing_attempt = ChallengeAttempt.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if existing_attempt and existing_attempt.completed:
        return jsonify({'success': False, 'error': 'Challenge already completed'}), 400
    
    is_correct = False
    if challenge.category == 'encryption':
        is_correct = (user_answer == challenge.ciphertext)
    elif challenge.category == 'decryption':
        is_correct = (user_answer == challenge.plaintext)
    else:
        is_correct = (user_answer == 'LEMON')
    
    if existing_attempt:
        existing_attempt.attempts += 1
        if is_correct and not existing_attempt.completed:
            existing_attempt.completed = True
            existing_attempt.completed_at = datetime.now()
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    else:
        attempt = ChallengeAttempt(
            user_id=current_user.id,
            challenge_id=challenge_id,
            attempts=1,
            completed=is_correct,
            completed_at=datetime.now() if is_correct else None
        )
        db.session.add(attempt)
        if is_correct:
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'isCorrect': is_correct,
        'xpEarned': challenge.xp_reward if is_correct else 0,
        'correctAnswer': challenge.plaintext if challenge.category == 'decryption' else '',
        'hint': challenge.hint,
        'totalXP': get_user_progress(current_user.id).xp
    })

@app.route('/api/quiz/substitution/questions')
@login_required
def get_substitution_quiz():
    """Get substitution cipher quiz questions"""
    questions = QuizQuestion.query.filter_by(cipher_name='substitution').all()
    quiz_data = []
    for q in questions:
        quiz_data.append({
            'id': q.id,
            'question': q.question,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d],
            'correct': ['A', 'B', 'C', 'D'].index(q.correct_answer),
            'explanation': q.explanation,
            'difficulty': q.difficulty,
            'points': q.xp_reward
        })
    return jsonify(quiz_data)

@app.route('/api/quiz/substitution/challenges')
@login_required
def get_substitution_challenges():
    """Get substitution cipher challenges"""
    challenges = Challenge.query.filter_by(cipher_name='substitution').all()
    challenges_data = []
    for c in challenges:
        challenges_data.append({
            'id': c.id,
            'title': c.title,
            'description': c.description,
            'content': c.ciphertext,
            'plaintext': c.plaintext,
            'hint': c.hint,
            'difficulty': c.difficulty,
            'xp': c.xp_reward,
            'category': c.category
        })
    return jsonify(challenges_data)

@app.route('/api/quiz/playfair/questions')
@login_required
def get_playfair_quiz():
    """Get Playfair cipher quiz questions"""
    questions = QuizQuestion.query.filter_by(cipher_name='playfair').all()
    quiz_data = []
    for q in questions:
        quiz_data.append({
            'id': q.id,
            'question': q.question,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d],
            'correct': ['A', 'B', 'C', 'D'].index(q.correct_answer),
            'explanation': q.explanation,
            'difficulty': q.difficulty,
            'points': q.xp_reward
        })
    return jsonify(quiz_data)

@app.route('/api/quiz/playfair/challenges')
@login_required
def get_playfair_challenges():
    """Get Playfair cipher challenges"""
    challenges = Challenge.query.filter_by(cipher_name='playfair').all()
    challenges_data = []
    for c in challenges:
        challenges_data.append({
            'id': c.id,
            'title': c.title,
            'description': c.description,
            'ciphertext': c.ciphertext,
            'plaintext': c.plaintext,
            'hint': c.hint,
            'difficulty': c.difficulty,
            'xp': c.xp_reward,
            'category': c.category
        })
    return jsonify(challenges_data)

@app.route('/api/challenge/playfair/submit', methods=['POST'])
@login_required
def submit_playfair_challenge():
    """Submit Playfair cipher challenge answer"""
    data = request.get_json()
    challenge_id = data.get('challengeId')
    user_answer = data.get('answer', '').strip().upper()
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'error': 'Challenge not found'}), 404
    
    if challenge.cipher_name != 'playfair':
        return jsonify({'success': False, 'error': 'Invalid cipher challenge'}), 400
    
    existing_attempt = ChallengeAttempt.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if existing_attempt and existing_attempt.completed:
        return jsonify({'success': False, 'error': 'Challenge already completed'}), 400
    
    is_correct = False
    if challenge.category == 'decryption':
        # For Playfair, remove spaces and compare
        is_correct = (user_answer.replace(' ', '') == challenge.plaintext.replace(' ', '').upper())
    elif challenge.category == 'encryption':
        # Allow for different formatting in ciphertext
        is_correct = (user_answer.replace(' ', '') == challenge.ciphertext.replace(' ', '').upper())
    else:
        is_correct = (user_answer == challenge.plaintext.upper())
    
    if existing_attempt:
        existing_attempt.attempts += 1
        if is_correct and not existing_attempt.completed:
            existing_attempt.completed = True
            existing_attempt.completed_at = datetime.now()
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    else:
        attempt = ChallengeAttempt(
            user_id=current_user.id,
            challenge_id=challenge_id,
            attempts=1,
            completed=is_correct,
            completed_at=datetime.now() if is_correct else None
        )
        db.session.add(attempt)
        if is_correct:
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'isCorrect': is_correct,
        'xpEarned': challenge.xp_reward if is_correct else 0,
        'correctAnswer': challenge.plaintext.upper() if challenge.category == 'decryption' else challenge.ciphertext.upper(),
        'hint': challenge.hint if not is_correct else '',
        'totalXP': get_user_progress(current_user.id).xp,
        'message': '🎉 Jawaban benar! Anda mendapatkan ' + str(challenge.xp_reward) + ' XP!' if is_correct else '❌ Jawaban salah. Coba lagi!'
    })

@app.route('/api/challenge/substitution/submit', methods=['POST'])
@login_required
def submit_substitution_challenge():
    """Submit substitution cipher challenge answer"""
    data = request.get_json()
    challenge_id = data.get('challengeId')
    user_answer = data.get('answer', '').strip().upper()
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'error': 'Challenge not found'}), 404
    
    # Check if this challenge belongs to substitution cipher
    if challenge.cipher_name != 'substitution':
        return jsonify({'success': False, 'error': 'Invalid cipher challenge'}), 400
    
    existing_attempt = ChallengeAttempt.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if existing_attempt and existing_attempt.completed:
        return jsonify({'success': False, 'error': 'Challenge already completed'}), 400
    
    is_correct = False
    if challenge.category == 'decryption':
        # For decryption, check if answer matches plaintext
        is_correct = (user_answer == challenge.plaintext.upper())
    elif challenge.category == 'encryption':
        # For encryption, check if answer matches ciphertext
        is_correct = (user_answer == challenge.ciphertext.upper())
    elif challenge.category == 'frequency_analysis':
        # For frequency analysis, check if answer is close enough
        # Allow some flexibility in answer
        is_correct = (user_answer.replace(' ', '') == challenge.plaintext.replace(' ', '').upper())
    else:
        is_correct = (user_answer == challenge.plaintext.upper())
    
    if existing_attempt:
        existing_attempt.attempts += 1
        if is_correct and not existing_attempt.completed:
            existing_attempt.completed = True
            existing_attempt.completed_at = datetime.now()
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    else:
        attempt = ChallengeAttempt(
            user_id=current_user.id,
            challenge_id=challenge_id,
            attempts=1,
            completed=is_correct,
            completed_at=datetime.now() if is_correct else None
        )
        db.session.add(attempt)
        if is_correct:
            update_user_xp(current_user.id, challenge.xp_reward, "challenge_completed")
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'isCorrect': is_correct,
        'xpEarned': challenge.xp_reward if is_correct else 0,
        'correctAnswer': challenge.plaintext.upper() if challenge.category == 'decryption' else challenge.ciphertext.upper(),
        'hint': challenge.hint if not is_correct else '',
        'totalXP': get_user_progress(current_user.id).xp,
        'message': '🎉 Jawaban benar! Anda mendapatkan ' + str(challenge.xp_reward) + ' XP!' if is_correct else '❌ Jawaban salah. Coba lagi!'
    })

@app.route('/api/challenge/bruteforce/submit', methods=['POST'])
def submit_bruteforce_challenge():
    try:
        data = request.get_json()
        challenge_id = data.get('challengeId')
        user_answer = data.get('answer', '').strip().upper()
        
        challenges = get_bruteforce_challenges().json
        challenge = next((c for c in challenges if c['id'] == challenge_id), None)
        
        if not challenge:
            return jsonify({'success': False, 'error': 'Challenge tidak ditemukan'})
        
        is_correct = user_answer == challenge['answer'].upper()
        xp_earned = challenge['xp'] if is_correct else 0
        
        return jsonify({
            'success': True,
            'isCorrect': is_correct,
            'correctAnswer': challenge['answer'],
            'expectedShift': challenge.get('expected_shift', 0),
            'xpEarned': xp_earned,
            'message': 'Jawaban benar!' if is_correct else 'Jawaban salah. Coba lagi!',
            'hint': challenge['hint'] if not is_correct else ''
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============== ERROR HANDLERS ===============
@app.errorhandler(401)
def unauthorized(e):
    flash('Anda tidak memiliki akses. Silakan login terlebih dahulu.', 'danger')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    flash('Akses ditolak.', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    flash('Halaman tidak ditemukan.', 'warning')
    return redirect(url_for('index'))

# =============== DATABASE INITIALIZATION ===============
def initialize_database():
    """Initialize database dengan data default"""
    print("🔧 Inisialisasi database...")
    db.create_all()
    print("✅ Tabel database dibuat")
    
    init_quiz_data()
    print("✅ Data quiz ditambahkan")
    
    init_challenges_data()
    print("✅ Data challenges ditambahkan")
    
    if Achievement.query.count() == 0:
        achievements = [
            Achievement(
                name='Caesar Novice',
                description='Selesaikan quiz Caesar Cipher pertama',
                icon='fas fa-crown',
                xp_reward=50,
                requirement='complete_caesar_quiz'
            ),
            Achievement(
                name='Shift Master',
                description='Selesaikan semua challenge Caesar Cipher',
                icon='fas fa-trophy',
                xp_reward=100,
                requirement='complete_all_caesar_challenges'
            ),
            Achievement(
                name='Vigenere Explorer',
                description='Selesaikan quiz Vigenere Cipher',
                icon='fas fa-key',
                xp_reward=75,
                requirement='complete_vigenere_quiz'
            ),
        ]
        
        for a in achievements:
            db.session.add(a)
        
        db.session.commit()
        print("✅ Data achievements ditambahkan")
    
    print("🎉 Database berhasil diinisialisasi!")

@app.route('/reset-db', methods=['GET', 'POST'])
def reset_database():
    """Route untuk reset database (HANYA UNTUK DEVELOPMENT!)"""
    if request.method == 'GET':
        return '''
        <h1>Reset Database</h1>
        <p>Ini akan menghapus semua data!</p>
        <form method="POST">
            <input type="hidden" name="confirm" value="yes">
            <button type="submit" style="background: red; color: white; padding: 10px 20px;">
                Reset Database
            </button>
        </form>
        '''
    
    if request.method == 'POST':
        try:
            db.drop_all()
            db.create_all()
            
            init_quiz_data()
            init_challenges_data()
            
            achievements = [
                Achievement(
                    name='Caesar Novice',
                    description='Selesaikan quiz Caesar Cipher pertama',
                    icon='fas fa-crown',
                    xp_reward=50,
                    requirement='complete_caesar_quiz'
                ),
                Achievement(
                    name='Shift Master',
                    description='Selesaikan semua challenge Caesar Cipher',
                    icon='fas fa-trophy',
                    xp_reward=100,
                    requirement='complete_all_caesar_challenges'
                ),
                Achievement(
                    name='Crypto Learner',
                    description='Gunakan 5 cipher berbeda',
                    icon='fas fa-graduation-cap',
                    xp_reward=150,
                    requirement='use_5_ciphers'
                )
            ]
            for ach in achievements:
                db.session.add(ach)
            
            db.session.commit()
            
            return '''
            <h1>Database Berhasil Direset!</h1>
            <p>Semua tabel telah di-recreate dengan schema baru.</p>
            <a href="/">Kembali ke Home</a>
            '''
            
        except Exception as e:
            return f'<h1>Error: {str(e)}</h1>'

# =============== MAIN ENTRY POINT ===============
if __name__ == '__main__':
    with app.app_context():
        initialize_database()
    
    app.run(debug=True, host='0.0.0.0', port=5000)