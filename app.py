from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
import os
import secrets
import bcrypt
from config import DevelopmentConfig, ProductionConfig


# ini tuh bagian inisialisasi aplikasi yaa
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Anda harus login terlebih dahulu untuk mengakses halaman ini.'
login_manager.login_message_category = 'warning'

# Argon2 hasher 
ph = PasswordHasher(
    time_cost=2,        # Iterasi
    memory_cost=65536,  # Memory dalam KB (64 MB)
    parallelism=4,      # Thread paralel
    hash_len=32,        # Panjang hash output
    salt_len=16         # Panjang salt
)

from flask_login import UserMixin

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def secure_logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Anda sudah logout.', 'info')
            return redirect(url_for('index'))
        
        # Hanya izinkan POST untuk melakukan logout dan validasi token sekali-pakai
        if request.method != 'POST':
            flash('Gunakan tombol logout (POST).', 'warning')
            return redirect(url_for('dashboard'))
        
        token = request.form.get('token')
        if not token or token != session.get('logout_token'):
            flash('Akses tidak valid. Gunakan tombol logout yang disediakan.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Token sekali-pakai: hapus setelah dipakai
        session.pop('logout_token', None)

        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def security_headers():
    protected_routes = [
        'substitution', 'transposition', 'playfair', 'hill', 'rsa', 'hash_func',
        'aes_page', 'des_page', 'triple_des_page', 'blowfish_page',
        'api_substitution', 'api_railfence', 'api_columnar', 'api_route',
        'api_playfair', 'api_playfair_matrix', 'api_hill', 'api_rsa_generate',
        'api_rsa_encrypt', 'api_rsa_decrypt', 'api_hash_generate', 
        'api_hash_compare', 'api_password_strength', 'api_bcrypt_hash',
        'api_argon2_hash', 'api_hash_compare_algos', 'api_aes', 'api_des',
        'api_triple_des', 'api_blowfish'
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
        
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            session.permanent = True
            session['logout_token'] = secrets.token_urlsafe(32)
            flash('Login berhasil!', 'success')
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah!', 'danger')
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@secure_logout_required
def logout():
    logout_user()
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if 'logout_token' not in session:
        session['logout_token'] = secrets.token_urlsafe(32)
    return render_template('dashboard.html', username=current_user.username, logout_token=session['logout_token'])

# Fitur Basic (Free)
@app.route('/caesar')
def caesar():
    return render_template('caesar.html')

@app.route('/vigenere')
def vigenere():
    return render_template('vigenere.html')

@app.route('/bruteforce')
def bruteforce():
    return render_template('bruteforce.html')

# Fitur Premium (Login Required)
@app.route('/substitution')
@login_required
def substitution():
    return render_template('substitution.html')

@app.route('/transposition')
@login_required
def transposition():
    return render_template('transposition.html')

@app.route('/playfair')
@login_required
def playfair():
    return render_template('playfair.html')

@app.route('/hill')
@login_required
def hill():
    return render_template('hill.html')

@app.route('/rsa')
@login_required
def rsa():
    return render_template('rsa.html')

@app.route('/hash')
@login_required
def hash_func():
    return render_template('hash.html')

# FITUR PREMIUM BARU - Modern Encryption
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

@app.route('/blowfish')
@login_required
def blowfish_page():
    return render_template('blowfish.html')

# API Endpoints - Basic (Free)
@app.route('/api/caesar', methods=['POST'])
def api_caesar():
    from utils.caesar import caesar_encrypt, caesar_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    shift = int(data.get('shift', 3))
    mode = data.get('mode', 'encrypt')
    
    if mode == 'encrypt':
        result = caesar_encrypt(text, shift)
    else:
        result = caesar_decrypt(text, shift)
    
    return {'result': result}

@app.route('/api/vigenere', methods=['POST'])
def api_vigenere():
    from utils.vigenere import vigenere_encrypt, vigenere_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    if mode == 'encrypt':
        result = vigenere_encrypt(text, key)
    else:
        result = vigenere_decrypt(text, key)
    
    return {'result': result}

@app.route('/api/bruteforce', methods=['POST'])
def api_bruteforce():
    from utils.bruteforce import bruteforce_caesar
    
    data = request.get_json()
    text = data.get('text', '')
    
    results = bruteforce_caesar(text)
    
    return {'results': results}

# API Endpoints - Premium (Login Required)
@app.route('/api/substitution', methods=['POST'])
@login_required
def api_substitution():
    from utils.substitution import substitution_encrypt, substitution_decrypt, key_from_keyword
    
    data = request.get_json()
    text = data.get('text', '')
    keyword = data.get('keyword', '')
    mode = data.get('mode', 'encrypt')
    
    key = key_from_keyword(keyword) if keyword else None
    
    if mode == 'encrypt':
        result, used_key = substitution_encrypt(text, key)
        return {'result': result, 'key': list(used_key.items())}
    else:
        key_dict = dict(data.get('key', [])) if data.get('key') else key
        result = substitution_decrypt(text, key_dict)
        return {'result': result}

@app.route('/api/transposition/railfence', methods=['POST'])
@login_required
def api_railfence():
    from utils.transposition import rail_fence_encrypt, rail_fence_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    rails = int(data.get('rails', 3))
    mode = data.get('mode', 'encrypt')
    
    if mode == 'encrypt':
        result = rail_fence_encrypt(text, rails)
    else:
        result = rail_fence_decrypt(text, rails)
    
    return {'result': result}

@app.route('/api/transposition/columnar', methods=['POST'])
@login_required
def api_columnar():
    from utils.transposition import columnar_transposition_encrypt, columnar_transposition_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    if mode == 'encrypt':
        result = columnar_transposition_encrypt(text, key)
    else:
        result = columnar_transposition_decrypt(text, key)
    
    return {'result': result}

@app.route('/api/transposition/route', methods=['POST'])
@login_required
def api_route():
    from utils.transposition import route_cipher_encrypt, route_cipher_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    rows = int(data.get('rows', 3))
    cols = int(data.get('cols', 4))
    mode = data.get('mode', 'encrypt')
    
    if mode == 'encrypt':
        result = route_cipher_encrypt(text, rows, cols)
    else:
        result = route_cipher_decrypt(text, rows, cols)
    
    return {'result': result}

@app.route('/api/playfair', methods=['POST'])
@login_required
def api_playfair():
    from utils.playfair import playfair_encrypt, playfair_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    show_matrix = data.get('show_matrix', False)  # Toggle untuk show/hide matrix
    
    if mode == 'encrypt':
        result = playfair_encrypt(text, key)
        response = {'result': result}
        if show_matrix:
            from utils.playfair import display_playfair_matrix
            response['matrix'] = display_playfair_matrix(key)
        return response
    else:
        result = playfair_decrypt(text, key)
        return {'result': result}

@app.route('/api/playfair/matrix', methods=['POST'])
@login_required
def api_playfair_matrix():
    from utils.playfair import display_playfair_matrix
    
    data = request.get_json()
    key = data.get('key', '')
    
    matrix = display_playfair_matrix(key)
    
    return {'matrix': matrix}

@app.route('/api/hill', methods=['POST'])
@login_required
def api_hill():
    from utils.hill import hill_encrypt, hill_decrypt, is_valid_key_matrix
    import numpy as np
    
    data = request.get_json()
    text = data.get('text', '')
    key_matrix_data = data.get('key_matrix', [])
    mode = data.get('mode', 'encrypt')
    
    try:
        key_matrix = np.array(key_matrix_data)
        
        valid, message = is_valid_key_matrix(key_matrix)
        if not valid:
            return {'error': message}, 400
        
        if mode == 'encrypt':
            result = hill_encrypt(text, key_matrix)
        else:
            result = hill_decrypt(text, key_matrix)
            if result is None:
                return {'error': 'Matriks tidak bisa di-inverse'}, 400
        
        return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/rsa/generate', methods=['POST'])
@login_required
def api_rsa_generate():
    from utils.rsa import generate_keypair
    
    public_key, private_key = generate_keypair(bits=16)
    
    return {
        'public_key': public_key,
        'private_key': private_key
    }

@app.route('/api/rsa/encrypt', methods=['POST'])
@login_required
def api_rsa_encrypt():
    from utils.rsa import rsa_encrypt, ciphertext_to_string
    
    data = request.get_json()
    text = data.get('text', '')
    public_key = tuple(data.get('public_key', []))
    
    ciphertext = rsa_encrypt(text, public_key)
    ciphertext_string = ciphertext_to_string(ciphertext)
    
    return {
        'ciphertext': ciphertext,
        'ciphertext_string': ciphertext_string
    }

@app.route('/api/rsa/decrypt', methods=['POST'])
@login_required
def api_rsa_decrypt():
    from utils.rsa import rsa_decrypt
    
    data = request.get_json()
    ciphertext = data.get('ciphertext', [])
    private_key = tuple(data.get('private_key', []))
    
    plaintext = rsa_decrypt(ciphertext, private_key)
    
    return {'plaintext': plaintext}

# Hash API - Bcrypt & Argon2
@app.route('/api/hash/generate', methods=['POST'])
@login_required
def api_hash_generate():
    from utils.hash_utils import hash_all
    
    data = request.get_json()
    text = data.get('text', '')
    
    hashes = hash_all(text)
    
    return {'hashes': hashes}

@app.route('/api/hash/bcrypt', methods=['POST'])
@login_required
def api_bcrypt_hash():
    data = request.get_json()
    password = data.get('password', '')
    
    # Hash dengan bcrypt
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    return {
        'algorithm': 'bcrypt',
        'hash': hashed.decode('utf-8'),
        'rounds': 12,
        'info': 'Bcrypt menggunakan cost factor (rounds) untuk mengatur kompleksitas'
    }

@app.route('/api/hash/argon2', methods=['POST'])
@login_required
def api_argon2_hash():
    data = request.get_json()
    password = data.get('password', '')
    
    # Hash dengan argon2 dan tampilkan parameter
    hashed = ph.hash(password)
    
    return {
        'algorithm': 'argon2id',
        'hash': hashed,
        'parameters': {
            'time_cost': ph.time_cost,
            'memory_cost': f'{ph.memory_cost} KB ({ph.memory_cost/1024:.1f} MB)',
            'parallelism': ph.parallelism,
            'hash_length': ph.hash_len,
            'salt_length': ph.salt_len
        },
        'info': 'Argon2 adalah pemenang Password Hashing Competition (2015)'
    }

@app.route('/api/hash/compare-algos', methods=['POST'])
@login_required
def api_hash_compare_algos():
    data = request.get_json()
    password = data.get('password', '')
    
    import time
    
    # Test Bcrypt
    start = time.time()
    bcrypt_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    bcrypt_time = time.time() - start
    
    # Test Argon2
    start = time.time()
    argon2_hash = ph.hash(password)
    argon2_time = time.time() - start
    
    return {
        'bcrypt': {
            'hash': bcrypt_hash.decode('utf-8'),
            'time': f'{bcrypt_time:.4f} seconds',
            'rounds': 12
        },
        'argon2': {
            'hash': argon2_hash,
            'time': f'{argon2_time:.4f} seconds',
            'params': f'time={ph.time_cost}, memory={ph.memory_cost}KB, parallel={ph.parallelism}'
        },
        'recommendation': 'Argon2 lebih modern dan lebih aman untuk aplikasi baru'
    }

@app.route('/api/hash/compare', methods=['POST'])
@login_required
def api_hash_compare():
    from utils.hash_utils import compare_hashes
    
    data = request.get_json()
    text1 = data.get('text1', '')
    text2 = data.get('text2', '')
    algorithm = data.get('algorithm', 'sha256')
    
    result = compare_hashes(text1, text2, algorithm)
    
    return result

@app.route('/api/hash/password-strength', methods=['POST'])
@login_required
def api_password_strength():
    from utils.hash_utils import password_strength_check
    
    data = request.get_json()
    password = data.get('password', '')
    
    result = password_strength_check(password)
    
    return result

# MODERN ENCRYPTION APIs - Premium Features
@app.route('/api/aes', methods=['POST'])
@login_required
def api_aes():
    from utils.modern_crypto import aes_encrypt, aes_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    try:
        if mode == 'encrypt':
            result, iv = aes_encrypt(text, key)
            return {'result': result, 'iv': iv}
        else:
            iv = data.get('iv', '')
            result = aes_decrypt(text, key, iv)
            return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/des', methods=['POST'])
@login_required
def api_des():
    from utils.modern_crypto import des_encrypt, des_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    try:
        if mode == 'encrypt':
            result, iv = des_encrypt(text, key)
            return {'result': result, 'iv': iv}
        else:
            iv = data.get('iv', '')
            result = des_decrypt(text, key, iv)
            return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/triple-des', methods=['POST'])
@login_required
def api_triple_des():
    from utils.modern_crypto import triple_des_encrypt, triple_des_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    try:
        if mode == 'encrypt':
            result, iv = triple_des_encrypt(text, key)
            return {'result': result, 'iv': iv}
        else:
            iv = data.get('iv', '')
            result = triple_des_decrypt(text, key, iv)
            return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/blowfish', methods=['POST'])
@login_required
def api_blowfish():
    from utils.modern_crypto import blowfish_encrypt, blowfish_decrypt
    
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    try:
        if mode == 'encrypt':
            result, iv = blowfish_encrypt(text, key)
            return {'result': result, 'iv': iv}
        else:
            iv = data.get('iv', '')
            result = blowfish_decrypt(text, key, iv)
            return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

# Error handlers
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)