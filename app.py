from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
import os
import secrets

# ini tuh bagian inisialisasi aplikasi yaa
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 menit

# nah kalo yang ini inisialisasi database tetap kita pake Sqlite yaa biar sederhana euy
db = SQLAlchemy(app)

# nah ini inisialisasi login manager buat ngatur sesi user
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Anda harus login terlebih dahulu untuk mengakses halaman ini.'
login_manager.login_message_category = 'warning'

# yang ini buat hasher password pake Argon2 requirements bapak bayu pamungkas
ph = PasswordHasher()

# ini model user buat database disimpan di Sqlite disini aja lah
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

# Decorator khusus untuk mencegah akses langsung lewat URL
def prevent_direct_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Cek apakah request berasal dari dalam aplikasi (referrer check)
        if not current_user.is_authenticated:
            flash('Anda harus login terlebih dahulu!', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator untuk logout yang aman
def secure_logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Anda sudah logout.', 'info')
            return redirect(url_for('index'))
        
        # Cek apakah ada CSRF token atau request method POST
        if request.method == 'GET':
            # Untuk logout via GET, pastikan ada token di session
            if 'logout_token' not in session:
                session['logout_token'] = secrets.token_urlsafe(32)
            
            # Validasi token
            token = request.args.get('token')
            if token != session.get('logout_token'):
                flash('Akses tidak valid. Gunakan tombol logout yang disediakan.', 'danger')
                return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# Middleware untuk proteksi tambahan
@app.before_request
def security_headers():
    # Proteksi tambahan untuk halaman yang memerlukan login
    protected_routes = [
        'substitution', 'transposition', 'playfair', 'hill', 'rsa', 'hash_func',
        'api_substitution', 'api_railfence', 'api_columnar', 'api_route',
        'api_playfair', 'api_playfair_matrix', 'api_hill', 'api_rsa_generate',
        'api_rsa_encrypt', 'api_rsa_decrypt', 'api_hash_generate', 
        'api_hash_compare', 'api_password_strength'
    ]
    
    # Cek apakah endpoint yang diakses memerlukan login
    if request.endpoint in protected_routes:
        if not current_user.is_authenticated:
            if request.is_json or request.path.startswith('/api/'):
                return {'error': 'Unauthorized. Login required.'}, 401
            flash('Anda harus login terlebih dahulu!', 'danger')
            return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    # Tambahkan security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ini routes buat aplikasi webnya ya gaes

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
        
        # Haus Validasi awokwok:3
        if not username or not email or not password:
            flash('Semua field harus diisi!', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Password tidak cocok!', 'danger')
            return redirect(url_for('register'))
        
        # cek username atos aya anu nganggo acan
        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan!', 'danger')
            return redirect(url_for('register'))
        
        # sami ieu ge cek email atos aya anu nganggo acan
        if User.query.filter_by(email=email).first():
            flash('Email sudah terdaftar!', 'danger')
            return redirect(url_for('register'))
        
        # ieu simpen user anyar na database
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
            # Generate logout token untuk user ini
            session['logout_token'] = secrets.token_urlsafe(32)
            flash('Login berhasil!', 'success')
            next_page = request.args.get('next')
            # Validasi next_page untuk mencegah open redirect
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@secure_logout_required
def logout():
    # Hapus token logout dari session
    session.pop('logout_token', None)
    logout_user()
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Generate atau ambil logout token untuk ditampilkan di dashboard
    if 'logout_token' not in session:
        session['logout_token'] = secrets.token_urlsafe(32)
    return render_template('dashboard.html', username=current_user.username, logout_token=session['logout_token'])

# nah ie routs kanggo fitur-fitur cryptography na

# nu ieu fitur dasar anu teu butuh login
@app.route('/caesar')
def caesar():
    return render_template('caesar.html')

@app.route('/vigenere')
def vigenere():
    return render_template('vigenere.html')

@app.route('/bruteforce')
def bruteforce():
    return render_template('bruteforce.html')

# tahh mun ieu fitur anu butuh login
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

# di handap ieu API na gaes, nu teu butuh login heula

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

# tah mun anu ieu fitur anu kedah login heula

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
    
    if mode == 'encrypt':
        result = playfair_encrypt(text, key)
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
        
        # ieu validasi matriks konci nya barudak
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


@app.route('/api/hash/generate', methods=['POST'])
@login_required
def api_hash_generate():
    from utils.hash_utils import hash_all
    
    data = request.get_json()
    text = data.get('text', '')
    
    hashes = hash_all(text)
    
    return {'hashes': hashes}


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

# Error handlers untuk keamanan tambahan
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
        db.create_all()  # nah upami ieu kanggo ngadamel database na mun can aya
    app.run(debug=True)