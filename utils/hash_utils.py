import hashlib
import hmac

def md5_hash(text):
    """
    Generate MD5 hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: MD5 hash dalam hexadecimal
    """
    return hashlib.md5(text.encode()).hexdigest()


def sha1_hash(text):
    """
    Generate SHA-1 hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: SHA-1 hash dalam hexadecimal
    """
    return hashlib.sha1(text.encode()).hexdigest()


def sha256_hash(text):
    """
    Generate SHA-256 hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: SHA-256 hash dalam hexadecimal
    """
    return hashlib.sha256(text.encode()).hexdigest()


def sha512_hash(text):
    """
    Generate SHA-512 hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: SHA-512 hash dalam hexadecimal
    """
    return hashlib.sha512(text.encode()).hexdigest()


def sha3_256_hash(text):
    """
    Generate SHA3-256 hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: SHA3-256 hash dalam hexadecimal
    """
    return hashlib.sha3_256(text.encode()).hexdigest()


def blake2b_hash(text):
    """
    Generate BLAKE2b hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: BLAKE2b hash dalam hexadecimal
    """
    return hashlib.blake2b(text.encode()).hexdigest()


def blake2s_hash(text):
    """
    Generate BLAKE2s hash
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        str: BLAKE2s hash dalam hexadecimal
    """
    return hashlib.blake2s(text.encode()).hexdigest()


def hmac_sha256(text, key):
    """
    Generate HMAC-SHA256
    
    Args:
        text (str): Pesan
        key (str): Secret key
    
    Returns:
        str: HMAC dalam hexadecimal
    """
    return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()


def hash_all(text):
    """
    Generate semua hash sekaligus
    
    Args:
        text (str): Teks yang akan di-hash
    
    Returns:
        dict: Dictionary berisi semua hash
    """
    return {
        'md5': md5_hash(text),
        'sha1': sha1_hash(text),
        'sha256': sha256_hash(text),
        'sha512': sha512_hash(text),
        'sha3_256': sha3_256_hash(text),
        'blake2b': blake2b_hash(text),
        'blake2s': blake2s_hash(text)
    }


def compare_hashes(text1, text2, algorithm='sha256'):
    """
    Bandingkan hash dari dua teks
    
    Args:
        text1 (str): Teks pertama
        text2 (str): Teks kedua
        algorithm (str): Algoritma yang digunakan
    
    Returns:
        dict: Hasil perbandingan
    """
    algorithms = {
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash,
        'sha512': sha512_hash,
        'sha3_256': sha3_256_hash,
        'blake2b': blake2b_hash,
        'blake2s': blake2s_hash
    }
    
    if algorithm not in algorithms:
        algorithm = 'sha256'
    
    hash_func = algorithms[algorithm]
    hash1 = hash_func(text1)
    hash2 = hash_func(text2)
    
    return {
        'algorithm': algorithm,
        'hash1': hash1,
        'hash2': hash2,
        'match': hash1 == hash2
    }


def file_hash_simulator(content, algorithm='sha256'):
    """
    Simulasi hashing file (untuk demo)
    
    Args:
        content (str): Konten file
        algorithm (str): Algoritma hash
    
    Returns:
        dict: Info hash
    """
    algorithms = {
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash,
        'sha512': sha512_hash
    }
    
    hash_func = algorithms.get(algorithm, sha256_hash)
    file_hash = hash_func(content)
    
    return {
        'algorithm': algorithm.upper(),
        'hash': file_hash,
        'length': len(file_hash),
        'content_size': len(content)
    }


def check_hash_collision(text1, text2):
    """
    Cek apakah dua teks berbeda menghasilkan hash yang sama (collision)
    
    Args:
        text1 (str): Teks pertama
        text2 (str): Teks kedua
    
    Returns:
        dict: Hasil pengecekan collision
    """
    results = {}
    
    for name, func in [
        ('MD5', md5_hash),
        ('SHA1', sha1_hash),
        ('SHA256', sha256_hash),
        ('SHA512', sha512_hash)
    ]:
        hash1 = func(text1)
        hash2 = func(text2)
        
        results[name] = {
            'collision': hash1 == hash2 and text1 != text2,
            'hash1': hash1,
            'hash2': hash2
        }
    
    return results


def password_strength_check(password):
    """
    Cek kekuatan password berdasarkan hash entropy
    
    Args:
        password (str): Password yang akan dicek
    
    Returns:
        dict: Informasi kekuatan password
    """
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1
    
    strength = 'Weak'
    if score >= 5:
        strength = 'Strong'
    elif score >= 3:
        strength = 'Medium'
    
    return {
        'length': length,
        'has_uppercase': has_upper,
        'has_lowercase': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'score': score,
        'strength': strength,
        'hash_sha256': sha256_hash(password)
    }