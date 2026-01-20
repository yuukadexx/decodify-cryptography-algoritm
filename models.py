from flask_login import UserMixin
from datetime import datetime, date, timedelta
import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from extensions import db

# =============== CONSTANTS ===============
DIFFICULTY_LEVELS = ['beginner', 'intermediate', 'advanced']
CIPHER_TYPES = [
    'caesar', 'vigenere', 'substitution', 'transposition', 
    'playfair', 'hill', 'rsa', 'aes', 'des', 'triple_des', 
    'blowfish', 'hash', 'bruteforce'
]

# =============== UTILITY FUNCTIONS ===============
def get_argon2_hasher():
    """Return Argon2 hasher instance"""
    return PasswordHasher(
        time_cost=2,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )

# =============== USER & AUTH MODELS ===============

class User(UserMixin, db.Model):
    """
    User model dengan authentication lengkap
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Profile Information
    full_name = db.Column(db.String(100))
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(255), default='default_avatar.png')
    location = db.Column(db.String(100))
    website = db.Column(db.String(200))
    
    # Account Status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    
    # Subscription
    premium_level = db.Column(db.Integer, default=0)  # 0: free, 1: basic, 2: pro
    premium_expires = db.Column(db.DateTime)
    subscription_id = db.Column(db.String(100))
    
    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime)
    
    # Relationships
    progress = db.relationship('UserProgress', back_populates='user', uselist=False, 
                              cascade='all, delete-orphan')
    settings = db.relationship('UserSettings', back_populates='user', uselist=False,
                              cascade='all, delete-orphan')
    
    # Indexes
    __table_args__ = (
        db.Index('idx_user_search', 'username', 'email', 'full_name'),
        db.Index('idx_user_status', 'is_active', 'is_premium'),
    )
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """Hash password menggunakan Argon2"""
        ph = get_argon2_hasher()
        self.password_hash = ph.hash(password)
        self.last_password_change = datetime.utcnow()
    
    def check_password(self, password):
        """Verifikasi password dengan Argon2"""
        ph = get_argon2_hasher()
        try:
            ph.verify(self.password_hash, password)
            
            # Check if password needs rehashing (if Argon2 parameters changed)
            if ph.check_needs_rehash(self.password_hash):
                self.set_password(password)
            
            return True
        except VerifyMismatchError:
            return False
    
    def increment_failed_login(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
    
    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if not self.account_locked_until:
            return False
        return datetime.utcnow() < self.account_locked_until
    
    def get_stats(self):
        """Get user statistics"""
        return {
            'level': self.progress.level if self.progress else 1,
            'xp': self.progress.xp if self.progress else 0,
            'challenges_completed': self.progress.challenges_completed if self.progress else 0,
            'encryptions': self.progress.encryptions_performed if self.progress else 0,
            'streak': self.progress.current_streak if self.progress else 0,
        }


class UserProgress(db.Model):
    """
    User progress tracking model
    """
    __tablename__ = 'user_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Level & XP
    level = db.Column(db.Integer, default=1, index=True)
    xp = db.Column(db.Integer, default=0)
    xp_to_next_level = db.Column(db.Integer, default=100)
    
    # Stats
    challenges_completed = db.Column(db.Integer, default=0)
    quizzes_completed = db.Column(db.Integer, default=0)
    encryptions_performed = db.Column(db.Integer, default=0)
    decryptions_performed = db.Column(db.Integer, default=0)
    tutorials_completed = db.Column(db.Integer, default=0)
    
    # Learning Analytics
    learning_time_minutes = db.Column(db.Integer, default=0)
    total_sessions = db.Column(db.Integer, default=0)
    avg_session_minutes = db.Column(db.Float, default=0)
    
    # Streaks
    current_streak = db.Column(db.Integer, default=0)
    longest_streak = db.Column(db.Integer, default=0)
    last_active_date = db.Column(db.Date, default=date.today, index=True)
    
    # Badges & Achievements
    badges_earned = db.Column(db.Text, default='[]')  # JSON array of badge IDs
    achievements_unlocked = db.Column(db.Integer, default=0)
    
    # Rankings
    global_rank = db.Column(db.Integer)
    category_rank = db.Column(db.String(50))
    
    # Progress Percentages
    caesar_progress = db.Column(db.Integer, default=0)
    vigenere_progress = db.Column(db.Integer, default=0)
    substitution_progress = db.Column(db.Integer, default=0)
    transposition_progress = db.Column(db.Integer, default=0)
    playfair_progress = db.Column(db.Integer, default=0)
    hill_progress = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='progress')
    
    def __repr__(self):
        return f'<UserProgress {self.user_id} - Level {self.level}>'
    
    def add_xp(self, amount, activity_type=None):
        """Add XP and check for level up"""
        old_level = self.level
        self.xp += amount
        
        # Check for level up
        new_level = max(1, self.xp // 100 + 1)
        if new_level > old_level:
            self.level = new_level
            self.xp_to_next_level = new_level * 100
        
        return new_level > old_level  # Return True if leveled up
    
    def update_streak(self):
        """Update login streak"""
        today = date.today()
        
        if self.last_active_date:
            days_diff = (today - self.last_active_date).days
            
            if days_diff == 1:  # Consecutive day
                self.current_streak += 1
            elif days_diff > 1:  # Broken streak
                self.current_streak = 1
            
            if self.current_streak > self.longest_streak:
                self.longest_streak = self.current_streak
        
        self.last_active_date = today
    
    def get_badges(self):
        """Get badges as Python list"""
        try:
            return json.loads(self.badges_earned)
        except:
            return []
    
    def add_badge(self, badge_id):
        """Add a badge to user"""
        badges = self.get_badges()
        if badge_id not in badges:
            badges.append(badge_id)
            self.badges_earned = json.dumps(badges)
    
    def get_progress_summary(self):
        """Get progress summary dictionary"""
        return {
            'level': self.level,
            'xp': self.xp,
            'xp_to_next_level': self.xp_to_next_level,
            'xp_percentage': min(100, (self.xp % 100)),
            'challenges_completed': self.challenges_completed,
            'encryptions': self.encryptions_performed,
            'streak': self.current_streak,
            'longest_streak': self.longest_streak,
            'learning_hours': self.learning_time_minutes // 60,
            'badges_count': len(self.get_badges()),
            'achievements': self.achievements_unlocked,
        }


class UserSettings(db.Model):
    """
    User preferences and settings
    """
    __tablename__ = 'user_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # UI/UX Preferences
    theme = db.Column(db.String(20), default='light')  # light, dark, auto
    language = db.Column(db.String(10), default='id')  # id, en
    font_size = db.Column(db.String(10), default='medium')  # small, medium, large
    animation_enabled = db.Column(db.Boolean, default=True)
    sound_effects = db.Column(db.Boolean, default=True)
    notifications_sound = db.Column(db.Boolean, default=True)
    
    # Privacy Settings
    show_profile = db.Column(db.Boolean, default=True)
    show_progress = db.Column(db.Boolean, default=True)
    show_achievements = db.Column(db.Boolean, default=True)
    show_on_leaderboard = db.Column(db.Boolean, default=True)
    allow_messages = db.Column(db.Boolean, default=True)
    
    # Notification Preferences
    email_notifications = db.Column(db.Boolean, default=True)
    push_notifications = db.Column(db.Boolean, default=True)
    notify_new_challenges = db.Column(db.Boolean, default=True)
    notify_achievements = db.Column(db.Boolean, default=True)
    notify_system_updates = db.Column(db.Boolean, default=True)
    notify_promotions = db.Column(db.Boolean, default=False)
    
    # Learning Preferences
    default_cipher = db.Column(db.String(50), default='caesar')
    difficulty_preference = db.Column(db.String(20), default='medium')
    auto_save_progress = db.Column(db.Boolean, default=True)
    show_hints = db.Column(db.Boolean, default=True)
    show_solutions = db.Column(db.Boolean, default=False)
    
    # Security Settings
    two_factor_auth = db.Column(db.Boolean, default=False)
    login_notifications = db.Column(db.Boolean, default=True)
    session_timeout = db.Column(db.Integer, default=30)  # minutes
    
    # Data & Storage
    save_history = db.Column(db.Boolean, default=True)
    save_encryptions = db.Column(db.Boolean, default=True)
    clear_history_days = db.Column(db.Integer, default=30)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='settings')
    
    def __repr__(self):
        return f'<UserSettings {self.user_id}>'
    
    def to_dict(self):
        """Convert settings to dictionary"""
        return {
            'theme': self.theme,
            'language': self.language,
            'font_size': self.font_size,
            'privacy': {
                'show_profile': self.show_profile,
                'show_progress': self.show_progress,
                'show_on_leaderboard': self.show_on_leaderboard,
            },
            'notifications': {
                'email': self.email_notifications,
                'push': self.push_notifications,
                'new_challenges': self.notify_new_challenges,
            },
            'learning': {
                'default_cipher': self.default_cipher,
                'show_hints': self.show_hints,
                'auto_save': self.auto_save_progress,
            }
        }


# =============== AUTHENTICATION MODELS ===============

class ResetToken(db.Model):
    """
    Password reset tokens
    """
    __tablename__ = 'reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    token_type = db.Column(db.String(20), default='password_reset')  # password_reset, email_verify
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime)
    
    # Additional info
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))
    
    __table_args__ = (
        db.Index('idx_reset_token_valid', 'token', 'used', 'expires_at'),
    )
    
    def __repr__(self):
        return f'<ResetToken {self.token[:8]}...>'
    
    def is_valid(self):
        """Check if token is still valid"""
        if self.used:
            return False
        if datetime.utcnow() > self.expires_at:
            return False
        return True
    
    def mark_used(self):
        """Mark token as used"""
        self.used = True
        self.used_at = datetime.utcnow()


class Session(db.Model):
    """
    User session tracking
    """
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(100), primary_key=True)  # Session ID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    session_data = db.Column(db.Text)  # JSON encoded session data
    
    # Device info
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    device_type = db.Column(db.String(50))  # desktop, mobile, tablet
    browser = db.Column(db.String(50))
    os = db.Column(db.String(50))
    
    # Location info (if available)
    country = db.Column(db.String(50))
    city = db.Column(db.String(100))
    timezone = db.Column(db.String(50))
    
    # Activity tracking
    login_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    logout_at = db.Column(db.DateTime)
    
    # Session status
    is_active = db.Column(db.Boolean, default=True)
    logout_reason = db.Column(db.String(50))  # user, timeout, admin
    
    # Relationships
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))
    
    __table_args__ = (
        db.Index('idx_session_user', 'user_id', 'is_active'),
        db.Index('idx_session_expiry', 'expires_at'),
    )
    
    def __repr__(self):
        return f'<Session {self.id[:8]}...>'
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def terminate(self, reason='user'):
        """Terminate session"""
        self.is_active = False
        self.logout_at = datetime.utcnow()
        self.logout_reason = reason


class LoginHistory(db.Model):
    """
    User login history
    """
    __tablename__ = 'login_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Login details
    login_at = db.Column(db.DateTime, default=datetime.utcnow)
    logout_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Status
    successful = db.Column(db.Boolean, default=True)
    failure_reason = db.Column(db.String(100))  # wrong_password, locked, etc.
    
    # Location (if available)
    country = db.Column(db.String(50))
    city = db.Column(db.String(100))
    
    # Relationships
    user = db.relationship('User', backref=db.backref('login_history', lazy=True))
    
    __table_args__ = (
        db.Index('idx_login_user', 'user_id', 'login_at'),
        db.Index('idx_login_time', 'login_at'),
    )
    
    def __repr__(self):
        status = "SUCCESS" if self.successful else "FAILED"
        return f'<LoginHistory {self.user_id} - {status}>'


# =============== CIPHER & LEARNING MODELS ===============

class CipherUsage(db.Model):
    """
    Track cipher usage statistics
    """
    __tablename__ = 'cipher_usage'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cipher_name = db.Column(db.String(50), nullable=False, index=True)
    
    # Usage stats
    usage_count = db.Column(db.Integer, default=0)
    encryption_count = db.Column(db.Integer, default=0)
    decryption_count = db.Column(db.Integer, default=0)
    analysis_count = db.Column(db.Integer, default=0)
    
    # Success rates
    successful_encryptions = db.Column(db.Integer, default=0)
    successful_decryptions = db.Column(db.Integer, default=0)
    
    # Time tracking
    total_time_seconds = db.Column(db.Integer, default=0)
    avg_time_per_use = db.Column(db.Float, default=0)
    
    # Last usage
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.String(50))  # encrypt, decrypt, analyze
    
    # Relationships
    user = db.relationship('User', backref=db.backref('cipher_usages', lazy=True))
    
    __table_args__ = (
        db.Index('idx_cipher_user', 'user_id', 'cipher_name'),
        db.Index('idx_cipher_stats', 'cipher_name', 'usage_count'),
        db.UniqueConstraint('user_id', 'cipher_name', name='unique_user_cipher'),
    )
    
    def __repr__(self):
        return f'<CipherUsage {self.user_id} - {self.cipher_name}>'
    
    def record_usage(self, activity_type, successful=True, time_seconds=0):
        """Record cipher usage"""
        self.usage_count += 1
        self.total_time_seconds += time_seconds
        
        if time_seconds > 0:
            self.avg_time_per_use = self.total_time_seconds / self.usage_count
        
        if activity_type == 'encrypt':
            self.encryption_count += 1
            if successful:
                self.successful_encryptions += 1
        elif activity_type == 'decrypt':
            self.decryption_count += 1
            if successful:
                self.successful_decryptions += 1
        elif activity_type == 'analyze':
            self.analysis_count += 1
        
        self.last_used = datetime.utcnow()
        self.last_activity = activity_type
    
    def get_success_rate(self):
        """Get success rate percentage"""
        total_operations = self.encryption_count + self.decryption_count
        if total_operations == 0:
            return 0
        
        successful = self.successful_encryptions + self.successful_decryptions
        return (successful / total_operations) * 100


class UserActivity(db.Model):
    """
    User activity log
    """
    __tablename__ = 'user_activities'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Activity details
    activity_type = db.Column(db.String(50), nullable=False, index=True)
    activity_subtype = db.Column(db.String(50))
    description = db.Column(db.String(500), nullable=False)
    
    # Cipher-specific
    cipher_name = db.Column(db.String(50), index=True)
    cipher_operation = db.Column(db.String(20))  # encrypt, decrypt, analyze
    input_text = db.Column(db.Text)
    output_text = db.Column(db.Text)
    
    # XP and rewards
    xp_gained = db.Column(db.Integer, default=0)
    badge_earned = db.Column(db.String(50))
    achievement_unlocked = db.Column(db.String(100))
    
    # Metadata
    duration_seconds = db.Column(db.Integer)  # How long the activity took
    difficulty = db.Column(db.String(20))
    success = db.Column(db.Boolean, default=True)
    
    # Device info
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('activities', lazy=True))
    
    __table_args__ = (
        db.Index('idx_activity_user_time', 'user_id', 'timestamp'),
        db.Index('idx_activity_type_time', 'activity_type', 'timestamp'),
    )
    
    def __repr__(self):
        return f'<UserActivity {self.user_id} - {self.activity_type}>'
    
    def to_dict(self):
        """Convert to dictionary for API response"""
        return {
            'id': self.id,
            'activity_type': self.activity_type,
            'description': self.description,
            'cipher_name': self.cipher_name,
            'xp_gained': self.xp_gained,
            'timestamp': self.timestamp.isoformat(),
            'success': self.success,
        }


# =============== QUIZ & CHALLENGE MODELS ===============

class QuizQuestion(db.Model):
    """
    Quiz questions for ciphers
    """
    __tablename__ = 'quiz_questions'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Question metadata
    cipher_name = db.Column(db.String(50), nullable=False, index=True)
    category = db.Column(db.String(50), default='general')
    question_type = db.Column(db.String(20), default='multiple_choice')  # multiple_choice, true_false, fill_blank
    difficulty = db.Column(db.String(20), default='medium', index=True)
    
    # Question content
    question = db.Column(db.Text, nullable=False)
    question_image = db.Column(db.String(255))  # URL to image if any
    code_snippet = db.Column(db.Text)  # For code-based questions
    
    # Options (for multiple choice)
    option_a = db.Column(db.String(500))
    option_b = db.Column(db.String(500))
    option_c = db.Column(db.String(500))
    option_d = db.Column(db.String(500))
    option_e = db.Column(db.String(500))
    
    # Correct answer
    correct_answer = db.Column(db.String(10), nullable=False)  # A, B, C, D, E or text for fill_blank
    correct_answer_text = db.Column(db.Text)  # Full text of correct answer
    
    # Explanation and hints
    explanation = db.Column(db.Text)
    hint = db.Column(db.String(500))
    
    # Stats
    times_attempted = db.Column(db.Integer, default=0)
    times_correct = db.Column(db.Integer, default=0)
    average_time = db.Column(db.Float, default=0)  # Average time to answer in seconds
    
    # Scoring
    xp_reward = db.Column(db.Integer, default=10)
    point_value = db.Column(db.Integer, default=1)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_premium = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<QuizQuestion {self.id} - {self.cipher_name}>'
    
    def record_attempt(self, is_correct, time_seconds):
        """Record attempt statistics"""
        self.times_attempted += 1
        if is_correct:
            self.times_correct += 1
        
        # Update average time
        if self.times_attempted > 0:
            total_time = self.average_time * (self.times_attempted - 1) + time_seconds
            self.average_time = total_time / self.times_attempted
    
    def get_success_rate(self):
        """Get success rate percentage"""
        if self.times_attempted == 0:
            return 0
        return (self.times_correct / self.times_attempted) * 100
    
    def to_dict(self):
        """Convert to dictionary for API"""
        return {
            'id': self.id,
            'cipher_name': self.cipher_name,
            'question': self.question,
            'options': {
                'A': self.option_a,
                'B': self.option_b,
                'C': self.option_c,
                'D': self.option_d,
                'E': self.option_e,
            },
            'correct_answer': self.correct_answer,
            'explanation': self.explanation,
            'difficulty': self.difficulty,
            'xp_reward': self.xp_reward,
            'success_rate': self.get_success_rate(),
        }


class QuizAttempt(db.Model):
    """
    Quiz attempt records
    """
    __tablename__ = 'quiz_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.String(50), nullable=False)  # Identifier for the quiz session
    cipher_name = db.Column(db.String(50), nullable=False, index=True)
    
    # Results
    score = db.Column(db.Integer, default=0)
    total_questions = db.Column(db.Integer, default=0)
    correct_answers = db.Column(db.Integer, default=0)
    percentage = db.Column(db.Float, default=0)
    
    # Time tracking
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    
    # Difficulty
    difficulty = db.Column(db.String(20), default='medium')
    
    # Rewards
    xp_earned = db.Column(db.Integer, default=0)
    badges_earned = db.Column(db.Text, default='[]')  # JSON array
    
    # Status
    completed = db.Column(db.Boolean, default=False)
    passed = db.Column(db.Boolean, default=False)
    passed_threshold = db.Column(db.Integer, default=70)  # Percentage needed to pass
    
    # Detailed results (JSON)
    detailed_results = db.Column(db.Text)  # JSON array of question results
    
    # Relationships
    user = db.relationship('User', backref=db.backref('quiz_attempts', lazy=True))
    
    __table_args__ = (
        db.Index('idx_quiz_attempt_user', 'user_id', 'cipher_name'),
        db.Index('idx_quiz_attempt_time', 'start_time'),
    )
    
    def __repr__(self):
        return f'<QuizAttempt {self.user_id} - {self.cipher_name} - {self.percentage}%>'
    
    def calculate_score(self, detailed_results):
        """Calculate score from detailed results"""
        self.detailed_results = json.dumps(detailed_results)
        
        correct = sum(1 for result in detailed_results if result.get('correct', False))
        total = len(detailed_results)
        
        self.correct_answers = correct
        self.total_questions = total
        self.score = correct
        self.percentage = (correct / total * 100) if total > 0 else 0
        
        # Check if passed
        self.passed = self.percentage >= self.passed_threshold
        
        # Calculate duration
        if self.end_time:
            self.duration_seconds = int((self.end_time - self.start_time).total_seconds())
    
    def get_detailed_results(self):
        """Get detailed results as Python list"""
        try:
            return json.loads(self.detailed_results) if self.detailed_results else []
        except:
            return []
    
    def get_badges(self):
        """Get badges earned"""
        try:
            return json.loads(self.badges_earned)
        except:
            return []


class Challenge(db.Model):
    """
    Cryptographic challenges
    """
    __tablename__ = 'challenges'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Challenge metadata
    cipher_name = db.Column(db.String(50), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), default='encryption')  # encryption, decryption, analysis, etc.
    
    # Content
    ciphertext = db.Column(db.Text)
    plaintext = db.Column(db.Text)
    hint = db.Column(db.Text)
    solution = db.Column(db.Text)  # Detailed solution
    solution_steps = db.Column(db.Text)  # Step-by-step solution
    
    # Difficulty and scoring
    difficulty = db.Column(db.String(20), default='easy', index=True)
    difficulty_score = db.Column(db.Integer, default=1)  # 1-10
    xp_reward = db.Column(db.Integer, default=25)
    time_estimate = db.Column(db.Integer)  # Estimated time in minutes
    
    # Hints system
    hint_cost = db.Column(db.Integer, default=5)  # XP cost for hint
    max_hints = db.Column(db.Integer, default=3)
    hint_texts = db.Column(db.Text)  # JSON array of hints
    
    # Requirements
    required_level = db.Column(db.Integer, default=1)
    required_ciphers = db.Column(db.String(200))  # Comma-separated list
    is_premium = db.Column(db.Boolean, default=False)
    
    # Stats
    attempts_count = db.Column(db.Integer, default=0)
    success_count = db.Column(db.Integer, default=0)
    average_time = db.Column(db.Float, default=0)
    
    # Files
    attachment_url = db.Column(db.String(255))
    attachment_type = db.Column(db.String(50))
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Challenge {self.id}: {self.title}>'
    
    def get_hints_list(self):
        """Get hints as Python list"""
        try:
            return json.loads(self.hint_texts) if self.hint_texts else []
        except:
            return []
    
    def get_success_rate(self):
        """Get success rate percentage"""
        if self.attempts_count == 0:
            return 0
        return (self.success_count / self.attempts_count) * 100
    
    def record_attempt(self, successful, time_seconds):
        """Record challenge attempt"""
        self.attempts_count += 1
        if successful:
            self.success_count += 1
        
        # Update average time
        if self.attempts_count > 0:
            total_time = self.average_time * (self.attempts_count - 1) + time_seconds
            self.average_time = total_time / self.attempts_count
    
    def to_dict(self):
        """Convert to dictionary for API"""
        return {
            'id': self.id,
            'cipher_name': self.cipher_name,
            'title': self.title,
            'description': self.description,
            'difficulty': self.difficulty,
            'xp_reward': self.xp_reward,
            'success_rate': self.get_success_rate(),
            'attempts_count': self.attempts_count,
            'is_premium': self.is_premium,
            'required_level': self.required_level,
            'hints_available': len(self.get_hints_list()),
        }


class ChallengeAttempt(db.Model):
    """
    User attempts at challenges
    """
    __tablename__ = 'challenge_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    
    # Attempt details
    attempt_number = db.Column(db.Integer, default=1)
    user_answer = db.Column(db.Text)
    is_correct = db.Column(db.Boolean, default=False)
    
    # Hints used
    hints_used = db.Column(db.Integer, default=0)
    hints_taken = db.Column(db.Text)  # JSON array of hint indices used
    xp_deduction = db.Column(db.Integer, default=0)  # For using hints
    
    # Time tracking
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    
    # Rewards
    xp_earned = db.Column(db.Integer, default=0)
    bonus_xp = db.Column(db.Integer, default=0)  # For speed, no hints, etc.
    
    # Status
    completed = db.Column(db.Boolean, default=False)
    gave_up = db.Column(db.Boolean, default=False)
    
    # Additional info
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('challenge_attempts', lazy=True))
    challenge = db.relationship('Challenge', backref=db.backref('attempts', lazy=True))
    
    __table_args__ = (
        db.Index('idx_challenge_attempt_user', 'user_id', 'challenge_id'),
        db.Index('idx_challenge_attempt_time', 'start_time'),
        db.UniqueConstraint('user_id', 'challenge_id', 'attempt_number', 
                           name='unique_user_challenge_attempt'),
    )
    
    def __repr__(self):
        status = "CORRECT" if self.is_correct else "WRONG"
        return f'<ChallengeAttempt {self.user_id} - {self.challenge_id} - {status}>'
    
    def complete_attempt(self, user_answer, is_correct, hints_used=0, hints_taken=None):
        """Complete the challenge attempt"""
        self.user_answer = user_answer
        self.is_correct = is_correct
        self.hints_used = hints_used
        self.hints_taken = json.dumps(hints_taken) if hints_taken else '[]'
        self.completed = True
        self.end_time = datetime.utcnow()
        
        # Calculate duration
        if self.start_time and self.end_time:
            self.duration_seconds = int((self.end_time - self.start_time).total_seconds())
        
        # Calculate XP
        self.calculate_xp()
    
    def calculate_xp(self):
        """Calculate XP earned"""
        if not self.is_correct:
            self.xp_earned = 0
            return
        
        # Base XP from challenge
        base_xp = self.challenge.xp_reward if self.challenge else 25
        
        # Deduct for hints
        hint_deduction = self.hints_used * (self.challenge.hint_cost if self.challenge else 5)
        
        # Bonus for speed (if completed in less than 1/3 of estimated time)
        speed_bonus = 0
        if self.challenge and self.challenge.time_estimate and self.duration_seconds:
            estimated_seconds = self.challenge.time_estimate * 60
            if self.duration_seconds < estimated_seconds / 3:
                speed_bonus = base_xp * 0.2  # 20% bonus
        
        # Bonus for no hints
        no_hint_bonus = 0
        if self.hints_used == 0:
            no_hint_bonus = base_xp * 0.1  # 10% bonus
        
        # Calculate final XP
        self.xp_deduction = hint_deduction
        self.bonus_xp = speed_bonus + no_hint_bonus
        self.xp_earned = max(0, base_xp - hint_deduction + self.bonus_xp)
    
    def get_hints_taken(self):
        """Get hints taken as Python list"""
        try:
            return json.loads(self.hints_taken) if self.hints_taken else []
        except:
            return []


# =============== GLOSSARY MODELS ===============

class GlossaryTerm(db.Model):
    """
    Cryptographic glossary terms
    """
    __tablename__ = 'glossary_terms'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Term information
    title = db.Column(db.String(200), nullable=False, index=True)
    slug = db.Column(db.String(200), unique=True, nullable=False, index=True)
    pronunciation = db.Column(db.String(100))
    acronym = db.Column(db.String(50))  # If term is an acronym
    alternate_names = db.Column(db.String(500))  # Comma-separated
    
    # Content
    definition = db.Column(db.Text, nullable=False)
    extended_definition = db.Column(db.Text)
    
    # Categorization
    category = db.Column(db.String(100), index=True)
    subcategory = db.Column(db.String(100))
    difficulty = db.Column(db.String(20), default='beginner', index=True)
    letter = db.Column(db.String(1), nullable=False, index=True)  # First letter for A-Z index
    
    # Historical information
    year = db.Column(db.Integer)
    inventor = db.Column(db.String(500))  # Comma-separated names
    
    # Applications
    application = db.Column(db.Text)
    
    # Examples
    example = db.Column(db.Text)
    
    # Metadata
    tags = db.Column(db.String(500))
    footnote = db.Column(db.Text)
    
    # Statistics
    view_count = db.Column(db.Integer, default=0)
    bookmarked_count = db.Column(db.Integer, default=0)
    
    # Status flags
    is_featured = db.Column(db.Boolean, default=False, index=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    bookmarks = db.relationship('UserBookmark', back_populates='term', cascade='all, delete-orphan')
    
    __table_args__ = (
        db.Index('idx_glossary_search', 'title', 'definition', 'tags'),
        db.Index('idx_glossary_popular', 'view_count', 'bookmarked_count'),
    )
    
    def __repr__(self):
        return f'<GlossaryTerm {self.id}: {self.title}>'
    
    def increment_view(self):
        """Increment view count"""
        self.view_count += 1
    
    def get_tags_list(self):
        """Get tags as list"""
        if not self.tags:
            return []
        return [tag.strip() for tag in self.tags.split(',')]
    
    def to_dict(self, include_details=False):
        """Convert to dictionary for API"""
        data = {
            'id': self.id,
            'title': self.title,
            'slug': self.slug,
            'pronunciation': self.pronunciation,
            'definition': self.definition,
            'category': self.category,
            'difficulty': self.difficulty,
            'letter': self.letter,
            'view_count': self.view_count,
            'bookmarked_count': self.bookmarked_count,
            'is_featured': self.is_featured,
            'tags': self.get_tags_list(),
        }
        
        if include_details:
            data.update({
                'extended_definition': self.extended_definition,
                'inventor': self.inventor,
                'year': self.year,
                'application': self.application,
                'example': self.example,
                'created_at': self.created_at.isoformat(),
                'updated_at': self.updated_at.isoformat(),
            })
        
        return data


class GlossaryCategory(db.Model):
    """
    Glossary categories
    """
    __tablename__ = 'glossary_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='book')
    color = db.Column(db.String(20), default='#6366f1')
    
    # Ordering and display
    display_order = db.Column(db.Integer, default=0)
    show_in_menu = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    
    # Statistics
    term_count = db.Column(db.Integer, default=0)
    total_views = db.Column(db.Integer, default=0)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<GlossaryCategory {self.id}: {self.name}>'
    
    def update_term_count(self):
        """Update term count"""
        count = GlossaryTerm.query.filter_by(category=self.name, is_verified=True).count()
        self.term_count = count
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'icon': self.icon,
            'color': self.color,
            'term_count': self.term_count,
            'display_order': self.display_order,
            'is_featured': self.is_featured,
        }


class UserBookmark(db.Model):
    """
    User bookmarks for glossary terms
    """
    __tablename__ = 'user_bookmarks'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    term_id = db.Column(db.Integer, db.ForeignKey('glossary_terms.id'), nullable=False)
    
    # Bookmark metadata
    folder = db.Column(db.String(50), default='default')  # Organize into folders
    notes = db.Column(db.Text)
    tags = db.Column(db.String(200))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_viewed = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('bookmarks', lazy=True))
    term = db.relationship('GlossaryTerm', back_populates='bookmarks')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'term_id', name='unique_user_bookmark'),
        db.Index('idx_bookmark_user', 'user_id', 'created_at'),
        db.Index('idx_bookmark_term', 'term_id'),
    )
    
    def __repr__(self):
        return f'<UserBookmark {self.user_id} - {self.term_id}>'
    
    def update_view(self):
        """Update last viewed timestamp"""
        self.last_viewed = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'term_id': self.term_id,
            'term_title': self.term.title if self.term else None,
            'term_definition': self.term.definition[:200] + '...' if self.term else None,
            'folder': self.folder,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'last_viewed': self.last_viewed.isoformat() if self.last_viewed else None,
        }


class SearchHistory(db.Model):
    """
    User search history
    """
    __tablename__ = 'search_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Null for anonymous
    session_id = db.Column(db.String(100))
    
    # Search details
    query = db.Column(db.String(500), nullable=False)
    search_type = db.Column(db.String(50), default='glossary')  # glossary, cipher, tutorial, all
    filters = db.Column(db.Text)  # JSON object of filters applied
    
    # Results
    results_count = db.Column(db.Integer, default=0)
    result_ids = db.Column(db.Text)  # JSON array of result IDs
    
    # Click tracking
    clicked_result_id = db.Column(db.Integer)
    click_position = db.Column(db.Integer)
    
    # Device info
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    # Timestamps
    searched_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('search_history', lazy=True))
    
    __table_args__ = (
        db.Index('idx_search_user', 'user_id', 'searched_at'),
        db.Index('idx_search_query', 'query', 'searched_at'),
    )
    
    def __repr__(self):
        return f'<SearchHistory {self.id}: {self.query[:50]}...>'
    
    def get_filters(self):
        """Get filters as Python dict"""
        try:
            return json.loads(self.filters) if self.filters else {}
        except:
            return {}
    
    def get_result_ids(self):
        """Get result IDs as Python list"""
        try:
            return json.loads(self.result_ids) if self.result_ids else []
        except:
            return []
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'query': self.query,
            'search_type': self.search_type,
            'results_count': self.results_count,
            'searched_at': self.searched_at.isoformat(),
            'clicked_result': bool(self.clicked_result_id),
        }


# =============== ACHIEVEMENT MODELS ===============

class Achievement(db.Model):
    """
    Achievements/badges system
    """
    __tablename__ = 'achievements'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Achievement details
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), nullable=False)
    icon_color = db.Column(db.String(20), default='#6366f1')
    
    # Categorization
    category = db.Column(db.String(50), default='general')  # learning, skill, challenge, social
    tier = db.Column(db.Integer, default=1)  # 1: bronze, 2: silver, 3: gold, 4: platinum
    difficulty = db.Column(db.String(20), default='easy')
    
    # Requirements
    requirement = db.Column(db.String(100))
    requirement_value = db.Column(db.Integer, default=1)
    
    # Rewards
    xp_reward = db.Column(db.Integer, default=100)
    badge_class = db.Column(db.String(50))  # CSS class for styling
    
    # Display
    display_order = db.Column(db.Integer, default=0)
    is_secret = db.Column(db.Boolean, default=False)  # Hidden until unlocked
    is_active = db.Column(db.Boolean, default=True)
    
    # Statistics
    unlocked_count = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_achievement_category', 'category', 'tier'),
        db.Index('idx_achievement_active', 'is_active', 'display_order'),
    )
    
    def __repr__(self):
        return f'<Achievement {self.id}: {self.name}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'icon_color': self.icon_color,
            'category': self.category,
            'tier': self.tier,
            'xp_reward': self.xp_reward,
            'unlocked_count': self.unlocked_count,
            'is_secret': self.is_secret,
        }


class UserAchievement(db.Model):
    """
    User unlocked achievements
    """
    __tablename__ = 'user_achievements'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievements.id'), nullable=False)
    
    # Unlock details
    unlocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    progress_before = db.Column(db.Text)  # JSON snapshot of user progress when unlocked
    trigger_activity = db.Column(db.String(100))  # What triggered the unlock
    
    # Display
    is_new = db.Column(db.Boolean, default=True)  # Mark as new until user sees it
    is_favorite = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('user_achievements', lazy=True))
    achievement = db.relationship('Achievement', backref=db.backref('user_achievements', lazy=True))
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'achievement_id', name='unique_user_achievement'),
        db.Index('idx_user_achievement', 'user_id', 'unlocked_at'),
    )
    
    def __repr__(self):
        return f'<UserAchievement {self.user_id} - {self.achievement_id}>'
    
    def mark_as_seen(self):
        """Mark achievement as seen (not new anymore)"""
        self.is_new = False
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'achievement': self.achievement.to_dict() if self.achievement else None,
            'unlocked_at': self.unlocked_at.isoformat(),
            'is_new': self.is_new,
            'is_favorite': self.is_favorite,
        }


# =============== LEADERBOARD MODELS ===============

class Leaderboard(db.Model):
    """
    Leaderboards for different time periods
    """
    __tablename__ = 'leaderboards'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Leaderboard details
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    
    # Time period
    period_type = db.Column(db.String(20), default='weekly')  # daily, weekly, monthly, all_time
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    is_current = db.Column(db.Boolean, default=True, index=True)
    
    # Scoring criteria
    scoring_type = db.Column(db.String(50), default='xp')  # xp, challenges, quizzes, combo
    
    # Visibility
    is_public = db.Column(db.Boolean, default=True)
    min_level = db.Column(db.Integer, default=1)
    
    # Prizes
    prize_description = db.Column(db.Text)
    prize_xp = db.Column(db.Integer, default=0)
    
    # Statistics
    total_participants = db.Column(db.Integer, default=0)
    avg_score = db.Column(db.Float, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_leaderboard_period', 'period_type', 'start_date'),
        db.Index('idx_leaderboard_current', 'is_current', 'period_type'),
    )
    
    def __repr__(self):
        return f'<Leaderboard {self.id}: {self.name}>'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'period_type': self.period_type,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'is_current': self.is_current,
            'total_participants': self.total_participants,
            'prize_xp': self.prize_xp,
        }


class LeaderboardEntry(db.Model):
    """
    User entries in leaderboards
    """
    __tablename__ = 'leaderboard_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    leaderboard_id = db.Column(db.Integer, db.ForeignKey('leaderboards.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Ranking
    rank = db.Column(db.Integer, default=0)
    previous_rank = db.Column(db.Integer, default=0)
    rank_change = db.Column(db.Integer, default=0)  # positive = up, negative = down
    
    # Scores
    score = db.Column(db.Float, default=0)
    score_breakdown = db.Column(db.Text)  # JSON breakdown of score components
    
    # Statistics for this period
    xp_gained = db.Column(db.Integer, default=0)
    challenges_completed = db.Column(db.Integer, default=0)
    quizzes_completed = db.Column(db.Integer, default=0)
    encryptions_performed = db.Column(db.Integer, default=0)
    streak_days = db.Column(db.Integer, default=0)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_updated = db.Column(db.DateTime)
    
    # Relationships
    leaderboard = db.relationship('Leaderboard', backref=db.backref('entries', lazy=True))
    user = db.relationship('User', backref=db.backref('leaderboard_entries', lazy=True))
    
    __table_args__ = (
        db.UniqueConstraint('leaderboard_id', 'user_id', name='unique_leaderboard_user'),
        db.Index('idx_leaderboard_entry_score', 'leaderboard_id', 'score'),
        db.Index('idx_leaderboard_entry_rank', 'leaderboard_id', 'rank'),
    )
    
    def __repr__(self):
        return f'<LeaderboardEntry {self.leaderboard_id} - {self.user_id} - Rank {self.rank}>'
    
    def get_score_breakdown(self):
        """Get score breakdown as Python dict"""
        try:
            return json.loads(self.score_breakdown) if self.score_breakdown else {}
        except:
            return {}
    
    def update_rank_change(self, new_rank):
        """Update rank and calculate change"""
        self.previous_rank = self.rank
        self.rank = new_rank
        self.rank_change = self.previous_rank - new_rank  # Positive if improved
        self.last_updated = datetime.utcnow()
    
    def to_dict(self, include_user=True):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'rank': self.rank,
            'previous_rank': self.previous_rank,
            'rank_change': self.rank_change,
            'score': self.score,
            'xp_gained': self.xp_gained,
            'challenges_completed': self.challenges_completed,
            'is_active': self.is_active,
        }
        
        if include_user and self.user:
            data['user'] = {
                'id': self.user.id,
                'username': self.user.username,
                'profile_picture': self.user.profile_picture,
                'level': self.user.progress.level if self.user.progress else 1,
            }
        
        return data


# =============== TUTORIAL & CONTENT MODELS ===============

class Tutorial(db.Model):
    """
    Tutorial content
    """
    __tablename__ = 'tutorials'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Tutorial metadata
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    subtitle = db.Column(db.String(300))
    excerpt = db.Column(db.Text)
    
    # Content
    content = db.Column(db.Text, nullable=False)
    
    # Categorization
    category = db.Column(db.String(50), nullable=False, index=True)
    difficulty = db.Column(db.String(20), default='beginner', index=True)
    
    # Target cipher
    cipher_name = db.Column(db.String(50), index=True)
    
    # Learning info
    estimated_time = db.Column(db.Integer)  # in minutes
    
    # Statistics
    view_count = db.Column(db.Integer, default=0)
    completion_count = db.Column(db.Integer, default=0)
    
    # Status
    is_published = db.Column(db.Boolean, default=False, index=True)
    is_featured = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    
    # Ordering
    display_order = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Tutorial {self.id}: {self.title}>'
    
    def increment_view(self):
        """Increment view count"""
        self.view_count += 1
    
    def to_dict(self, include_content=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'title': self.title,
            'slug': self.slug,
            'excerpt': self.excerpt,
            'category': self.category,
            'difficulty': self.difficulty,
            'cipher_name': self.cipher_name,
            'estimated_time': self.estimated_time,
            'view_count': self.view_count,
            'is_premium': self.is_premium,
            'is_featured': self.is_featured,
            'created_at': self.created_at.isoformat(),
        }
        
        if include_content:
            data['content'] = self.content
        
        return data


class TutorialProgress(db.Model):
    """
    User progress in tutorials
    """
    __tablename__ = 'tutorial_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tutorial_id = db.Column(db.Integer, db.ForeignKey('tutorials.id'), nullable=False)
    
    # Progress tracking
    status = db.Column(db.String(20), default='not_started')  # not_started, in_progress, completed
    completion_percentage = db.Column(db.Integer, default=0)
    current_section = db.Column(db.String(100))
    
    # Time tracking
    first_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    time_spent_seconds = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime)
    
    # User interaction
    notes = db.Column(db.Text)
    rating = db.Column(db.Integer)  # 1-5
    
    # Bookmark
    is_bookmarked = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('tutorial_progress', lazy=True))
    tutorial = db.relationship('Tutorial', backref=db.backref('user_progress', lazy=True))
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'tutorial_id', name='unique_user_tutorial'),
        db.Index('idx_tutorial_progress_user', 'user_id', 'status'),
        db.Index('idx_tutorial_progress_tutorial', 'tutorial_id', 'status'),
    )
    
    def __repr__(self):
        return f'<TutorialProgress {self.user_id} - {self.tutorial_id} - {self.completion_percentage}%>'
    
    def update_progress(self, percentage, current_section=None):
        """Update progress percentage"""
        self.completion_percentage = min(100, max(0, percentage))
        self.current_section = current_section
        self.last_accessed = datetime.utcnow()
        
        # Update status
        if self.completion_percentage == 0:
            self.status = 'not_started'
        elif self.completion_percentage == 100:
            self.status = 'completed'
            if not self.completed_at:
                self.completed_at = datetime.utcnow()
        else:
            self.status = 'in_progress'
    
    def add_time(self, seconds):
        """Add time spent on tutorial"""
        self.time_spent_seconds += seconds
        self.last_accessed = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'tutorial_id': self.tutorial_id,
            'tutorial_title': self.tutorial.title if self.tutorial else None,
            'status': self.status,
            'completion_percentage': self.completion_percentage,
            'current_section': self.current_section,
            'time_spent_minutes': self.time_spent_seconds // 60,
            'first_accessed': self.first_accessed.isoformat(),
            'last_accessed': self.last_accessed.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'is_bookmarked': self.is_bookmarked,
            'rating': self.rating,
        }


# =============== SUPPORT MODELS ===============

class ContactMessage(db.Model):
    """
    Contact form messages
    """
    __tablename__ = 'contact_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Sender information
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Message details
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='general')  # bug, feature, question, feedback
    
    # Status
    status = db.Column(db.String(20), default='new')  # new, read, replied, closed
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    
    # Response tracking
    response = db.Column(db.Text)
    responded_at = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[user_id],
                            backref=db.backref('contact_messages', lazy=True))
    
    __table_args__ = (
        db.Index('idx_contact_status', 'status', 'priority'),
        db.Index('idx_contact_email', 'email'),
    )
    
    def __repr__(self):
        return f'<ContactMessage {self.id}: {self.subject}>'
    
    def mark_as_read(self):
        """Mark message as read"""
        if self.status == 'new':
            self.status = 'read'
    
    def add_response(self, response_text):
        """Add response to message"""
        self.response = response_text
        self.responded_at = datetime.utcnow()
        self.status = 'replied'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'subject': self.subject,
            'message': self.message[:500] + '...' if len(self.message) > 500 else self.message,
            'category': self.category,
            'status': self.status,
            'priority': self.priority,
            'created_at': self.created_at.isoformat(),
            'has_response': bool(self.response),
        }


class Notification(db.Model):
    """
    User notifications
    """
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Notification details
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default='info')  # info, success, warning, error
    icon = db.Column(db.String(50))
    
    # Action
    action_url = db.Column(db.String(500))
    action_text = db.Column(db.String(100))
    
    # Status
    is_read = db.Column(db.Boolean, default=False, index=True)
    is_important = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime)
    
    # Metadata
    source_type = db.Column(db.String(50))  # system, achievement, challenge, message
    source_id = db.Column(db.Integer)  # ID of source item
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    
    __table_args__ = (
        db.Index('idx_notification_user_unread', 'user_id', 'is_read', 'created_at'),
    )
    
    def __repr__(self):
        return f'<Notification {self.id}: {self.title}>'
    
    def mark_as_read(self):
        """Mark notification as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.notification_type,
            'icon': self.icon,
            'action_url': self.action_url,
            'action_text': self.action_text,
            'is_read': self.is_read,
            'is_important': self.is_important,
            'created_at': self.created_at.isoformat(),
            'source_type': self.source_type,
            'source_id': self.source_id,
        }


# =============== SYSTEM MODELS ===============

class SystemLog(db.Model):
    """
    System logging for debugging and monitoring
    """
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Log details
    level = db.Column(db.String(20), default='info')  # debug, info, warning, error, critical
    module = db.Column(db.String(100))  # Module/component where log originated
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)  # JSON with additional details
    
    # User context
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Request context
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    request_path = db.Column(db.String(500))
    
    # Error tracking
    error_type = db.Column(db.String(100))
    error_traceback = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('system_logs', lazy=True))
    
    __table_args__ = (
        db.Index('idx_log_level_time', 'level', 'created_at'),
        db.Index('idx_log_module', 'module', 'created_at'),
    )
    
    def __repr__(self):
        return f'<SystemLog {self.id}: {self.level} - {self.message[:50]}...>'
    
    def get_details(self):
        """Get details as Python dict"""
        try:
            return json.loads(self.details) if self.details else {}
        except:
            return {}


class AppSetting(db.Model):
    """
    Application settings and configuration
    """
    __tablename__ = 'app_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')  # string, integer, float, boolean, json
    category = db.Column(db.String(50), default='general')
    description = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_setting_key', 'key'),
        db.Index('idx_setting_category', 'category'),
    )
    
    def __repr__(self):
        return f'<AppSetting {self.key}>'
    
    def get_value(self):
        """Get typed value"""
        if self.value_type == 'integer':
            return int(self.value) if self.value else 0
        elif self.value_type == 'float':
            return float(self.value) if self.value else 0.0
        elif self.value_type == 'boolean':
            return self.value.lower() == 'true' if self.value else False
        elif self.value_type == 'json':
            try:
                return json.loads(self.value) if self.value else {}
            except:
                return {}
        else:  # string
            return self.value or ''
    
    def set_value(self, new_value):
        """Set value with automatic type detection"""
        if isinstance(new_value, bool):
            self.value_type = 'boolean'
            self.value = 'true' if new_value else 'false'
        elif isinstance(new_value, int):
            self.value_type = 'integer'
            self.value = str(new_value)
        elif isinstance(new_value, float):
            self.value_type = 'float'
            self.value = str(new_value)
        elif isinstance(new_value, (dict, list)):
            self.value_type = 'json'
            self.value = json.dumps(new_value)
        else:
            self.value_type = 'string'
            self.value = str(new_value)


# =============== HELPER FUNCTIONS ===============

def get_user_by_id(user_id):
    """Get user by ID with error handling"""
    return User.query.get(user_id)


def get_user_by_username(username):
    """Get user by username"""
    return User.query.filter_by(username=username).first()


def get_user_by_email(email):
    """Get user by email"""
    return User.query.filter_by(email=email).first()


def create_user(username, email, password):
    """Create new user with progress and settings"""
    user = User(username=username, email=email)
    user.set_password(password)
    return user


def log_activity(user_id, activity_type, description, **kwargs):
    """Log user activity"""
    activity = UserActivity(
        user_id=user_id,
        activity_type=activity_type,
        description=description,
        **kwargs
    )
    return activity