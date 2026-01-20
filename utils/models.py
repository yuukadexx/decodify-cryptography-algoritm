# utils/models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, date
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets

# Initialize SQLAlchemy
db = SQLAlchemy()

# Argon2 hasher
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)


# =============== USER MODELS ===============
class User(UserMixin, db.Model):
    """User model for authentication and user management"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    premium_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    progress = db.relationship('UserProgress', backref='user', uselist=False, lazy=True)
    activities = db.relationship('UserActivity', backref='user', lazy=True, cascade='all, delete-orphan')
    cipher_usages = db.relationship('CipherUsage', backref='user', lazy=True, cascade='all, delete-orphan')
    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True, cascade='all, delete-orphan')
    challenge_attempts = db.relationship('ChallengeAttempt', backref='user', lazy=True, cascade='all, delete-orphan')
    user_achievements = db.relationship('UserAchievement', backref='user', lazy=True, cascade='all, delete-orphan')
    bookmarks = db.relationship('UserBookmark', backref='user', lazy=True, cascade='all, delete-orphan')
    search_history = db.relationship('SearchHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    
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
    
    def get_progress(self):
        """Get or create user progress"""
        progress = UserProgress.query.filter_by(user_id=self.id).first()
        if not progress:
            progress = UserProgress(user_id=self.id)
            db.session.add(progress)
            db.session.commit()
        return progress
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def get_stats(self):
        """Get user statistics"""
        progress = self.get_progress()
        return {
            'username': self.username,
            'email': self.email,
            'level': progress.level,
            'xp': progress.xp,
            'challenges_completed': progress.challenges_completed,
            'encryptions_performed': progress.encryptions_performed,
            'learning_time_minutes': progress.learning_time_minutes,
            'current_streak': progress.current_streak,
            'is_premium': self.is_premium,
            'created_at': self.created_at
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class UserProgress(db.Model):
    """User progress and statistics"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    level = db.Column(db.Integer, default=1)
    xp = db.Column(db.Integer, default=0)
    challenges_completed = db.Column(db.Integer, default=0)
    encryptions_performed = db.Column(db.Integer, default=0)
    learning_time_minutes = db.Column(db.Integer, default=0)
    current_streak = db.Column(db.Integer, default=0)
    last_active_date = db.Column(db.Date, default=date.today)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def add_xp(self, xp_earned, activity_type="general"):
        """Add XP to user and check for level up"""
        old_level = self.level
        self.xp += xp_earned
        
        # Check level up (100 XP per level)
        new_level = (self.xp // 100) + 1
        if new_level > old_level:
            self.level = new_level
            # Log level up activity
            from utils.models import UserActivity
            activity = UserActivity(
                user_id=self.user_id,
                activity_type='level_up',
                description=f'Level up dari {old_level} ke {new_level}!',
                xp_gained=xp_earned
            )
            db.session.add(activity)
        
        # Update streak
        today = date.today()
        if self.last_active_date != today:
            if (today - self.last_active_date).days == 1:
                self.current_streak += 1
            else:
                self.current_streak = 1
            self.last_active_date = today
        
        db.session.commit()
        return self
    
    def __repr__(self):
        return f'<UserProgress {self.user_id} Level {self.level}>'


class UserActivity(db.Model):
    """User activity log"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    cipher_name = db.Column(db.String(50), nullable=True)
    xp_gained = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<UserActivity {self.activity_type} - {self.user_id}>'


# =============== ACHIEVEMENT MODELS ===============
class Achievement(db.Model):
    """Achievements available in the system"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    icon = db.Column(db.String(50))
    xp_reward = db.Column(db.Integer, default=100)
    requirement = db.Column(db.String(100))
    difficulty = db.Column(db.String(20), default='easy')
    category = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user_achievements = db.relationship('UserAchievement', backref='achievement', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Achievement {self.name}>'


class UserAchievement(db.Model):
    """User's unlocked achievements"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievement.id'), nullable=False)
    unlocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate achievements
    __table_args__ = (db.UniqueConstraint('user_id', 'achievement_id', name='unique_user_achievement'),)
    
    def __repr__(self):
        return f'<UserAchievement User:{self.user_id} Achievement:{self.achievement_id}>'


# =============== CIPHER MODELS ===============
class CipherUsage(db.Model):
    """Track cipher usage by users"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cipher_name = db.Column(db.String(50), nullable=False)
    usage_count = db.Column(db.Integer, default=0)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint for user and cipher combination
    __table_args__ = (db.UniqueConstraint('user_id', 'cipher_name', name='unique_user_cipher'),)
    
    def increment_usage(self):
        """Increment usage count and update last used timestamp"""
        self.usage_count += 1
        self.last_used = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<CipherUsage {self.cipher_name} - User:{self.user_id}>'


# =============== QUIZ MODELS ===============
class QuizQuestion(db.Model):
    """Quiz questions for different ciphers"""
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
    category = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_options(self):
        """Get all options as a list"""
        return [self.option_a, self.option_b, self.option_c, self.option_d]
    
    def check_answer(self, selected_option):
        """Check if selected option is correct"""
        return selected_option == self.correct_answer
    
    def __repr__(self):
        return f'<QuizQuestion {self.cipher_name} - {self.id}>'


class QuizAttempt(db.Model):
    """User's quiz attempts"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cipher_name = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, default=0)
    total_questions = db.Column(db.Integer, default=0)
    percentage = db.Column(db.Float, default=0.0)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    time_taken = db.Column(db.Integer, default=0)  # in seconds
    details = db.Column(db.Text, nullable=True)  # JSON details of attempt
    
    def calculate_percentage(self):
        """Calculate percentage score"""
        if self.total_questions > 0:
            self.percentage = (self.score / self.total_questions) * 100
        return self.percentage
    
    def __repr__(self):
        return f'<QuizAttempt {self.cipher_name} - Score:{self.score}/{self.total_questions}>'


# =============== CHALLENGE MODELS ===============
class Challenge(db.Model):
    """Cipher challenges for users to solve"""
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
    solution_hint = db.Column(db.String(500), nullable=True)
    tags = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    attempts = db.relationship('ChallengeAttempt', backref='challenge', lazy=True, cascade='all, delete-orphan')
    
    def check_solution(self, user_answer):
        """Check if user's answer matches the solution"""
        # Remove extra spaces and convert to uppercase for comparison
        clean_user_answer = user_answer.strip().upper()
        clean_solution = self.plaintext.strip().upper()
        
        # Allow some flexibility in answers
        if self.category == 'analysis':
            return clean_user_answer.replace(' ', '') == clean_solution.replace(' ', '')
        elif self.category == 'matrix':
            try:
                # Handle matrix comparisons
                import ast
                user_matrix = ast.literal_eval(clean_user_answer)
                solution_matrix = ast.literal_eval(clean_solution)
                return str(user_matrix) == str(solution_matrix)
            except:
                return clean_user_answer == clean_solution
        else:
            return clean_user_answer == clean_solution
    
    def __repr__(self):
        return f'<Challenge {self.title} - {self.cipher_name}>'


class ChallengeAttempt(db.Model):
    """User's challenge attempts"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)
    user_answer = db.Column(db.String(500), nullable=True)
    is_correct = db.Column(db.Boolean, default=False)
    xp_earned = db.Column(db.Integer, default=0)
    
    # Unique constraint to prevent duplicate attempts tracking
    __table_args__ = (db.UniqueConstraint('user_id', 'challenge_id', name='unique_user_challenge'),)
    
    def record_attempt(self, user_answer, is_correct):
        """Record a new attempt"""
        self.attempts += 1
        self.last_attempt = datetime.utcnow()
        self.user_answer = user_answer
        self.is_correct = is_correct
        
        if is_correct and not self.completed:
            self.completed = True
            self.completed_at = datetime.utcnow()
            # Get XP reward from challenge
            challenge = Challenge.query.get(self.challenge_id)
            if challenge:
                self.xp_earned = challenge.xp_reward
        
        db.session.commit()
        return self
    
    def __repr__(self):
        return f'<ChallengeAttempt Challenge:{self.challenge_id} - User:{self.user_id}>'


# =============== GLOSSARY MODELS ===============
class GlossaryTerm(db.Model):
    """Cryptography glossary terms"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    pronunciation = db.Column(db.String(100))
    definition = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    difficulty = db.Column(db.String(20), default='beginner')
    letter = db.Column(db.String(1), nullable=False)
    year = db.Column(db.String(20))
    inventor = db.Column(db.String(200))
    application = db.Column(db.String(500))
    example = db.Column(db.Text)
    footnote = db.Column(db.Text)
    tags = db.Column(db.String(500))
    view_count = db.Column(db.Integer, default=0)
    bookmarked_count = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    bookmarks = db.relationship('UserBookmark', backref='term', lazy=True, cascade='all, delete-orphan')
    
    def increment_view_count(self):
        """Increment view count"""
        self.view_count += 1
        db.session.commit()
    
    def get_tags_list(self):
        """Get tags as list"""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',')]
        return []
    
    def add_tags(self, new_tags):
        """Add new tags"""
        existing_tags = self.get_tags_list()
        existing_tags.extend(new_tags)
        # Remove duplicates
        existing_tags = list(set(existing_tags))
        self.tags = ','.join(existing_tags)
        db.session.commit()
    
    def __repr__(self):
        return f'<GlossaryTerm {self.title}>'


class GlossaryCategory(db.Model):
    """Glossary categories"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    icon = db.Column(db.String(50))
    term_count = db.Column(db.Integer, default=0)
    display_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def update_term_count(self):
        """Update term count for this category"""
        count = GlossaryTerm.query.filter_by(category=self.name, is_active=True).count()
        self.term_count = count
        db.session.commit()
    
    def __repr__(self):
        return f'<GlossaryCategory {self.name}>'


class UserBookmark(db.Model):
    """User's bookmarked glossary terms"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    term_id = db.Column(db.Integer, db.ForeignKey('glossary_term.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate bookmarks
    __table_args__ = (db.UniqueConstraint('user_id', 'term_id', name='unique_user_bookmark'),)
    
    def __repr__(self):
        return f'<UserBookmark User:{self.user_id} Term:{self.term_id}>'


class SearchHistory(db.Model):
    """User's search history"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    query = db.Column(db.String(200), nullable=False)
    results_count = db.Column(db.Integer, default=0)
    searched_at = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default='glossary')  # 'glossary', 'challenges', etc.
    
    def __repr__(self):
        return f'<SearchHistory {self.query} - {self.user_id}>'


# =============== TUTORIAL MODELS ===============
class Tutorial(db.Model):
    """Tutorial content"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subtitle = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    cipher_name = db.Column(db.String(50), nullable=False)
    difficulty = db.Column(db.String(20), default='beginner')
    category = db.Column(db.String(50))
    tags = db.Column(db.String(200))
    view_count = db.Column(db.Integer, default=0)
    is_published = db.Column(db.Boolean, default=True)
    author = db.Column(db.String(100), default='System')
    estimated_time = db.Column(db.Integer, default=10)  # in minutes
    prerequisites = db.Column(db.String(200))
    learning_objectives = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def increment_view_count(self):
        """Increment view count"""
        self.view_count += 1
        db.session.commit()
    
    def __repr__(self):
        return f'<Tutorial {self.title}>'


class TutorialProgress(db.Model):
    """User's tutorial progress"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tutorial_id = db.Column(db.Integer, db.ForeignKey('tutorial.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    time_spent = db.Column(db.Integer, default=0)  # in minutes
    current_page = db.Column(db.Integer, default=1)
    notes = db.Column(db.Text)
    rating = db.Column(db.Integer, nullable=True)  # 1-5 stars
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'tutorial_id', name='unique_user_tutorial'),)
    
    def __repr__(self):
        return f'<TutorialProgress Tutorial:{self.tutorial_id} - User:{self.user_id}>'


# =============== COMMUNITY MODELS ===============
class ForumTopic(db.Model):
    """Forum topics"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), default='general')
    tags = db.Column(db.String(200))
    view_count = db.Column(db.Integer, default=0)
    reply_count = db.Column(db.Integer, default=0)
    is_pinned = db.Column(db.Boolean, default=False)
    is_locked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('forum_topics', lazy=True))
    replies = db.relationship('ForumReply', backref='topic', lazy=True, cascade='all, delete-orphan')
    
    def increment_view_count(self):
        """Increment view count"""
        self.view_count += 1
        db.session.commit()
    
    def update_reply_count(self):
        """Update reply count"""
        count = ForumReply.query.filter_by(topic_id=self.id, is_active=True).count()
        self.reply_count = count
        db.session.commit()
    
    def __repr__(self):
        return f'<ForumTopic {self.title}>'


class ForumReply(db.Model):
    """Forum replies"""
    id = db.Column(db.Integer, primary_key=True)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topic.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_answer = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('forum_replies', lazy=True))
    
    def __repr__(self):
        return f'<ForumReply Topic:{self.topic_id} - User:{self.user_id}>'


# =============== LEADERBOARD MODELS ===============
class DailyLeaderboard(db.Model):
    """Daily leaderboard entries"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, default=date.today)
    xp_earned = db.Column(db.Integer, default=0)
    challenges_completed = db.Column(db.Integer, default=0)
    quizzes_completed = db.Column(db.Integer, default=0)
    rank = db.Column(db.Integer, nullable=True)
    streak_days = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='unique_user_daily'),)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('daily_scores', lazy=True))
    
    def __repr__(self):
        return f'<DailyLeaderboard {self.date} - User:{self.user_id}>'


class MonthlyLeaderboard(db.Model):
    """Monthly leaderboard entries"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    total_xp = db.Column(db.Integer, default=0)
    total_challenges = db.Column(db.Integer, default=0)
    total_quizzes = db.Column(db.Integer, default=0)
    average_score = db.Column(db.Float, default=0.0)
    rank = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('user_id', 'year', 'month', name='unique_user_monthly'),)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('monthly_scores', lazy=True))
    
    def __repr__(self):
        return f'<MonthlyLeaderboard {self.year}-{self.month} - User:{self.user_id}>'


# =============== SYSTEM MODELS ===============
class SystemLog(db.Model):
    """System logs for debugging and monitoring"""
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)  # INFO, WARNING, ERROR, DEBUG
    module = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('system_logs', lazy=True))
    
    def __repr__(self):
        return f'<SystemLog {self.level} - {self.module}>'


class AppSettings(db.Model):
    """Application settings"""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50), default='general')
    data_type = db.Column(db.String(20), default='string')  # string, integer, boolean, json
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_value(self):
        """Get value with proper type conversion"""
        if self.data_type == 'integer':
            return int(self.value)
        elif self.data_type == 'boolean':
            return self.value.lower() in ('true', '1', 'yes')
        elif self.data_type == 'json':
            import json
            return json.loads(self.value)
        else:
            return self.value
    
    def set_value(self, value):
        """Set value with proper type conversion"""
        if self.data_type == 'integer':
            self.value = str(int(value))
        elif self.data_type == 'boolean':
            self.value = 'true' if value else 'false'
        elif self.data_type == 'json':
            import json
            self.value = json.dumps(value)
        else:
            self.value = str(value)
    
    def __repr__(self):
        return f'<AppSettings {self.key}>'


# =============== HELPER FUNCTIONS ===============
def get_user_progress(user_id):
    """Get or create user progress (for backward compatibility)"""
    progress = UserProgress.query.filter_by(user_id=user_id).first()
    if not progress:
        progress = UserProgress(user_id=user_id)
        db.session.add(progress)
        db.session.commit()
    return progress


def update_user_xp(user_id, xp_earned, activity_type="quiz", cipher_name=None):
    """Update user XP and log activity"""
    progress = get_user_progress(user_id)
    progress.add_xp(xp_earned)
    
    # Log activity
    activity = UserActivity(
        user_id=user_id,
        activity_type=activity_type,
        description=f'Mendapatkan {xp_earned} XP dari {activity_type}',
        cipher_name=cipher_name,
        xp_gained=xp_earned
    )
    db.session.add(activity)
    db.session.commit()
    
    return progress


def log_cipher_usage(user_id, cipher_name):
    """Log cipher usage for statistics"""
    usage = CipherUsage.query.filter_by(user_id=user_id, cipher_name=cipher_name).first()
    if usage:
        usage.increment_usage()
    else:
        usage = CipherUsage(
            user_id=user_id,
            cipher_name=cipher_name,
            usage_count=1
        )
        db.session.add(usage)
    
    # Update user progress
    progress = get_user_progress(user_id)
    progress.encryptions_performed += 1
    db.session.commit()


# =============== INITIALIZATION FUNCTIONS ===============
def init_default_settings():
    """Initialize default application settings"""
    default_settings = [
        {
            'key': 'app_name',
            'value': 'DecoDify',
            'description': 'Application name',
            'category': 'general',
            'data_type': 'string',
            'is_public': True
        },
        {
            'key': 'app_version',
            'value': '1.0.0',
            'description': 'Application version',
            'category': 'general',
            'data_type': 'string',
            'is_public': True
        },
        {
            'key': 'maintenance_mode',
            'value': 'false',
            'description': 'Enable maintenance mode',
            'category': 'system',
            'data_type': 'boolean',
            'is_public': False
        },
        {
            'key': 'enable_registration',
            'value': 'true',
            'description': 'Allow new user registration',
            'category': 'security',
            'data_type': 'boolean',
            'is_public': False
        },
        {
            'key': 'max_login_attempts',
            'value': '5',
            'description': 'Maximum login attempts before lockout',
            'category': 'security',
            'data_type': 'integer',
            'is_public': False
        },
        {
            'key': 'session_timeout',
            'value': '1800',
            'description': 'Session timeout in seconds',
            'category': 'security',
            'data_type': 'integer',
            'is_public': False
        },
        {
            'key': 'default_xp_per_question',
            'value': '10',
            'description': 'Default XP reward per quiz question',
            'category': 'gamification',
            'data_type': 'integer',
            'is_public': False
        },
        {
            'key': 'default_xp_per_challenge',
            'value': '25',
            'description': 'Default XP reward per challenge',
            'category': 'gamification',
            'data_type': 'integer',
            'is_public': False
        },
        {
            'key': 'xp_per_level',
            'value': '100',
            'description': 'XP required per level',
            'category': 'gamification',
            'data_type': 'integer',
            'is_public': True
        },
    ]
    
    for setting_data in default_settings:
        if not AppSettings.query.filter_by(key=setting_data['key']).first():
            setting = AppSettings(**setting_data)
            db.session.add(setting)
    
    db.session.commit()


def init_default_achievements():
    """Initialize default achievements"""
    default_achievements = [
        {
            'name': 'Caesar Novice',
            'description': 'Selesaikan quiz Caesar Cipher pertama',
            'icon': 'fas fa-crown',
            'xp_reward': 50,
            'requirement': 'complete_caesar_quiz',
            'difficulty': 'easy',
            'category': 'beginner'
        },
        {
            'name': 'Shift Master',
            'description': 'Selesaikan semua challenge Caesar Cipher',
            'icon': 'fas fa-trophy',
            'xp_reward': 100,
            'requirement': 'complete_all_caesar_challenges',
            'difficulty': 'medium',
            'category': 'caesar'
        },
        {
            'name': 'Vigenere Explorer',
            'description': 'Selesaikan quiz Vigenere Cipher',
            'icon': 'fas fa-key',
            'xp_reward': 75,
            'requirement': 'complete_vigenere_quiz',
            'difficulty': 'medium',
            'category': 'vigenere'
        },
        {
            'name': 'Polyalphabetic Pro',
            'description': 'Selesaikan semua challenge Vigenere',
            'icon': 'fas fa-lock',
            'xp_reward': 150,
            'requirement': 'complete_all_vigenere_challenges',
            'difficulty': 'hard',
            'category': 'vigenere'
        },
        {
            'name': 'Crypto Learner',
            'description': 'Gunakan 5 cipher berbeda',
            'icon': 'fas fa-graduation-cap',
            'xp_reward': 200,
            'requirement': 'use_5_ciphers',
            'difficulty': 'medium',
            'category': 'general'
        },
        {
            'name': 'Streak Starter',
            'description': 'Login selama 3 hari berturut-turut',
            'icon': 'fas fa-fire',
            'xp_reward': 50,
            'requirement': '3_day_streak',
            'difficulty': 'easy',
            'category': 'general'
        },
        {
            'name': 'Quiz Champion',
            'description': 'Selesaikan 10 quiz dengan skor sempurna',
            'icon': 'fas fa-star',
            'xp_reward': 300,
            'requirement': '10_perfect_quizzes',
            'difficulty': 'hard',
            'category': 'quiz'
        },
        {
            'name': 'Challenge Conqueror',
            'description': 'Selesaikan 25 challenge',
            'icon': 'fas fa-shield-alt',
            'xp_reward': 500,
            'requirement': 'complete_25_challenges',
            'difficulty': 'hard',
            'category': 'challenge'
        },
        {
            'name': 'Glossary Guru',
            'description': 'Bookmark 50 istilah glossary',
            'icon': 'fas fa-book',
            'xp_reward': 250,
            'requirement': 'bookmark_50_terms',
            'difficulty': 'medium',
            'category': 'glossary'
        },
        {
            'name': 'Level 10 Achiever',
            'description': 'Mencapai level 10',
            'icon': 'fas fa-rocket',
            'xp_reward': 1000,
            'requirement': 'reach_level_10',
            'difficulty': 'hard',
            'category': 'level'
        },
    ]
    
    for achievement_data in default_achievements:
        if not Achievement.query.filter_by(name=achievement_data['name']).first():
            achievement = Achievement(**achievement_data)
            db.session.add(achievement)
    
    db.session.commit()


def create_all_tables():
    """Create all database tables"""
    db.create_all()
    print("✅ All database tables created")


def init_database():
    """Initialize database with default data"""
    print("🔧 Initializing database...")
    
    # Create all tables
    create_all_tables()
    
    # Initialize default settings
    init_default_settings()
    print("✅ Default settings initialized")
    
    # Initialize default achievements
    init_default_achievements()
    print("✅ Default achievements initialized")
    
    print("🎉 Database initialization complete!")