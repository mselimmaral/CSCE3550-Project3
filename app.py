from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
import sqlite3
import uuid
import os
import time
from functools import wraps
from datetime import datetime
from collections import deque

app = Flask(__name__)

# Initialize Argon2 hasher with secure defaults
ph = PasswordHasher()

# Initialize AES encryption using environment variable
if 'NOT_MY_KEY' not in os.environ:
    raise ValueError("Encryption key NOT_MY_KEY must be set in environment variables")

# Create Fernet instance for AES encryption
fernet = Fernet(os.environ['NOT_MY_KEY'].encode())

# Rate limiting setup
RATE_LIMIT = 10  # requests per second
rate_limit_window = deque(maxlen=RATE_LIMIT)

def init_db():
    """Initialize database with required tables"""
    with sqlite3.connect('jwks.db') as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        ''')
        
        # Create auth_logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        # Create or modify keys table to include encrypted private keys
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key_data TEXT NOT NULL,
            exp INTEGER NOT NULL,
            encrypted_private_key TEXT
        )
        ''')
        
        conn.commit()

def rate_limit_decorator(f):
    """Decorator to implement rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        now = time.time()
        
        # Remove old timestamps
        while rate_limit_window and now - rate_limit_window[0] > 1:
            rate_limit_window.popleft()
        
        # Check if we're over the limit
        if len(rate_limit_window) >= RATE_LIMIT:
            return jsonify({"error": "Too many requests"}), 429
        
        rate_limit_window.append(now)
        return f(*args, **kwargs)
    return decorated_function

def log_auth_request(user_id):
    """Log authentication request to database"""
    with sqlite3.connect('jwks.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO auth_logs (request_ip, user_id)
        VALUES (?, ?)
        ''', (request.remote_addr, user_id))
        conn.commit()

@app.route('/register', methods=['POST'])
def register():
    """Handle user registration"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        
        if not username or not email:
            return jsonify({"error": "Missing required fields"}), 400
        
        # Generate secure password using UUIDv4
        password = str(uuid.uuid4())
        
        # Hash password using Argon2
        password_hash = ph.hash(password)
        
        with sqlite3.connect('jwks.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO users (username, password_hash, email)
            VALUES (?, ?, ?)
            ''', (username, password_hash, email))
            conn.commit()
        
        return jsonify({"password": password}), 201
        
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth', methods=['POST'])
@rate_limit_decorator
def authenticate():
    """Handle authentication requests"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Missing credentials"}), 400
        
        with sqlite3.connect('jwks.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            
            if not result:
                return jsonify({"error": "Invalid credentials"}), 401
            
            user_id, stored_hash = result
            
            try:
                ph.verify(stored_hash, password)
                # Update last login timestamp
                cursor.execute('''
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP 
                WHERE id = ?
                ''', (user_id,))
                
                # Log successful authentication
                log_auth_request(user_id)
                
                conn.commit()
                return jsonify({"message": "Authentication successful"}), 200
                
            except Exception:
                return jsonify({"error": "Invalid credentials"}), 401
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def encrypt_private_key(private_key):
    """Encrypt private key using AES"""
    return fernet.encrypt(private_key.encode()).decode()

def decrypt_private_key(encrypted_key):
    """Decrypt private key using AES"""
    return fernet.decrypt(encrypted_key.encode()).decode()

# Initialize database when the application starts
init_db()

if __name__ == '__main__':
    app.run(port=8080)
