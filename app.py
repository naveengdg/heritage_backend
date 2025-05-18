import os
from flask import Flask, request, jsonify, session
import google.generativeai as genai
from flask_cors import CORS
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Fix CORS for the specific frontend domain

# Remove any existing CORS configuration
if hasattr(app, '_cors_config'):
    del app._cors_config

# Apply new CORS configuration
CORS(app, 
     resources={r"/*": {"origins": ["https://frontend-heritage.onrender.com"], "supports_credentials": True}},
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     expose_headers=["Content-Type", "Authorization"])
app.secret_key = 'your_secret_key_here'  # Change to a strong, random key in production

# Configure session to work better across domains
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Allow cookies over HTTP for testing
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE=None,  # Allow cross-domain cookies
    PERMANENT_SESSION_LIFETIME=86400  # Session lasts for 1 day (in seconds)
)

# Get Gemini API key from environment variable
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    raise RuntimeError('Please set the GEMINI_API_KEY environment variable.')

genai.configure(api_key=GEMINI_API_KEY)

# Use Gemini Pro model
model = genai.GenerativeModel('models/gemini-1.5-flash')

# Language code mapping (for future expansion)
LANG_MAP = {
    'en': 'English',
    'ta': 'Tamil',
}

# Root route for basic testing
@app.route('/')
def root():
    return jsonify({
        'status': 'online',
        'message': 'Heritage Explorer API is running',
        'endpoints': [
            '/register', '/login', '/ask', '/test-db', '/init-db', '/contact-message'
        ]
    })

# Helper function to get a MySQL database connection
def get_db_connection():
    try:
        # Get database credentials from environment variables
        db_host = os.environ.get('DB_HOST', 'localhost')
        db_user = os.environ.get('DB_USER', 'avnadmin')
        db_password = os.environ.get('DB_PASSWORD', '')
        db_name = os.environ.get('DB_NAME', 'defaultdb')
        db_port = int(os.environ.get('DB_PORT', '26016'))  # Convert to integer and use Aiven's default port
        
        # Log connection attempt (without password)
        app.logger.info(f"Attempting to connect to MySQL at {db_host}:{db_port} as {db_user}")
        
        # Aiven MySQL connection parameters
        return mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            ssl_disabled=False,  # Aiven requires SSL
            ssl_verify_cert=False,  # Aiven doesn't use standard SSL verification
            ssl_verify_identity=False,
            ssl_ca=None,
            ssl_cert=None,
            ssl_key=None,
            use_pure=True,  # Use pure Python implementation for better compatibility
            connect_timeout=15  # Increase timeout for slow connections
        )
    except Exception as e:
        app.logger.error(f"Database connection error: {str(e)}")
        raise

# Initialize database tables
def initialize_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Read and execute SQL schema
        with open('schema.sql', 'r') as f:
            sql = f.read()
            # Split SQL statements for compatibility
            statements = sql.split(';')
            for statement in statements:
                if statement.strip():
                    cursor.execute(statement)
            
        conn.commit()
        cursor.close()
        app.logger.info("Database initialized successfully")
        return True
    except Exception as e:
        app.logger.error(f"Database initialization error: {str(e)}")
        return False

# Route to initialize database
@app.route('/init-db', methods=['GET'])
def init_db_route():
    success = initialize_database()
    if success:
        return jsonify({'message': 'Database initialized successfully'})
    else:
        return jsonify({'error': 'Failed to initialize database'}), 500

@app.route('/ask', methods=['POST'])
def ask():
    data = request.get_json()
    question = data.get('question', '').strip()
    language = data.get('language', 'en')
    if not question:
        return jsonify({'error': 'No question provided.'}), 400

    # Prompt Gemini to answer in the correct language
    prompt = question
    if language == 'ta':
        prompt = f"Please answer the following question in Tamil:\n{question}"
    else:
        prompt = f"Please answer the following question in English:\n{question}"

    try:
        response = model.generate_content(prompt)
        answer = response.text.strip()
        return jsonify({'answer': answer})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Test route to verify DB connection
@app.route('/test-db')
def test_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES;")
        tables = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'tables': tables})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    # Basic validation
    if not name or not email or not password:
        return jsonify({'error': 'All fields are required.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if email already exists
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Email already registered.'}), 409

    # Hash the password
    password_hash = generate_password_hash(password)

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
        (name, email, password_hash)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Registration successful!'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, password_hash FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found.'}), 404

    user_id, name, password_hash = user
    if not check_password_hash(password_hash, password):
        return jsonify({'error': 'Incorrect password.'}), 401

    # Instead of using session, return user data directly
    # The frontend will store this in localStorage
    user_data = {
        'id': user_id,
        'name': name,
        'email': email,
        'auth_token': f"{user_id}_{email}_{hash(name + str(user_id))}"
    }

    return jsonify({
        'message': 'Login successful!', 
        'user': user_data,
        'logged_in': True
    })

@app.route('/logout', methods=['POST'])
def logout():
    # With token-based auth, logout is handled client-side
    # by removing the token from localStorage
    # This endpoint just confirms the logout
    return jsonify({
        'message': 'Logged out successfully',
        'logged_in': False
    })

@app.route('/session', methods=['GET', 'POST'])
def check_session():
    # Check for auth token in request headers or JSON body
    auth_token = None
    
    # Check if token is in headers
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        auth_token = auth_header.split(' ')[1]
    
    # If not in headers, check if it's in JSON body
    if not auth_token and request.method == 'POST' and request.is_json:
        data = request.get_json()
        auth_token = data.get('auth_token')
    
    # If we have a token, validate it (in a real app, you'd verify it properly)
    if auth_token:
        try:
            # Simple validation - in production you'd use JWT or similar
            parts = auth_token.split('_')
            if len(parts) >= 2:
                user_id = parts[0]
                email = parts[1]
                
                # Get user from database to verify
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT id, name FROM users WHERE id = %s AND email = %s", (user_id, email))
                user = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if user:
                    user_id, name = user
                    return jsonify({
                        'logged_in': True, 
                        'user': {
                            'id': user_id,
                            'name': name,
                            'email': email
                        }
                    })
        except Exception as e:
            app.logger.error(f"Session validation error: {str(e)}")
    
    # If no token or validation failed
    return jsonify({'logged_in': False})

@app.route('/contact-message', methods=['POST'])
def contact_message():
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    message = data.get('message', '').strip()
    if not name or not email or not message:
        return jsonify({'error': 'All fields are required.'}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO contact_messages (name, email, message) VALUES (%s, %s, %s)
        """, (name, email, message))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'Your message has been received!'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to save your message.'}), 500

# Initialize database on startup
with app.app_context():
    try:
        initialize_database()
        app.logger.info("Database initialized on startup")
    except Exception as e:
        app.logger.error(f"Failed to initialize database on startup: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True)