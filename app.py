import os
from flask import Flask, request, jsonify, session
import google.generativeai as genai
from flask_cors import CORS
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:8000"])
app.secret_key = 'your_secret_key_here'  # Change to a strong, random key in production

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

# Helper function to get a MySQL database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",  # Change to 'heritage_user' if you created that user
        password="220701183",  # <-- Replace with your MySQL password
        database="heritage_explorer"
    )

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

    # Set session
    session['user_id'] = user_id
    session['user_name'] = name
    session['user_email'] = email

    return jsonify({'message': 'Login successful!', 'user': {'id': user_id, 'name': name, 'email': email}})

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/session')
def check_session():
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'user': {
            'id': session['user_id'],
            'name': session['user_name'],
            'email': session['user_email']
        }})
    else:
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

if __name__ == '__main__':
    app.run(debug=True) 