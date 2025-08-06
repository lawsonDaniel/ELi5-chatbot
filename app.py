from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
import google.generativeai as genai

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this in production

# Configure Gemini AI
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')
else:
    model = None
    print("Warning: GEMINI_API_KEY not found. Chat functionality will be limited.")

# Database setup
def init_db():
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Chat history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            response TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Database helper functions
def get_user_by_email(email):
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email, password):
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
                      (email, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def save_chat(user_id, message, response):
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO chat_history (user_id, message, response) VALUES (?, ?, ?)',
                  (user_id, message, response))
    conn.commit()
    conn.close()

def get_chat_history(user_id):
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT message, response, created_at FROM chat_history WHERE user_id = ? ORDER BY created_at',
                  (user_id,))
    history = cursor.fetchall()
    conn.close()
    return history

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if not email or not password:
            flash('Please fill in all fields')
            return render_template('register.html')
        
        if get_user_by_email(email):
            flash('Email already registered')
            return render_template('register.html')
        
        user_id = create_user(email, password)
        if user_id:
            session['user_id'] = user_id
            session['email'] = email
            flash('Registration successful!')
            return redirect(url_for('chat'))
        else:
            flash('Registration failed')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = get_user_by_email(email)
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['email'] = user[1]
            flash('Login successful!')
            return redirect(url_for('chat'))
        else:
            flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    history = get_chat_history(session['user_id'])
    return render_template('chat.html', history=history, email=session['email'])

@app.route('/ask', methods=['POST'])
def ask():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    user_question = data.get('question', '').strip()
    
    if not user_question:
        return jsonify({'error': 'Please ask a question'}), 400
    
    # Check if Gemini is configured
    if not model:
        return jsonify({'error': 'AI service is not configured. Please set up your Gemini API key.'}), 500
    
    try:
        # Create prompt for explaining like you're 5
        prompt = f"""Please explain the following question in a way that a 5-year-old would understand. 
        Use simple words, fun examples, and maybe compare it to things kids know about like toys, animals, or everyday activities.
        Keep it friendly and engaging.
        
        Question: {user_question}"""
        
        response = model.generate_content(prompt)
        ai_response = response.text
        
        # Save to database
        save_chat(session['user_id'], user_question, ai_response)
        
        return jsonify({
            'question': user_question,
            'response': ai_response
        })
        
    except Exception as e:
        return jsonify({'error': f'Sorry, I had trouble thinking of an answer: {str(e)}'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)