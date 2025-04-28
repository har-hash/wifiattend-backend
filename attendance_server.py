import os
import re
import sqlite3
from flask import Flask, jsonify, request
from datetime import datetime
import numpy as np
import face_recognition
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB_PATH = 'attendance.db'

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Users: id, name, email, password_hash, mac_address, face_embedding
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        mac_address TEXT NOT NULL UNIQUE,
        face_embedding BLOB
    )''')
    # Attendance: id, user_id, timestamp
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

init_db()

# --- Helper: Scan Network ---
def scan_network():
    # Use 'arp -a' to get IP and MAC addresses of connected devices
    arp_output = os.popen('arp -a').read()
    # Regex for MAC address
    mac_regex = r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))'
    # Find all MACs
    macs = re.findall(mac_regex, arp_output)
    found_macs = set([m[0].lower() for m in macs])
    return found_macs

# --- API: Register User ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    mac = data.get('mac_address').lower()
    if not (name and email and password and mac):
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    password_hash = generate_password_hash(password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (name, email, password_hash, mac_address) VALUES (?, ?, ?, ?)',
                  (name, email, password_hash, mac))
        conn.commit()
        return jsonify({'success': True}), 201
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Email or MAC already registered'}), 409
    finally:
        conn.close()

# --- API: Register Face ---
@app.route('/register_face', methods=['POST'])
def register_face():
    name = request.form.get('name')
    mac = request.form.get('mac_address', '').lower()
    file = request.files.get('face_image')
    if not (name and file):
        return jsonify({'success': False, 'error': 'Missing name or face image'}), 400
    # Save file temporarily
    filename = secure_filename(file.filename)
    filepath = f'tmp_{filename}'
    file.save(filepath)
    # Extract face embedding
    image = face_recognition.load_image_file(filepath)
    encodings = face_recognition.face_encodings(image)
    if not encodings:
        os.remove(filepath)
        return jsonify({'success': False, 'error': 'No face found in image'}), 400
    embedding = encodings[0]
    embedding_bytes = embedding.tobytes()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # Insert or update user with embedding
        c.execute('''INSERT INTO users (name, mac_address, face_embedding) VALUES (?, ?, ?)
                     ON CONFLICT(mac_address) DO UPDATE SET face_embedding=excluded.face_embedding, name=excluded.name''',
                  (name, mac, embedding_bytes))
        conn.commit()
        return jsonify({'success': True}), 201
    finally:
        conn.close()
        os.remove(filepath)

# --- API: Login User ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    email = data.get('email')
    password = data.get('password')
    if not (email and password):
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, name, email, password_hash FROM users WHERE email=?', (email,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row[3], password):
        return jsonify({'success': True, 'user': {'id': row[0], 'name': row[1], 'email': row[2]}})
    else:
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

# --- API: Verify Face ---
@app.route('/verify_face', methods=['POST'])
def verify_face():
    file = request.files.get('face_image')
    if not file:
        return jsonify({'success': False, 'error': 'No face image provided'}), 400
    filename = secure_filename(file.filename)
    filepath = f'tmp_{filename}'
    file.save(filepath)
    image = face_recognition.load_image_file(filepath)
    encodings = face_recognition.face_encodings(image)
    if not encodings:
        os.remove(filepath)
        return jsonify({'success': False, 'error': 'No face found in image'}), 400
    embedding = encodings[0]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, name, email, mac_address, face_embedding FROM users WHERE face_embedding IS NOT NULL')
    users = c.fetchall()
    min_dist = float('inf')
    matched_user = None
    for user_id, name, email, mac, emb_bytes in users:
        db_emb = np.frombuffer(emb_bytes, dtype=np.float64)
        dist = np.linalg.norm(embedding - db_emb)
        if dist < 0.6 and dist < min_dist:  # 0.6 is a typical threshold
            min_dist = dist
            matched_user = {'id': user_id, 'name': name, 'email': email, 'mac_address': mac}
    conn.close()
    os.remove(filepath)
    if matched_user:
        return jsonify({'success': True, 'user': matched_user})
    else:
        return jsonify({'success': False, 'error': 'No match found'}), 404

# --- API: Get User ID by Email ---
@app.route('/get_user_id', methods=['GET'])
def get_user_id():
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE email=?', (email,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({'id': row[0]}), 200
    else:
        return jsonify({'error': 'User not found'}), 404

# --- API: Trigger Scan and Record Attendance ---
@app.route('/scan_and_record', methods=['POST'])
def scan_and_record():
    found_macs = scan_network()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, mac_address FROM users')
    users = c.fetchall()
    now = datetime.now().isoformat()
    attended = []
    for user_id, mac in users:
        if mac.lower() in found_macs:
            # Check if already marked today
            c.execute('SELECT * FROM attendance WHERE user_id=? AND date(timestamp)=date(?)', (user_id, now))
            if not c.fetchone():
                c.execute('INSERT INTO attendance (user_id, timestamp) VALUES (?, ?)', (user_id, now))
                attended.append(mac)
    conn.commit()
    conn.close()
    return jsonify({'attended': attended, 'count': len(attended)})

# --- API: Get Attendance Log ---
@app.route('/attendance', methods=['GET'])
def get_attendance():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT users.name, users.mac_address, attendance.timestamp
                 FROM attendance JOIN users ON attendance.user_id = users.id
                 ORDER BY attendance.timestamp DESC''')
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {'name': name, 'mac_address': mac, 'timestamp': timestamp}
        for name, mac, timestamp in rows
    ])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
