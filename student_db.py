import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'students.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        mac_address TEXT NOT NULL,
        reference_image_path TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

def add_student(name, email, password, mac_address, image_path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    password_hash = generate_password_hash(password)
    c.execute('INSERT INTO students (name, email, password_hash, mac_address, reference_image_path) VALUES (?, ?, ?, ?, ?)',
              (name, email, password_hash, mac_address, image_path))
    conn.commit()
    conn.close()

def get_student_by_email(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM students WHERE email = ?', (email,))
    student = c.fetchone()
    conn.close()
    return student

def verify_student(email, password):
    student = get_student_by_email(email)
    if student and check_password_hash(student[3], password):
        return student
    return None
