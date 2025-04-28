import sqlite3

db_path = 'attendance.db'  # Change if your DB file is named differently

conn = sqlite3.connect(db_path)
c = conn.cursor()
try:
    c.execute("ALTER TABLE users ADD COLUMN face_token TEXT;")
    print("face_token column added successfully.")
except Exception as e:
    print("Error:", e)
finally:
    conn.commit()
    conn.close()
