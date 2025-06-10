
import sqlite3
conn = sqlite3.connect("users.db")
conn.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL
)
''')
conn.commit()
conn.close()
