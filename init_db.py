# init_db.py
import sqlite3

DB_NAME = "userdata.db"

def create_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'cliente'
    )
    """)

    conn.commit()
    conn.close()
    print("✅ BD creada y tabla 'usuarios' lista.")

if __name__ == "__main__":
    create_db()
