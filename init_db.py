import sqlite3

DB_NAME = "userdata.db"

def create_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Tabla usuarios
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'cliente'
    );
    """)

    # Tabla viajes
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS viajes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_email TEXT NOT NULL,
        origen TEXT NOT NULL,
        destino TEXT NOT NULL,
        distancia_km REAL NOT NULL,
        pago_metodo TEXT NOT NULL,
        estado TEXT NOT NULL DEFAULT 'pendiente',
        conductor_email TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(cliente_email) REFERENCES usuarios(email),
        FOREIGN KEY(conductor_email) REFERENCES usuarios(email)
    );
    """)

    conn.commit()
    conn.close()

    print("✅ BD creada y tablas listas.")

if __name__ == "__main__":
    create_db()