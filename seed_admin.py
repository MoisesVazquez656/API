"""
Crea el primer usuario administrador directamente en la base de datos.

Uso:
    ADMIN_NOMBRE="Nombre Apellido" ADMIN_EMAIL="admin@sigerutt.com" ADMIN_PASSWORD="una_clave_segura" python seed_admin.py

Solo es necesario ejecutarlo una vez, la primera vez que se levanta la API,
ya que despues de eso el propio administrador puede crear mas usuarios
desde SIGERUTT (POST /api/admin/usuarios).
"""
import os
import sqlite3
import sys

import bcrypt

from init_db import create_db

DB_NAME = os.getenv("DB_PATH", "userdata.db")


def seed_admin():
    nombre = os.getenv("ADMIN_NOMBRE", "").strip()
    email = os.getenv("ADMIN_EMAIL", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "").strip()

    if not nombre or not email or not password:
        print("ERROR: define ADMIN_NOMBRE, ADMIN_EMAIL y ADMIN_PASSWORD como variables de entorno.")
        sys.exit(1)

    if len(password) < 6:
        print("ERROR: ADMIN_PASSWORD debe tener al menos 6 caracteres.")
        sys.exit(1)

    create_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,))
    if cursor.fetchone():
        print(f"El usuario {email} ya existe. No se creo ningun admin nuevo.")
        conn.close()
        return

    hash_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO usuarios (nombre, email, password, role) VALUES (?, ?, ?, ?)",
        (nombre, email, hash_password, "admin")
    )
    conn.commit()
    conn.close()

    print(f"Administrador creado correctamente: {email}")


if __name__ == "__main__":
    seed_admin()
