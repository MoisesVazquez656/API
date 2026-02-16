# app.py
import sqlite3
import bcrypt
from flask import Flask, jsonify, request
from pydantic import BaseModel, ValidationError, EmailStr, Field, ConfigDict

app = Flask(__name__)
DB_NAME = "userdata.db"

class UserSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=9, max_length=9)  # >8 y <10 => 9 exactos
    model_config = ConfigDict(extra="forbid")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/registro", methods=["POST"])
def registro():
    # 1) Validar entrada
    try:
        payload = request.get_json(force=True)
        user = UserSchema(**payload)
    except (ValidationError, Exception):
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    # 2) Verificar duplicado
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (user.email,))
        exists = cursor.fetchone()

        if exists:
            conn.close()
            return jsonify({"ERROR 409": "El usuario ya existe"}), 409

        # 3) Hash con bcrypt
        bpassword = user.password.encode("utf-8")
        salt = bcrypt.gensalt()  # por defecto cost 12, está bien para tarea
        hashed = bcrypt.hashpw(bpassword, salt)

        # 4) Insertar usuario
        cursor.execute(
            "INSERT INTO usuarios (email, password) VALUES (?, ?)",
            (user.email, hashed.decode("utf-8"))
        )
        conn.commit()
        conn.close()

        return jsonify({"Success 201": "Usuario Registrado"}), 201

    except sqlite3.IntegrityError:
        # Por si se cuela duplicado por condición de carrera (UNIQUE)
        try:
            conn.close()
        except:
            pass
        return jsonify({"ERROR 409": "El usuario ya existe"}), 409

    except Exception:
        try:
            conn.close()
        except:
            pass
        return jsonify({"ERROR 500": "Error interno"}), 500

if __name__ == "__main__":
    app.run(debug=True)