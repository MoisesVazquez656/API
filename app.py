import sqlite3
import bcrypt
from pydantic import BaseModel, ValidationError, EmailStr, ConfigDict, Field
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_NAME = "userdata.db"


# =========================
# 1) Esquemas (validaciones)
# =========================

class UserSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=10)
    model_config = ConfigDict(extra="forbid")


class UpdatePasswordSchema(BaseModel):
    email: EmailStr
    password_actual: str = Field(min_length=8, max_length=10)
    password_nueva: str = Field(min_length=8, max_length=10)
    model_config = ConfigDict(extra="forbid")


class UpdateUserSchema(BaseModel):
    email_actual: EmailStr
    password_actual: str = Field(min_length=8, max_length=10)

    # opcionales (puedes mandar uno o ambos)
    email_nuevo: EmailStr | None = None
    role_nuevo: str | None = None

    model_config = ConfigDict(extra="forbid")


# =========================
# 2) Endpoint: REGISTRO
# =========================

@app.route('/registro', methods=['POST'])
def register_user():
    # Validar entrada
    try:
        user = UserSchema(**request.json)
    except ValidationError:
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception:
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Verificar duplicado (sin recorrer toda la tabla)
        cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (user.email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"ERROR 409": "El usuario ya existe"}), 409

        # Hash de contraseña
        bpassword = user.password.encode("utf-8")
        salt = bcrypt.gensalt()
        hash_password = bcrypt.hashpw(bpassword, salt)

        # Insertar
        cursor.execute(
            "INSERT INTO usuarios (email, password) VALUES (?, ?)",
            (user.email, hash_password.decode())
        )
        conn.commit()
        conn.close()

        return jsonify({"SUCCESS 201": "Usuario Registrado"}), 201

    except sqlite3.Error as error:
        print(error)
        try:
            conn.close()
        except:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# 3) Endpoint: ACTUALIZAR PASSWORD
# =========================

@app.route('/actualizar-password', methods=['PUT'])
def update_password():
    # Validar entrada
    try:
        data = UpdatePasswordSchema(**request.json)
    except ValidationError:
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception:
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Buscar usuario y hash actual
        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (data.email,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        hash_guardado = row[0].encode("utf-8")

        # Verificar contraseña actual
        if not bcrypt.checkpw(data.password_actual.encode("utf-8"), hash_guardado):
            conn.close()
            return jsonify({"ERROR 401": "Contraseña actual incorrecta"}), 401

        # Evitar misma contraseña
        if data.password_actual == data.password_nueva:
            conn.close()
            return jsonify({"ERROR 400": "La nueva contraseña no puede ser igual"}), 400

        # Crear hash de nueva contraseña
        salt = bcrypt.gensalt()
        new_hash = bcrypt.hashpw(data.password_nueva.encode("utf-8"), salt).decode()

        # Update
        cursor.execute(
            "UPDATE usuarios SET password = ? WHERE email = ?",
            (new_hash, data.email)
        )
        conn.commit()
        conn.close()

        return jsonify({"SUCCESS 200": "Contraseña Actualizada"}), 200

    except sqlite3.Error as error:
        print(error)
        try:
            conn.close()
        except:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# 4) Endpoint: ACTUALIZAR USUARIO (email y/o role)
# =========================

@app.route('/actualizar-usuario', methods=['PUT'])
def update_user():
    # Validar entrada
    try:
        data = UpdateUserSchema(**request.json)
    except ValidationError:
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception:
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    # Debe enviar algo para actualizar
    if data.email_nuevo is None and data.role_nuevo is None:
        return jsonify({"ERROR 400": "Nada que actualizar"}), 400

    # Validar role si viene
    if data.role_nuevo is not None:
        roles_validos = {"cliente", "admin"}  # ajusta si quieres
        if data.role_nuevo not in roles_validos:
            return jsonify({"ERROR 400": "Rol invalido"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Buscar usuario por email_actual
        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (data.email_actual,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        # Verificar contraseña actual
        hash_guardado = row[0].encode("utf-8")
        if not bcrypt.checkpw(data.password_actual.encode("utf-8"), hash_guardado):
            conn.close()
            return jsonify({"ERROR 401": "Contraseña actual incorrecta"}), 401

        # Si cambia email, verificar duplicado
        if data.email_nuevo is not None and data.email_nuevo != data.email_actual:
            cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (data.email_nuevo,))
            if cursor.fetchone():
                conn.close()
                return jsonify({"ERROR 409": "El usuario ya existe"}), 409

        # Construir UPDATE dinámico
        campos = []
        valores = []

        if data.email_nuevo is not None:
            campos.append("email = ?")
            valores.append(data.email_nuevo)

        if data.role_nuevo is not None:
            campos.append("role = ?")
            valores.append(data.role_nuevo)

        valores.append(data.email_actual)

        query = f"UPDATE usuarios SET {', '.join(campos)} WHERE email = ?"
        cursor.execute(query, tuple(valores))

        conn.commit()
        conn.close()

        return jsonify({"SUCCESS 200": "Usuario Actualizado"}), 200

    except sqlite3.Error as error:
        print(error)
        try:
            conn.close()
        except:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# 5) Arranque
# =========================

if __name__ == '__main__':
    # Para confirmar rutas
    print(app.url_map)

    # Evita que el reloader oculte prints en algunos casos
    app.run(debug=True, use_reloader=False)
