import sqlite3
import bcrypt
import jwt
from datetime import datetime, timedelta, UTC
from functools import wraps

from pydantic import BaseModel, ValidationError, EmailStr, ConfigDict, Field
from flask import Flask, jsonify, request

from config import Config
from logger_config import logger

app = Flask(__name__)
DB_NAME = "userdata.db"


# =========================
# Helpers de seguridad
# =========================

def contiene_html_peligroso(texto: str) -> bool:
    return "<" in texto or ">" in texto


def token_requerido(roles_permitidos=None):
    def decorador(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")

            if not auth.startswith("Bearer "):
                logger.warning(f"Acceso sin token al endpoint {request.path}")
                return jsonify({"ERROR 401": "Token requerido"}), 401

            token = auth.split(" ", 1)[1].strip()

            try:
                payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                logger.warning(f"Intento de acceso con token expirado en endpoint {request.path}")
                return jsonify({"ERROR 401": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                logger.warning(f"Intento de acceso con token invalido en endpoint {request.path}")
                return jsonify({"ERROR 401": "Token invalido"}), 401

            request.user = payload

            if roles_permitidos is not None:
                if payload.get("role") not in roles_permitidos:
                    logger.warning(
                        f"Acceso no autorizado por rol. endpoint={request.path}, "
                        f"usuario={payload.get('email')}, role={payload.get('role')}"
                    )
                    return jsonify({"ERROR 403": "No autorizado"}), 403

            logger.debug(
                f"Token validado correctamente para usuario={payload.get('email')} "
                f"en endpoint={request.path}"
            )
            return f(*args, **kwargs)
        return wrapper
    return decorador


# =========================
# Esquemas
# =========================

class UserSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=10)
    model_config = ConfigDict(extra="forbid")


class LoginSchema(BaseModel):
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
    email_nuevo: EmailStr | None = None
    role_nuevo: str | None = None
    model_config = ConfigDict(extra="forbid")


class CrearViajeSchema(BaseModel):
    origen: str = Field(min_length=3, max_length=120)
    destino: str = Field(min_length=3, max_length=120)
    distancia_km: float = Field(gt=0)
    pago_metodo: str = Field(min_length=3, max_length=20)
    model_config = ConfigDict(extra="forbid")


class AceptarViajeSchema(BaseModel):
    viaje_id: int = Field(gt=0)
    model_config = ConfigDict(extra="forbid")


# =========================
# Health check opcional
# =========================

@app.route("/", methods=["GET"])
def home():
    logger.debug("Health check ejecutado.")
    return jsonify({"mensaje": "API funcionando"}), 200


# =========================
# Registro
# =========================

@app.route("/registro", methods=["POST"])
@app.route("/api/usuarios/registro", methods=["POST"])
def register_user():
    logger.debug("Inicio de solicitud de registro de usuario.")

    try:
        user = UserSchema(**request.json)
        logger.debug(f"Validacion de registro exitosa para email={user.email}")
    except ValidationError:
        logger.warning("Intento de registro con credenciales invalidas.")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en validacion de registro: {str(e)}")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (user.email,))
        if cursor.fetchone():
            conn.close()
            logger.warning(f"Intento de registro duplicado para email={user.email}")
            return jsonify({"ERROR 409": "El usuario ya existe"}), 409

        bpassword = user.password.encode("utf-8")
        salt = bcrypt.gensalt()
        hash_password = bcrypt.hashpw(bpassword, salt).decode()

        cursor.execute(
            "INSERT INTO usuarios (email, password) VALUES (?, ?)",
            (user.email, hash_password)
        )

        conn.commit()
        conn.close()

        logger.info(f"Usuario registrado correctamente. email={user.email}")
        return jsonify({"SUCCESS 201": "Usuario Registrado"}), 201

    except sqlite3.Error as error:
        logger.error(
            f"Error de base de datos en registro. "
            f"email={getattr(user, 'email', 'desconocido')} detalle={str(error)}"
        )
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# Login
# =========================

@app.route("/login", methods=["POST"])
@app.route("/api/usuarios/login", methods=["POST"])
def login():
    logger.debug("Inicio de solicitud de autenticacion.")

    try:
        data = LoginSchema(**request.json)
        logger.debug(f"Validacion de login exitosa para email={data.email}")
    except ValidationError:
        logger.warning("Intento de login con credenciales invalidas.")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en validacion de login: {str(e)}")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT password, role FROM usuarios WHERE email = ?", (data.email,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            logger.warning(f"Intento de login con usuario inexistente. email={data.email}")
            return jsonify({"ERROR 401": "Credenciales Invalidas"}), 401

        hash_guardado = row[0].encode("utf-8")
        role = row[1]

        if not bcrypt.checkpw(data.password.encode("utf-8"), hash_guardado):
            logger.warning(f"Intento de login fallido por password incorrecta. email={data.email}")
            return jsonify({"ERROR 401": "Credenciales Invalidas"}), 401

        payload = {
            "email": data.email,
            "role": role,
            "exp": datetime.now(UTC) + timedelta(minutes=30)
        }

        token = jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")

        logger.info(f"Autenticacion exitosa. email={data.email}, role={role}")
        return jsonify({"token": token}), 200

    except sqlite3.Error as error:
        logger.error(
            f"Error de base de datos en login. "
            f"email={getattr(data, 'email', 'desconocido')} detalle={str(error)}"
        )
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# Actualizar password
# =========================

@app.route("/actualizar-password", methods=["PUT"])
def update_password():
    logger.debug("Inicio de solicitud para actualizar password.")

    try:
        data = UpdatePasswordSchema(**request.json)
        logger.debug(f"Validacion de cambio de password exitosa para email={data.email}")
    except ValidationError:
        logger.warning("Intento de actualizar password con credenciales invalidas.")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en validacion de actualizar password: {str(e)}")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (data.email,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            logger.warning(f"Intento de actualizar password de usuario inexistente. email={data.email}")
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        hash_guardado = row[0].encode("utf-8")

        if not bcrypt.checkpw(data.password_actual.encode("utf-8"), hash_guardado):
            conn.close()
            logger.warning(f"Intento de actualizar password con contraseña actual incorrecta. email={data.email}")
            return jsonify({"ERROR 401": "Contraseña actual incorrecta"}), 401

        if data.password_actual == data.password_nueva:
            conn.close()
            logger.warning(f"Intento de reutilizar la misma password. email={data.email}")
            return jsonify({"ERROR 400": "La nueva contraseña no puede ser igual"}), 400

        salt = bcrypt.gensalt()
        new_hash = bcrypt.hashpw(data.password_nueva.encode("utf-8"), salt).decode()

        cursor.execute(
            "UPDATE usuarios SET password = ? WHERE email = ?",
            (new_hash, data.email)
        )
        conn.commit()
        conn.close()

        logger.info(f"Password actualizada correctamente. email={data.email}")
        return jsonify({"SUCCESS 200": "Contraseña Actualizada"}), 200

    except sqlite3.Error as error:
        logger.error(
            f"Error de base de datos al actualizar password. "
            f"email={getattr(data, 'email', 'desconocido')} detalle={str(error)}"
        )
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# Actualizar usuario
# =========================

@app.route("/actualizar-usuario", methods=["PUT"])
def update_user():
    logger.debug("Inicio de solicitud para actualizar usuario.")

    try:
        data = UpdateUserSchema(**request.json)
        logger.debug(f"Validacion de actualizar usuario exitosa para email={data.email_actual}")
    except ValidationError:
        logger.warning("Intento de actualizar usuario con credenciales invalidas.")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en validacion de actualizar usuario: {str(e)}")
        return jsonify({"ERROR 400": "Credenciales Invalidas"}), 400

    if data.email_nuevo is None and data.role_nuevo is None:
        logger.warning(f"Intento de actualizar usuario sin cambios enviados. email={data.email_actual}")
        return jsonify({"ERROR 400": "Nada que actualizar"}), 400

    if data.role_nuevo is not None:
        roles_validos = {"cliente", "admin"}
        if data.role_nuevo not in roles_validos:
            logger.warning(f"Intento de asignar rol invalido. email={data.email_actual}")
            return jsonify({"ERROR 400": "Rol invalido"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM usuarios WHERE email = ?", (data.email_actual,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            logger.warning(f"Intento de actualizar usuario inexistente. email={data.email_actual}")
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        hash_guardado = row[0].encode("utf-8")
        if not bcrypt.checkpw(data.password_actual.encode("utf-8"), hash_guardado):
            conn.close()
            logger.warning(f"Intento de actualizar usuario con password incorrecta. email={data.email_actual}")
            return jsonify({"ERROR 401": "Contraseña actual incorrecta"}), 401

        if data.email_nuevo is not None and data.email_nuevo != data.email_actual:
            cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (data.email_nuevo,))
            if cursor.fetchone():
                conn.close()
                logger.warning(
                    f"Intento de actualizar email a uno existente. "
                    f"email_actual={data.email_actual}, email_nuevo={data.email_nuevo}"
                )
                return jsonify({"ERROR 409": "El usuario ya existe"}), 409

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

        logger.info(
            f"Usuario actualizado correctamente. email_actual={data.email_actual}, "
            f"email_nuevo={data.email_nuevo}, role_nuevo={data.role_nuevo}"
        )
        return jsonify({"SUCCESS 200": "Usuario Actualizado"}), 200

    except sqlite3.Error as error:
        logger.error(
            f"Error de base de datos al actualizar usuario. "
            f"email={getattr(data, 'email_actual', 'desconocido')} detalle={str(error)}"
        )
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# Crear viaje
# =========================

@app.route("/api/viajes/crear", methods=["POST"])
@token_requerido(roles_permitidos={"cliente"})
def crear_viaje():
    logger.debug("Inicio de solicitud para crear viaje.")

    try:
        data = CrearViajeSchema(**request.json)
        logger.debug(f"Datos de viaje validados. usuario={request.user['email']}")
    except ValidationError:
        logger.warning("Intento de creacion de viaje con datos invalidos.")
        return jsonify({"ERROR 400": "Datos invalidos"}), 400

    if contiene_html_peligroso(data.origen) or contiene_html_peligroso(data.destino):
        logger.warning(f"Intento de creacion de viaje con texto no permitido. usuario={request.user['email']}")
        return jsonify({"ERROR 400": "Texto no permitido"}), 400

    metodos = {"efectivo", "tarjeta"}
    if data.pago_metodo.lower() not in metodos:
        logger.warning(f"Metodo de pago invalido en creacion de viaje. usuario={request.user['email']}")
        return jsonify({"ERROR 400": "Metodo de pago invalido"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cliente_email = request.user["email"]

        cursor.execute("""
            INSERT INTO viajes (cliente_email, origen, destino, distancia_km, pago_metodo, estado)
            VALUES (?, ?, ?, ?, ?, 'pendiente')
        """, (cliente_email, data.origen, data.destino, data.distancia_km, data.pago_metodo.lower()))

        conn.commit()
        viaje_id = cursor.lastrowid
        conn.close()

        logger.info(f"Viaje creado correctamente. usuario={cliente_email}, viaje_id={viaje_id}")
        return jsonify({"SUCCESS 201": "Viaje creado", "viaje_id": viaje_id}), 201

    except sqlite3.Error as e:
        logger.error(f"Error de base de datos al crear viaje. usuario={request.user['email']} detalle={str(e)}")
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# Aceptar viaje
# =========================

@app.route("/api/viajes/aceptar", methods=["POST"])
@token_requerido(roles_permitidos={"admin"})
def aceptar_viaje():
    logger.debug("Inicio de solicitud para aceptar viaje.")

    try:
        data = AceptarViajeSchema(**request.json)
        logger.debug(f"Solicitud de aceptacion validada. viaje_id={data.viaje_id}")
    except ValidationError:
        logger.warning("Intento de aceptar viaje con datos invalidos.")
        return jsonify({"ERROR 400": "Datos invalidos"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT estado FROM viajes WHERE id = ?", (data.viaje_id,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            logger.warning(f"Intento de aceptar viaje inexistente. viaje_id={data.viaje_id}")
            return jsonify({"ERROR 404": "Viaje no encontrado"}), 404

        if row[0] != "pendiente":
            conn.close()
            logger.warning(f"Intento de aceptar viaje no disponible. viaje_id={data.viaje_id}, estado_actual={row[0]}")
            return jsonify({"ERROR 409": "Viaje no disponible"}), 409

        conductor_email = request.user["email"]

        cursor.execute("""
            UPDATE viajes
            SET estado = 'aceptado', conductor_email = ?
            WHERE id = ?
        """, (conductor_email, data.viaje_id))

        conn.commit()
        conn.close()

        logger.info(f"Viaje aceptado correctamente. viaje_id={data.viaje_id}, conductor={conductor_email}")
        return jsonify({"SUCCESS 200": "Viaje aceptado"}), 200

    except sqlite3.Error as e:
        logger.error(
            f"Error de base de datos al aceptar viaje. "
            f"viaje_id={getattr(data, 'viaje_id', 'desconocido')} detalle={str(e)}"
        )
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


# =========================
# Arranque
# =========================

if __name__ == "__main__":
    logger.info("API iniciada correctamente.")
    app.run(debug=True, use_reloader=False)