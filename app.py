import os
import sqlite3
import bcrypt
import jwt
from datetime import datetime, timedelta, UTC
from functools import wraps

from pydantic import BaseModel, ValidationError, EmailStr, ConfigDict, Field
from flask import Flask, jsonify, request

from config import Config
from logger_config import logger
from init_db import create_db

app = Flask(__name__)
DB_NAME = os.getenv("DB_PATH", "userdata.db")

create_db()

ROLES_SIGERUTT = {"admin", "supervisor", "operador"}


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


class AdminCreateUserSchema(BaseModel):
    nombre: str = Field(min_length=3, max_length=150)
    email: EmailStr
    password: str = Field(min_length=6, max_length=72)
    role: str = Field(min_length=3, max_length=20)
    model_config = ConfigDict(extra="forbid")


class AdminUpdateUserSchema(BaseModel):
    nombre: str | None = Field(default=None, min_length=3, max_length=150)
    email: EmailStr | None = None
    role: str | None = Field(default=None, min_length=3, max_length=20)
    model_config = ConfigDict(extra="forbid")


@app.route("/", methods=["GET"])
def home():
    logger.debug("Health check ejecutado.")
    return jsonify({"mensaje": "API funcionando"}), 200


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
        except Exception as close_error:
            logger.error(f"No se pudo cerrar la conexion: {str(close_error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


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

        cursor.execute("SELECT id, password, role, nombre FROM usuarios WHERE email = ?", (data.email,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            logger.warning(f"Intento de login con usuario inexistente. email={data.email}")
            return jsonify({"ERROR 401": "Credenciales Invalidas"}), 401

        user_id = row[0]
        hash_guardado = row[1].encode("utf-8")
        role = row[2]
        nombre = row[3]

        if not bcrypt.checkpw(data.password.encode("utf-8"), hash_guardado):
            logger.warning(f"Intento de login fallido por password incorrecta. email={data.email}")
            return jsonify({"ERROR 401": "Credenciales Invalidas"}), 401

        payload = {
            "id": user_id,
            "email": data.email,
            "nombre": nombre,
            "role": role,
            "exp": datetime.now(UTC) + timedelta(minutes=30)
        }

        token = jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")

        logger.info(f"Autenticacion exitosa. email={data.email}, role={role}")
        return jsonify({"token": token, "id": user_id, "nombre": nombre, "role": role}), 200

    except sqlite3.Error as error:
        logger.error(
            f"Error de base de datos en login. "
            f"email={getattr(data, 'email', 'desconocido')} detalle={str(error)}"
        )
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


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
        except Exception as close_error:
            logger.error(f"No se pudo cerrar la conexion: {str(close_error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


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

        if data.email_nuevo is not None and data.role_nuevo is not None:
            cursor.execute(
                "UPDATE usuarios SET email = ?, role = ? WHERE email = ?",
                (data.email_nuevo, data.role_nuevo, data.email_actual)
            )
        elif data.email_nuevo is not None:
            cursor.execute(
                "UPDATE usuarios SET email = ? WHERE email = ?",
                (data.email_nuevo, data.email_actual)
            )
        elif data.role_nuevo is not None:
            cursor.execute(
                "UPDATE usuarios SET role = ? WHERE email = ?",
                (data.role_nuevo, data.email_actual)
            )

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
        except Exception as close_error:
            logger.error(f"No se pudo cerrar la conexion: {str(close_error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


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
        except Exception as close_error:
            logger.error(f"No se pudo cerrar la conexion: {str(close_error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


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
        except Exception as close_error:
            logger.error(f"No se pudo cerrar la conexion: {str(close_error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


@app.route("/api/admin/usuarios", methods=["POST"])
@token_requerido(roles_permitidos={"admin"})
def admin_crear_usuario():
    logger.debug("Inicio de creacion de usuario por administrador.")

    try:
        data = AdminCreateUserSchema(**request.json)
    except ValidationError:
        logger.warning("Intento de crear usuario con datos invalidos.")
        return jsonify({"ERROR 400": "Datos invalidos"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en validacion de crear usuario: {str(e)}")
        return jsonify({"ERROR 400": "Datos invalidos"}), 400

    if data.role not in ROLES_SIGERUTT:
        logger.warning(f"Intento de crear usuario con rol invalido. role={data.role}")
        return jsonify({"ERROR 400": "Rol invalido"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (data.email,))
        if cursor.fetchone():
            conn.close()
            logger.warning(f"Intento de crear usuario duplicado. email={data.email}")
            return jsonify({"ERROR 409": "El usuario ya existe"}), 409

        hash_password = bcrypt.hashpw(data.password.encode("utf-8"), bcrypt.gensalt()).decode()

        cursor.execute(
            "INSERT INTO usuarios (nombre, email, password, role) VALUES (?, ?, ?, ?)",
            (data.nombre, data.email, hash_password, data.role)
        )
        conn.commit()
        nuevo_id = cursor.lastrowid
        conn.close()

        logger.info(f"Usuario creado por administrador. email={data.email}, admin={request.user['email']}")
        return jsonify({"SUCCESS 201": "Usuario creado", "id": nuevo_id}), 201

    except sqlite3.Error as error:
        logger.error(f"Error de base de datos al crear usuario. detalle={str(error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


@app.route("/api/admin/usuarios", methods=["GET"])
@token_requerido(roles_permitidos={"admin"})
def admin_listar_usuarios():
    logger.debug("Listado de usuarios solicitado por administrador.")

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, nombre, email, role FROM usuarios ORDER BY id")
        filas = cursor.fetchall()
        conn.close()

        usuarios = [
            {"id": fila[0], "nombre": fila[1], "email": fila[2], "role": fila[3]}
            for fila in filas
        ]
        return jsonify({"usuarios": usuarios}), 200

    except sqlite3.Error as error:
        logger.error(f"Error de base de datos al listar usuarios. detalle={str(error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


@app.route("/api/admin/usuarios/<email>", methods=["GET"])
@token_requerido(roles_permitidos={"admin"})
def admin_obtener_usuario(email):
    logger.debug(f"Consulta de usuario solicitada por administrador. email={email}")

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, nombre, email, role FROM usuarios WHERE email = ?", (email,))
        fila = cursor.fetchone()
        conn.close()

        if not fila:
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        return jsonify({"id": fila[0], "nombre": fila[1], "email": fila[2], "role": fila[3]}), 200

    except sqlite3.Error as error:
        logger.error(f"Error de base de datos al obtener usuario. detalle={str(error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


@app.route("/api/admin/usuarios/<email>", methods=["PUT"])
@token_requerido(roles_permitidos={"admin"})
def admin_actualizar_usuario(email):
    logger.debug(f"Actualizacion de usuario solicitada por administrador. email={email}")

    try:
        data = AdminUpdateUserSchema(**request.json)
    except ValidationError:
        logger.warning("Intento de actualizar usuario con datos invalidos.")
        return jsonify({"ERROR 400": "Datos invalidos"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en validacion de actualizar usuario: {str(e)}")
        return jsonify({"ERROR 400": "Datos invalidos"}), 400

    if data.role is not None and data.role not in ROLES_SIGERUTT:
        logger.warning(f"Intento de actualizar usuario con rol invalido. role={data.role}")
        return jsonify({"ERROR 400": "Rol invalido"}), 400

    if data.nombre is None and data.email is None and data.role is None:
        return jsonify({"ERROR 400": "Nada que actualizar"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        if not cursor.fetchone():
            conn.close()
            logger.warning(f"Intento de actualizar usuario inexistente. email={email}")
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        if data.email is not None and data.email != email:
            cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (data.email,))
            if cursor.fetchone():
                conn.close()
                logger.warning(f"Intento de actualizar a un correo ya existente. email_nuevo={data.email}")
                return jsonify({"ERROR 409": "El correo ya esta en uso"}), 409

        campos = []
        valores = []
        if data.nombre is not None:
            campos.append("nombre = ?")
            valores.append(data.nombre)
        if data.email is not None:
            campos.append("email = ?")
            valores.append(data.email)
        if data.role is not None:
            campos.append("role = ?")
            valores.append(data.role)
        valores.append(email)

        cursor.execute(f"UPDATE usuarios SET {', '.join(campos)} WHERE email = ?", valores)
        conn.commit()
        conn.close()

        logger.info(f"Usuario actualizado por administrador. email={email}, admin={request.user['email']}")
        return jsonify({"SUCCESS 200": "Usuario actualizado"}), 200

    except sqlite3.Error as error:
        logger.error(f"Error de base de datos al actualizar usuario. detalle={str(error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


@app.route("/api/admin/usuarios/<email>", methods=["DELETE"])
@token_requerido(roles_permitidos={"admin"})
def admin_eliminar_usuario(email):
    logger.debug(f"Eliminacion de usuario solicitada por administrador. email={email}")

    if email == request.user["email"]:
        logger.warning(f"Intento de auto-eliminacion de administrador. email={email}")
        return jsonify({"ERROR 400": "No puedes eliminar tu propio usuario"}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,))
        if not cursor.fetchone():
            conn.close()
            logger.warning(f"Intento de eliminar usuario inexistente. email={email}")
            return jsonify({"ERROR 404": "Usuario no encontrado"}), 404

        cursor.execute("DELETE FROM usuarios WHERE email = ?", (email,))
        conn.commit()
        conn.close()

        logger.info(f"Usuario eliminado por administrador. email={email}, admin={request.user['email']}")
        return jsonify({"SUCCESS 200": "Usuario eliminado"}), 200

    except sqlite3.Error as error:
        logger.error(f"Error de base de datos al eliminar usuario. detalle={str(error)}")
        return jsonify({"ERROR 500": "Error en el servidor"}), 500


if __name__ == "__main__":
    logger.info("API iniciada correctamente.")
    app.run(debug=False, use_reloader=False)