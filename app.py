# app.py
import os
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from db_config import get_db_connection
import mysql.connector
from decimal import Decimal
import json
from datetime import datetime, timedelta, timezone
import bcrypt 
import jwt 
import random
import string
from flask_mail import Mail, Message

app = Flask(__name__)

# Configura CORS
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}}, supports_credentials=True)

# Carga la clave secreta de JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
# ¡NUEVO! Carga la clave secreta del Scheduler
app.config['CRON_SECRET_KEY'] = os.getenv('CRON_SECRET_KEY')

# --- Configuración de Flask-Mail ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True').lower() == 'true'
mail = Mail(app)

# --- (Helpers JSON y de Token se mantienen igual) ---
def json_converter(obj):
    if isinstance(obj, Decimal): return float(obj)
    if isinstance(obj, (datetime,)): return obj.isoformat()
    raise TypeError(f"El objeto de tipo {type(obj)} no es serializable en JSON")

def get_user_id_from_token():
    token = request.cookies.get('token')
    if not token: return None
    try:
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return data['id_usuario']
    except:
        return None

# --- Funciones de Envío de Correo ---
def send_verification_email(to_email, code):
    try:
        msg = Message(
            subject="¡Bienvenido a CanchApp! Verifica tu cuenta",
            sender=("CanchApp", app.config['MAIL_USERNAME']),
            recipients=[to_email]
        )
        msg.body = f"¡Gracias por registrarte en CanchApp!\nTu código de verificación es: {code}\n\nIngrésalo en la página para activar tu cuenta.\n\n- El equipo de CanchApp"
        mail.send(msg)
        print(f"--- Correo de verificación enviado exitosamente a {to_email} ---")
    except Exception as e:
        print(f"¡ERROR AL ENVIAR CORREO DE VERIFICACIÓN! {e}")
        # ¡IMPORTANTE! Lanzamos el error para que /register haga rollback
        raise e 

# --- ¡NUEVA FUNCIÓN DE CORREO! (HU-022) ---
def send_reminder_email(to_email, first_name, cancha_nombre, sede_nombre, fecha_hora_inicio):
    try:
        msg = Message(
            subject="Recordatorio de tu reserva en CanchApp",
            sender=("CanchApp", app.config['MAIL_USERNAME']),
            recipients=[to_email]
        )
        msg.body = f"""
        ¡Hola, {first_name}!
        
        Este es un recordatorio de tu próxima reserva en CanchApp.
        
        Cancha: {cancha_nombre}
        Sede: {sede_nombre}
        Fecha y Hora: {fecha_hora_inicio.strftime('%A, %d de %B de %Y a las %I:%M %p')}
        
        ¡No olvides tu partido!
        
        - El equipo de CanchApp
        """
        mail.send(msg)
        print(f"--- Recordatorio enviado exitosamente a {to_email} ---")
    except Exception as e:
        print(f"¡ERROR AL ENVIAR RECORDATORIO! a {to_email}: {e}")

# --- (Todos los endpoints de /api/canchas, /api/pagos se mantienen igual) ---
@app.route('/api/canchas', methods=['GET'])
def get_canchas():
    id_usuario = get_user_id_from_token() 
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Error de conexión a la base de datos"}), 500
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, c.foto,
                s.ubicacion_texto,
                MIN(t.precio_por_hora) AS precio_por_hora,
                MAX(f.id_usuario IS NOT NULL) AS is_favorito 
            FROM canchas c
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
            LEFT JOIN favoritos f ON c.id_cancha = f.id_cancha AND f.id_usuario = %s
            WHERE c.estado = 1
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.foto, s.ubicacion_texto;
        """
        cursor.execute(query, (id_usuario,))
        rows = cursor.fetchall()
        canchas = []
        for c in rows:
            canchas.append({
                "id": c['id_cancha'], "nombre": c['nombre'], "ubicacion": c['ubicacion_texto'],
                "precio": c['precio_por_hora'] or 0,
                "imagen": c['foto'] or 'https://placehold.co/400x300/CCCCCC/FFFFFF?text=Sin+Imagen',
                "lat": -12.1084 + (os.urandom(1)[0] / 255 - 0.5) * 0.1,
                "lng": -77.0031 + (os.urandom(1)[0] / 255 - 0.5) * 0.1,
                "is_favorito": bool(c['is_favorito']) 
            })
        cursor.close()
        conn.close()
        return json.dumps(canchas, default=json_converter), 200, {'Content-Type': 'application/json'}
    except mysql.connector.Error as err:
        print(f"Error en /api/canchas: {err}")
        return jsonify({"error": "Error al obtener las canchas"}), 500

@app.route('/api/canchas/<int:id>', methods=['GET'])
def get_cancha_detalle(id):
    id_usuario = get_user_id_from_token()
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cancha_query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, c.foto, s.ubicacion_texto,
                MIN(t.precio_por_hora) AS precio_por_hora,
                td.nombre AS tipo_deporte, ts.nombre AS tipo_superficie,
                MAX(f.id_usuario IS NOT NULL) AS is_favorito
            FROM canchas c
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
            LEFT JOIN tipos_deporte td ON c.id_tipo_deporte = td.id_tipo_deporte
            LEFT JOIN tipos_superficie ts ON c.id_tipo_superficie = ts.id_tipo_superficie
            LEFT JOIN favoritos f ON c.id_cancha = f.id_cancha AND f.id_usuario = %s
            WHERE c.id_cancha = %s
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.foto, s.ubicacion_texto, td.nombre, ts.nombre;
        """
        cursor.execute(cancha_query, (id_usuario, id))
        cancha = cursor.fetchone()
        if cancha is None:
            cursor.close()
            conn.close()
            return jsonify({"error": "Cancha no encontrada"}), 404

        reseñas_query = """
            SELECT r.id_reseña, r.calificacion, r.comentario, r.fecha_creacion, u.first_name, u.last_name
            FROM reseñas r
            JOIN reservas res ON r.id_reserva = res.id_reserva
            JOIN usuarios u ON res.id_usuario = u.id_usuario
            WHERE res.id_cancha = %s ORDER BY r.fecha_creacion DESC
        """
        cursor.execute(reseñas_query, (id,))
        reseñas = cursor.fetchall()
        
        cancha_formateada = {
            "id": cancha['id_cancha'], "nombre": cancha['nombre'], "ubicacion": cancha['ubicacion_texto'],
            "precio": cancha['precio_por_hora'] or 0,
            "rating": sum(r['calificacion'] for r in reseñas) / len(reseñas) if reseñas else 4.5,
            "is_favorito": bool(cancha['is_favorito']),
            "description": cancha['descripcion'],
            "gallery": [
                cancha['foto'] or 'https://placehold.co/600x400/CCCCCC/FFFFFF?text=Foto+Principal',
                'https://placehold.co/200x150/CCCCCC/FFFFFF?text=Foto+2',
                'https://placehold.co/200x150/CCCCCC/FFFFFF?text=Foto+3'
            ],
            "services": [
                {"name": "Estacionamiento", "icon": "🚗"}, {"name": "Baños y Duchas", "icon": "🚿"},
                {"name": "Bebidas", "icon": "🥤"},
            ],
            "reviews": [{
                "id": r['id_reseña'], "user": f"{r['first_name']} {r['last_name']}",
                "rating": r['calificacion'], "date": r['fecha_creacion'].strftime('%d/%m/%Y'),
                "comment": r['comentario']
            } for r in reseñas]
        }
        cursor.close()
        conn.close()
        return json.dumps(cancha_formateada, default=json_converter), 200, {'Content-Type': 'application/json'}
    except mysql.connector.Error as err:
        print(f"Error en /api/canchas/<id>: {err}")
        return jsonify({"error": "Error al obtener el detalle de la cancha"}), 500

@app.route('/api/canchas/<int:id>/disponibilidad', methods=['GET'])
def get_disponibilidad(id):
    # (Sin cambios)
    try:
        fecha_solicitada = request.args.get('fecha')
        if not fecha_solicitada:
            return jsonify({"error": "No se proporcionó fecha"}), 400
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        query_reservas = """
            SELECT fecha_hora_inicio FROM reservas 
            WHERE id_cancha = %s AND DATE(fecha_hora_inicio) = %s AND (estado = 'confirmada' OR estado = 'pendiente');
        """
        cursor.execute(query_reservas, (id, fecha_solicitada))
        reservas = cursor.fetchall()
        horas_ocupadas = {reserva['fecha_hora_inicio'].strftime('%H:%M') for reserva in reservas}
        cursor.close()
        conn.close()
        disponibilidad = {}
        for h in range(9, 23):
            hora_slot = f"{h:02d}:00"
            disponibilidad[hora_slot] = 'occupied' if hora_slot in horas_ocupadas else 'available'
        return jsonify(disponibilidad)
    except mysql.connector.Error as err:
        print(f"Error en /api/canchas/<id>/disponibilidad: {err}")
        return jsonify({"error": "Error al obtener la disponibilidad"}), 500

@app.route('/api/pagos', methods=['POST'])
def procesar_pago():
    # (Sin cambios)
    try:
        data = request.json
        id_reserva = data['id_reserva']
        monto = data['monto']
        metodo_pago = data['metodo_pago']
        id_transaccion_externa = f"TXN_{id_reserva}_{os.urandom(4).hex()}"
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        query_pago = """
            INSERT INTO pagos (id_reserva, monto, metodo_pago, id_transaccion_externa, estado)
            VALUES (%s, %s, %s, %s, 'completado')
        """
        cursor.execute(query_pago, (id_reserva, monto, metodo_pago, id_transaccion_externa))
        id_pago = cursor.lastrowid
        query_reserva = "UPDATE reservas SET estado = 'confirmada' WHERE id_reserva = %s"
        cursor.execute(query_reserva, (id_reserva,))
        conn.commit()
        cursor.close()
        conn.close()
        
        return json.dumps({
            "id_pago": id_pago, "id_reserva": id_reserva, "estado": "completado",
            "operacion": id_transaccion_externa, "monto": monto, "metodo": metodo_pago,
            "fecha_pago": datetime.now()
        }, default=json_converter), 201, {'Content-Type': 'application/json'}
    except mysql.connector.Error as err:
        print(f"Error en /api/pagos: {err}")
        return jsonify({"error": "Error al procesar el pago"}), 500

# --- Endpoints SPRINT 2 y 3 (Con Verificación de Correo) ---

@app.route('/api/register', methods=['POST'])
def registrar_usuario():
    # ¡MODIFICADO! Con manejo de error de envío
    try:
        data = request.json
        nombre_completo = data['nombre']
        email = data['email']
        password_plano = data['password']
        documento = data.get('documento') 
        telefono = data.get('telefono')

        nombres = nombre_completo.split(' ')
        first_name = nombres[0]
        last_name = ' '.join(nombres[1:]) if len(nombres) > 1 else ''

        password_bytes = password_plano.encode('utf-8')
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        
        id_rol_jugador = 1
        
        verification_code = ''.join(random.choices(string.digits, k=6))
        print(f"--- CÓDIGO DE VERIFICACIÓN PARA {email}: {verification_code} ---")
        
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        
        cursor = conn.cursor()
        query = """
            INSERT INTO usuarios (first_name, last_name, email, password, id_rol, username, 
                                  documento, telefono, verification_code, is_verified)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0)
        """
        cursor.execute(query, (
            first_name, last_name, email, password_hash, id_rol_jugador, 
            email, documento, telefono, verification_code
        ))
        conn.commit()
        id_usuario = cursor.lastrowid
        
        try:
            send_verification_email(email, verification_code)
        except Exception as e:
            # Si el correo falla, le avisamos al usuario y borramos el usuario
            print(f"¡ERROR AL ENVIAR CORREO! {e}")
            cursor.execute("DELETE FROM usuarios WHERE id_usuario = %s", (id_usuario,))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"error": "No se pudo enviar el correo de verificación. Revisa la configuración del servidor de correo."}), 500

        cursor.close()
        conn.close()
        return jsonify({"id_usuario": id_usuario, "mensaje": "Usuario registrado. Por favor, revisa tu email para el código de verificación."}), 201

    except mysql.connector.Error as err:
        if err.errno == 1062:
            return jsonify({"error": "El correo electrónico ya está registrado."}), 409
        print(f"Error en POST /api/register: {err}")
        return jsonify({"error": "Error al registrar el usuario"}), 500

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    # (Sin cambios)
    try:
        data = request.json
        email = data.get('email')
        code = data.get('code')
        if not email or not code:
            return jsonify({"error": "Email y código son requeridos."}), 400
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id_usuario, is_verified FROM usuarios WHERE email = %s AND verification_code = %s",
            (email, code)
        )
        usuario = cursor.fetchone()
        if not usuario:
            return jsonify({"error": "El código de verificación es incorrecto."}), 400
        if usuario['is_verified']:
            return jsonify({"mensaje": "Esta cuenta ya ha sido verificada."}), 200
        cursor.execute(
            "UPDATE usuarios SET is_verified = 1, verification_code = NULL WHERE id_usuario = %s",
            (usuario['id_usuario'],)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"mensaje": "¡Cuenta verificada exitosamente! Ya puedes iniciar sesión."}), 200
    except mysql.connector.Error as err:
        print(f"Error en POST /api/verify-email: {err}")
        return jsonify({"error": "Error al verificar la cuenta"}), 500

@app.route('/api/login', methods=['POST'])
def login_usuario():
    # ¡CORREGIDO!
    try:
        data = request.json
        email = data['email']
        password_plano = data['password']
        
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()
        
        if not usuario:
            cursor.close()
            conn.close()
            return jsonify({"error": "Credenciales inválidas."}), 401
            
        if not usuario['is_verified']:
            cursor.close()
            conn.close()
            return jsonify({"error": "Cuenta no verificada. Por favor, revisa tu email.", "needsVerification": True, "email": email}), 401

        password_hash_bd = usuario['password'].encode('utf-8')
        password_plano_bytes = password_plano.encode('utf-8')
        
        if not bcrypt.checkpw(password_plano_bytes, password_hash_bd):
            cursor.close()
            conn.close()
            return jsonify({"error": "Credenciales inválidas."}), 401
            
        cursor.close()
        conn.close()
        
        payload = {
            'id_usuario': usuario['id_usuario'],
            'email': usuario['email'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24) 
        }
        token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")
        
        response_data = {
            "user": {
                "id_usuario": usuario['id_usuario'],
                "email": usuario['email'],
                "first_name": usuario['first_name'],
                "last_name": usuario['last_name']
            },
            "token": token
        }
        
        resp = make_response(jsonify(response_data))
        
        # ¡LA CORRECCIÓN ANTERIOR!
        resp.set_cookie(
            'token', 
            token,  # <-- ¡Arreglado!
            httponly=True, 
            samesite='Lax', 
            max_age=60*60*24
        )
        return resp

    except Exception as e:
        print(f"Error en POST /api/login: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/logout', methods=['POST'])
def logout_usuario():
    # (Sin cambios)
    try:
        resp = make_response(jsonify({"mensaje": "Sesión cerrada"}))
        resp.set_cookie('token', '', httponly=True, samesite='Lax', expires=0)
        return resp
    except Exception as e:
        print(f"Error en POST /api/logout: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/profile', methods=['GET', 'PUT'])
def manejar_perfil():
    # ¡MODIFICADO! Para manejar 'recibir_notificaciones'
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado. Debes iniciar sesión."}), 401

    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            
            cursor = conn.cursor(dictionary=True)
            # ¡CAMBIO! Traemos el nuevo campo
            cursor.execute(
                "SELECT id_usuario, first_name, last_name, email, documento, telefono, recibir_notificaciones FROM usuarios WHERE id_usuario = %s", 
                (id_usuario,) 
            )
            usuario = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not usuario:
                return jsonify({"error": "Usuario no encontrado"}), 404
            
            # Convertimos el booleano
            usuario['recibir_notificaciones'] = bool(usuario['recibir_notificaciones'])
            return jsonify(usuario)
            
        except Exception as e:
            print(f"Error en GET /api/profile: {e}")
            return jsonify({"error": "Error interno del servidor"}), 500

    if request.method == 'PUT':
        try:
            data = request.json
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            
            cursor = conn.cursor()
            # ¡CAMBIO! Actualizamos el nuevo campo
            query = """
                UPDATE usuarios SET
                    first_name = %s,
                    last_name = %s,
                    documento = %s,
                    telefono = %s,
                    recibir_notificaciones = %s
                WHERE id_usuario = %s
            """
            cursor.execute(query, (
                data['first_name'],
                data['last_name'],
                data['documento'],
                data['telefono'],
                bool(data.get('recibir_notificaciones', True)), # ¡NUEVO!
                id_usuario
            ))
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({"mensaje": "Perfil actualizado correctamente"})
            
        except Exception as e:
            print(f"Error en PUT /api/profile: {e}")
            return jsonify({"error": "Error interno del servidor"}), 500

# --- (Todos los endpoints de /api/reservas, /api/resenas, /api/favoritos, 
# /api/profile/delete-check, /api/profile/delete-account se mantienen igual) ---
@app.route('/api/reservas', methods=['POST', 'GET'])
def manejar_reservas():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado. Debes iniciar sesión."}), 401
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            cursor = conn.cursor(dictionary=True)
            query = """
                SELECT 
                    r.id_reserva, r.id_cancha, r.fecha_hora_inicio, 
                    r.fecha_hora_fin, r.precio_total, r.estado,
                    c.nombre AS cancha_nombre,
                    s.nombre_sede, s.ubicacion_texto
                FROM reservas r
                JOIN canchas c ON r.id_cancha = c.id_cancha
                JOIN sedes s ON c.id_sede = s.id_sede
                WHERE r.id_usuario = %s ORDER BY r.fecha_hora_inicio DESC;
            """
            cursor.execute(query, (id_usuario,))
            reservas = cursor.fetchall()
            cursor.close()
            conn.close()
            return json.dumps(reservas, default=json_converter), 200, {'Content-Type': 'application/json'}
        except mysql.connector.Error as err:
            print(f"Error en GET /api/reservas: {err}")
            return jsonify({"error": "Error al obtener las reservas"}), 500
    if request.method == 'POST':
        try:
            data = request.json
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            cursor = conn.cursor()
            query = """
                INSERT INTO reservas (id_usuario, id_cancha, fecha_hora_inicio, fecha_hora_fin, precio_total, estado)
                VALUES (%s, %s, %s, %s, %s, 'pendiente')
            """
            cursor.execute(query, (
                id_usuario, data['id_cancha'], data['fecha_hora_inicio'], 
                data['fecha_hora_fin'], data['precio_total']
            ))
            conn.commit()
            id_reserva = cursor.lastrowid
            cursor.close()
            conn.close()
            return jsonify({"id_reserva": id_reserva, "estado": "pendiente"}), 201
        except mysql.connector.Error as err:
            print(f"Error en POST /api/reservas: {err}")
            return jsonify({"error": "Error al crear la reserva"}), 500

@app.route('/api/reservas/<int:id>/cancelar', methods=['PUT'])
def cancelar_reserva(id):
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT fecha_hora_inicio, estado FROM reservas WHERE id_reserva = %s AND id_usuario = %s",
            (id, id_usuario) 
        )
        reserva = cursor.fetchone()
        if not reserva:
            return jsonify({"error": "Reserva no encontrada o no te pertenece."}), 404
        if reserva['estado'] != 'confirmada':
            return jsonify({"error": "Esta reserva no se puede cancelar."}), 400
        ahora = datetime.now()
        inicio_reserva = reserva['fecha_hora_inicio']
        if (inicio_reserva - ahora) < timedelta(hours=24):
            return jsonify({"error": "No puedes cancelar una reserva con menos de 24 horas de anticipación."}), 400
        cursor.execute("UPDATE reservas SET estado = 'cancelada' WHERE id_reserva = %s", (id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"mensaje": "Reserva cancelada exitosamente"})
    except mysql.connector.Error as err:
        print(f"Error en PUT /api/reservas/<id>/cancelar: {err}")
        return jsonify({"error": "Error al cancelar la reserva"}), 500

@app.route('/api/reservas/<int:id>', methods=['PUT'])
def modificar_reserva(id):
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        data = request.json
        nueva_fecha_inicio = data['fecha_hora_inicio']
        nueva_fecha_fin = data['fecha_hora_fin']
        nuevo_precio = data['precio_total']
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM reservas WHERE id_reserva = %s AND id_usuario = %s",
            (id, id_usuario)
        )
        reserva_actual = cursor.fetchone()
        if not reserva_actual:
            cursor.close()
            conn.close()
            return jsonify({"error": "No tienes permiso para modificar esta reserva."}), 403
        query_colision = """
            SELECT id_reserva 
            FROM reservas
            WHERE id_cancha = %s
              AND id_reserva != %s 
              AND (estado = 'confirmada' OR estado = 'pendiente')
              AND (
                  (%s < fecha_hora_fin) AND (%s > fecha_hora_inicio)
              );
        """
        cursor.execute(query_colision, (
            reserva_actual['id_cancha'], 
            id, 
            nueva_fecha_inicio, 
            nueva_fecha_fin
        ))
        colision = cursor.fetchone()
        if colision:
            cursor.close()
            conn.close()
            return jsonify({"error": "El nuevo horario seleccionado ya no está disponible. Alguien más lo reservó."}), 409
        query_update = """
            UPDATE reservas
            SET 
                fecha_hora_inicio = %s,
                fecha_hora_fin = %s,
                precio_total = %s
            WHERE id_reserva = %s
        """
        cursor.execute(query_update, (nueva_fecha_inicio, nueva_fecha_fin, nuevo_precio, id))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"mensaje": "Reserva modificada exitosamente"})
    except mysql.connector.Error as err:
        print(f"Error en PUT /api/reservas/<id>: {err}")
        return jsonify({"error": "Error al modificar la reserva"}), 500

@app.route('/api/resenas/mis-resenas', methods=['GET'])
def get_mis_resenas():
    id_usuario = get_user_id_from_token() 
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
                r.id_reseña, r.calificacion, r.comentario, r.fecha_creacion,
                c.id_cancha, c.nombre AS cancha_nombre, res.id_reserva
            FROM reseñas r
            JOIN reservas res ON r.id_reserva = res.id_reserva
            JOIN canchas c ON res.id_cancha = c.id_cancha
            WHERE res.id_usuario = %s ORDER BY r.fecha_creacion DESC;
        """
        cursor.execute(query, (id_usuario,))
        reseñas = cursor.fetchall()
        formatted_reseñas = []
        for r in reseñas:
            formatted_reseñas.append({
                "id": r['id_reseña'], "id_reserva": r['id_reserva'],
                "rating": r['calificacion'], "comment": r['comentario'],
                "date": r['fecha_creacion'].strftime('%d/%m/%Y'),
                "canchaId": r['id_cancha'], "canchaNombre": r['cancha_nombre']
            })
        cursor.close()
        conn.close()
        return jsonify(formatted_reseñas)
    except mysql.connector.Error as err:
        print(f"Error en GET /api/resenas/mis-resenas: {err}")
        return jsonify({"error": "Error al obtener las reseñas"}), 500

@app.route('/api/resenas', methods=['POST'])
def crear_reseña():
    id_usuario = get_user_id_from_token() 
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        data = request.json
        id_reserva = data['id_reserva']
        calificacion = data['calificacion']
        comentario = data['comentario']
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM reservas WHERE id_reserva = %s AND id_usuario = %s AND estado = 'completada'",
            (id_reserva, id_usuario)
        )
        reserva = cursor.fetchone()
        if not reserva:
            return jsonify({"error": "Solo puedes dejar reseñas de reservas completadas."}), 403
        cursor.execute(
            "INSERT INTO reseñas (id_reserva, calificacion, comentario) VALUES (%s, %s, %s)",
            (id_reserva, calificacion, comentario)
        )
        conn.commit()
        id_reseña = cursor.lastrowid
        cursor.close()
        conn.close()
        return jsonify({"id_reseña": id_reseña, "mensaje": "Reseña creada"}), 201
    except mysql.connector.Error as err:
        if err.errno == 1062:
            return jsonify({"error": "Ya existe una reseña para esta reserva."}), 409
        print(f"Error en POST /api/resenas: {err}")
        return jsonify({"error": "Error al crear la reseña"}), 500

@app.route('/api/resenas/<int:id>', methods=['DELETE', 'PUT'])
def manejar_reseña_individual(id):
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    if request.method == 'PUT':
        try:
            data = request.json
            calificacion = data['calificacion']
            comentario = data['comentario']
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            cursor = conn.cursor()
            query = """
                UPDATE reseñas r JOIN reservas res ON r.id_reserva = res.id_reserva
                SET r.calificacion = %s, r.comentario = %s
                WHERE r.id_reseña = %s AND res.id_usuario = %s
            """
            cursor.execute(query, (calificacion, comentario, id, id_usuario))
            conn.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            conn.close()
            if affected_rows == 0:
                return jsonify({"error": "No se pudo actualizar la reseña."}), 404
            return jsonify({"mensaje": "Reseña actualizada exitosamente"})
        except mysql.connector.Error as err:
            print(f"Error en PUT /api/resenas/<id>: {err}")
            return jsonify({"error": "Error al actualizar la reseña"}), 500
    if request.method == 'DELETE':
        try:
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            cursor = conn.cursor()
            query = """
                DELETE r FROM reseñas r
                JOIN reservas res ON r.id_reserva = res.id_reserva
                WHERE r.id_reseña = %s AND res.id_usuario = %s
            """
            cursor.execute(query, (id, id_usuario))
            conn.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            conn.close()
            if affected_rows == 0:
                return jsonify({"error": "No se pudo eliminar la reseña."}), 404
            return jsonify({"mensaje": "Reseña eliminada exitosamente"})
        except mysql.connector.Error as err:
            print(f"Error en DELETE /api/resenas/<id>: {err}")
            return jsonify({"error": "Error al eliminar la reseña"}), 500

@app.route('/api/favoritos', methods=['GET', 'POST'])
def manejar_favoritos():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            cursor = conn.cursor(dictionary=True)
            query = """
                SELECT 
                    c.id_cancha, c.nombre, c.foto,
                    s.ubicacion_texto,
                    MIN(t.precio_por_hora) AS precio_por_hora,
                    f.fecha_agregado
                FROM favoritos f
                JOIN canchas c ON f.id_cancha = c.id_cancha
                JOIN sedes s ON c.id_sede = s.id_sede
                LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
                WHERE f.id_usuario = %s
                GROUP BY c.id_cancha, c.nombre, c.foto, s.ubicacion_texto, f.fecha_agregado
                ORDER BY f.fecha_agregado DESC;
            """
            cursor.execute(query, (id_usuario,))
            favoritos_raw = cursor.fetchall()
            favoritos = []
            for f in favoritos_raw:
                favoritos.append({
                    "id": f['id_cancha'],
                    "nombre": f['nombre'],
                    "ubicacion": f['ubicacion_texto'],
                    "precio": f['precio_por_hora'] or 0,
                    "imagen": f['foto'] or 'https://placehold.co/400x300/CCCCCC/FFFFFF?text=Sin+Imagen',
                    "fecha_agregado": f['fecha_agregado']
                })
            cursor.close()
            conn.close()
            return json.dumps(favoritos, default=json_converter), 200, {'Content-Type': 'application/json'}
        except mysql.connector.Error as err:
            print(f"Error en GET /api/favoritos: {err}")
            return jsonify({"error": "Error al obtener favoritos"}), 500
    if request.method == 'POST':
        try:
            data = request.json
            id_cancha = data['id_cancha']
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            cursor = conn.cursor()
            query = "INSERT INTO favoritos (id_usuario, id_cancha) VALUES (%s, %s)"
            cursor.execute(query, (id_usuario, id_cancha))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"mensaje": "Cancha añadida a favoritos"}), 201
        except mysql.connector.Error as err:
            if err.errno == 1062: 
                return jsonify({"error": "Esta cancha ya está en tus favoritos."}), 409
            print(f"Error en POST /api/favoritos: {err}")
            return jsonify({"error": "Error al añadir favorito"}), 500

@app.route('/api/favoritos/<int:id_cancha>', methods=['DELETE'])
def eliminar_favorito(id_cancha):
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor()
        query = "DELETE FROM favoritos WHERE id_usuario = %s AND id_cancha = %s"
        cursor.execute(query, (id_usuario, id_cancha))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        if affected_rows == 0:
            return jsonify({"error": "Favorito no encontrado."}), 404
        return jsonify({"mensaje": "Cancha eliminada de favoritos"}), 200
    except mysql.connector.Error as err:
        print(f"Error en DELETE /api/favoritos/<id>: {err}")
        return jsonify({"error": "Error al eliminar favorito"}), 500

@app.route('/api/profile/delete-check', methods=['GET'])
def check_deletable():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT id_reserva FROM reservas 
            WHERE id_usuario = %s 
            AND (estado = 'pendiente' OR estado = 'confirmada')
            LIMIT 1;
        """
        cursor.execute(query, (id_usuario,))
        reserva_activa = cursor.fetchone()
        cursor.close()
        conn.close()
        if reserva_activa:
            return jsonify({"error": "¡Usted tiene reservas en ejecución! No puede eliminar su cuenta."}), 409
        else:
            return jsonify({"message": "OK"}), 200
    except mysql.connector.Error as err:
        print(f"Error en GET /api/profile/delete-check: {err}")
        return jsonify({"error": "Error al verificar la cuenta"}), 500

@app.route('/api/profile/delete-account', methods=['POST'])
def delete_account():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    try:
        data = request.json
        password_plano = data['password']
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        usuario = cursor.fetchone()
        if not usuario:
            return jsonify({"error": "Usuario no encontrado."}), 404
        password_hash_bd = usuario['password'].encode('utf-8')
        password_plano_bytes = password_plano.encode('utf-8')
        if not bcrypt.checkpw(password_plano_bytes, password_hash_bd):
            return jsonify({"error": "La contraseña es incorrecta."}), 401
        cursor.execute("SELECT id_reserva FROM reservas WHERE id_usuario = %s", (id_usuario,))
        reservas = cursor.fetchall()
        if reservas:
            id_reservas = tuple(r['id_reserva'] for r in reservas)
            placeholder = '%s'
            if len(id_reservas) > 1:
                placeholder = ', '.join(['%s'] * len(id_reservas))
            cursor.execute(f"DELETE FROM reseñas WHERE id_reserva IN ({placeholder})", id_reservas)
            cursor.execute(f"DELETE FROM pagos WHERE id_reserva IN ({placeholder})", id_reservas)
        cursor.execute("DELETE FROM favoritos WHERE id_usuario = %s", (id_usuario,))
        cursor.execute("DELETE FROM reservas WHERE id_usuario = %s", (id_usuario,))
        cursor.execute("DELETE FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        conn.commit()
        cursor.close()
        conn.close()
        resp = make_response(jsonify({"mensaje": "El perfil se ha eliminado correctamente"}))
        resp.set_cookie('token', '', httponly=True, samesite='Lax', expires=0) 
        return resp
    except mysql.connector.Error as err:
        conn.rollback() 
        print(f"Error en POST /api/profile/delete-account: {err}")
        if err.errno == 1451: 
             return jsonify({"error": "No se puede eliminar la cuenta, está asignada como administrador de una empresa."}), 409
        return jsonify({"error": "Error al eliminar la cuenta"}), 500


# --- ¡NUEVO ENDPOINT PARA EL SCHEDULER! (HU-022) ---
@app.route('/api/tasks/send-reminders', methods=['POST'])
def send_reminders():
    # 1. Verificamos la clave secreta
    auth_header = request.headers.get('Authorization')
    secret_key = auth_header.split(' ')[1] if auth_header else None
    
    if not secret_key or secret_key != app.config['CRON_SECRET_KEY']:
        print("¡Intento fallido de ejecutar send_reminders! Clave secreta incorrecta.")
        return jsonify({"error": "No autorizado"}), 401

    print("--- [SCHEDULER]: Iniciando tarea de envío de recordatorios ---")
    
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 2. ¡LÓGICA CORREGIDA!
        # Buscamos reservas cuya FECHA sea igual a la FECHA de mañana.
        query = """
            SELECT
                r.id_reserva, r.fecha_hora_inicio,
                u.email, u.first_name,
                c.nombre AS cancha_nombre,
                s.nombre_sede
            FROM reservas r
            JOIN usuarios u ON r.id_usuario = u.id_usuario
            JOIN canchas c ON r.id_cancha = c.id_cancha
            JOIN sedes s ON c.id_sede = s.id_sede
            WHERE 
                r.estado = 'confirmada'
                AND u.is_verified = 1
                AND u.recibir_notificaciones = 1
                AND DATE(r.fecha_hora_inicio) = DATE(NOW() + INTERVAL 1 DAY);
        """
        cursor.execute(query)
        reservas_a_notificar = cursor.fetchall()
        cursor.close()
        conn.close()
        
        if not reservas_a_notificar:
            print("--- [SCHEDULER]: No se encontraron reservas para notificar mañana. ---")
            return jsonify({"mensaje": "No hay recordatorios para enviar."}), 200

        # 3. Enviamos los correos
        count = 0
        for r in reservas_a_notificar:
            # Importante: necesitamos 'locale' para que los nombres de días/meses salgan en español
            # (Asegúrate de tener el idioma español instalado en tu S.O. si esto falla)
            try:
                import locale
                # 'es_ES.UTF-8' para Linux/Mac, 'Spanish_Spain' o 'es-ES' para Windows
                locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8') 
            except locale.Error:
                try:
                    locale.setlocale(locale.LC_TIME, 'Spanish_Spain')
                except locale.Error:
                    print("Warning: Locale 'es_ES' o 'Spanish_Spain' no encontrado. Se usarán fechas en inglés.")
            
            send_reminder_email(
                to_email=r['email'],
                first_name=r['first_name'],
                cancha_nombre=r['cancha_nombre'],
                sede_nombre=r['nombre_sede'],
                fecha_hora_inicio=r['fecha_hora_inicio']
            )
            count += 1
        
        print(f"--- [SCHEDULER]: Tarea finalizada. {count} recordatorios enviados. ---")
        return jsonify({"mensaje": f"{count} recordatorios enviados exitosamente."}), 200

    except Exception as e:
        print(f"¡ERROR GRAVE en /api/tasks/send-reminders!: {e}")
        return jsonify({"error": "Error interno del servidor al procesar recordatorios"}), 500


# --- ESTO SIEMPRE DEBE IR AL FINAL ---
if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 8080))
    app.run(debug=True, port=port)