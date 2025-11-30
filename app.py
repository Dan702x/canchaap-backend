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
from fpdf import FPDF
from flask import send_file
import io
from threading import Thread

app = Flask(__name__)

# Configura CORS
CORS(
    app, 
    resources={r"/api/.*": {
        "origins": [
            "http://localhost:5173", 
            "http://127.0.0.1:5173",
            "https://cannchapp.netlify.app"  # <--- ¡AGREGA ESTO! (Tu URL exacta sin barra al final)
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "supports_credentials": True,
        "wildcard": True
    }}
)

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
        filtro_ubicacion = request.args.get('ubicacion')
        filtro_deporte = request.args.get('deporte')

        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Error de conexión a la base de datos"}), 500
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, c.estado, 
                c.foto_url_1, -- ¡NUEVO!
                s.ubicacion_texto, s.latitud, s.longitud,
                MIN(t.precio_por_hora) AS precio_por_hora,
                MAX(f.id_usuario IS NOT NULL) AS is_favorito,
                td.nombre AS tipo_deporte
            FROM canchas c
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tipos_deporte td ON c.id_tipo_deporte = td.id_tipo_deporte
            LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
            LEFT JOIN favoritos f ON c.id_cancha = f.id_cancha AND f.id_usuario = %s
        """
        params = [id_usuario]

        where_clauses = []
        if filtro_ubicacion:
            where_clauses.append("s.ubicacion_texto LIKE %s")
            params.append(f"%{filtro_ubicacion}%")
        if filtro_deporte:
            where_clauses.append("c.id_tipo_deporte = %s")
            params.append(filtro_deporte)
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        query += """
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.estado, c.foto_url_1,
                     s.ubicacion_texto, s.latitud, s.longitud, td.nombre
            ORDER BY is_favorito DESC, c.nombre ASC
        """

        cursor.execute(query, tuple(params))
        canchas = cursor.fetchall()

        canchas_list = [] # Renombramos para evitar confusión
        for c in canchas:
            canchas_list.append({
                "id": c['id_cancha'], "nombre": c['nombre'], "ubicacion": c['ubicacion_texto'],
                "precio": c['precio_por_hora'] or 0,
                "imagen": c['foto_url_1'] or 'https://placehold.co/400x300/CCCCCC/FFFFFF?text=Sin+Imagen', # ¡CAMBIO!
                "lat": c['latitud'] or 0.0,
                "lng": c['longitud'] or 0.0,
                "is_favorito": bool(c['is_favorito']),
                "estado": bool(c['estado']),
                "tipo_deporte": c['tipo_deporte']
            })

        cursor.close()
        conn.close()
        return json.dumps(canchas_list, default=json_converter), 200, {'Content-Type': 'application/json'}
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

        # 1. Obtenemos datos de la cancha (¡ahora con las 3 URLs!)
        cancha_query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, 
                c.foto_url_1, c.foto_url_2, c.foto_url_3, -- ¡NUEVO!
                s.ubicacion_texto,
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
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.foto_url_1, c.foto_url_2, c.foto_url_3, 
                     s.ubicacion_texto, td.nombre, ts.nombre;
        """
        cursor.execute(cancha_query, (id_usuario, id))
        cancha = cursor.fetchone()

        if cancha is None:
            cursor.close()
            conn.close()
            return jsonify({"error": "Cancha no encontrada"}), 404

        # 2. ¡NUEVO! Creamos la galería dinámica filtrando URLs nulas
        gallery_urls = []
        if cancha['foto_url_1']: gallery_urls.append(cancha['foto_url_1'])
        if cancha['foto_url_2']: gallery_urls.append(cancha['foto_url_2'])
        if cancha['foto_url_3']: gallery_urls.append(cancha['foto_url_3'])

        if not gallery_urls:
            gallery_urls.append('https://placehold.co/600x400/CCCCCC/FFFFFF?text=Sin+Foto')

        # 3. Obtenemos las reseñas (como antes)
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
            "rating": sum(r['calificacion'] for r in reseñas) / len(reseñas) if reseñas else 0,
            "is_favorito": bool(cancha['is_favorito']),
            "description": cancha['descripcion'],
            "tipo_deporte": cancha['tipo_deporte'],
            "tipo_superficie": cancha['tipo_superficie'],
            "gallery": gallery_urls, # ¡Galería dinámica!
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

def send_async_email(app, email, code):
    with app.app_context():
        try:
            send_verification_email(email, code)
        except Exception as e:
            print(f"Error enviando correo en segundo plano: {e}")

@app.route('/api/register', methods=['POST'])
def registrar_usuario():
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
            # Enviamos el correo en un hilo paralelo para no congelar al usuario
            Thread(target=send_async_email, args=(app, email, verification_code)).start()
        except Exception as e:
            print(f"Error al iniciar el hilo de correo: {e}")
            # No detenemos el registro, el usuario ya está guardado.

        cursor.close()
        conn.close()
        return jsonify({"id_usuario": id_usuario, "mensaje": "Usuario registrado. Revisa tu email."}), 201

    except mysql.connector.Error as err:
        if err.errno == 1062:
            return jsonify({"error": "El correo electrónico ya está registrado."}), 409
        print(f"Error en POST /api/register: {err}")
        return jsonify({"error": "Error al registrar el usuario"}), 500

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
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
        query = """
        SELECT 
            u.id_usuario, u.first_name, u.last_name, u.email, u.documento, 
            u.telefono, u.recibir_notificaciones, u.id_rol, u.password, u.is_verified,
            e.estado AS empresa_estado,
            e.id_empresa
        FROM usuarios u
        LEFT JOIN empresas e ON u.id_usuario = e.id_usuario_admin
        WHERE u.email = %s
        """
        cursor.execute(query, (email,))
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
                "last_name": usuario['last_name'],
                "id_rol": usuario['id_rol'],
                "empresa_estado": usuario.get('empresa_estado')
            },
            "token": token
        }
        
        resp = make_response(jsonify(response_data))
        
        # ¡LA CORRECCIÓN ANTERIOR!
        resp.set_cookie(
            'token', 
            token,  # <-- ¡Arreglado!
            httponly=True, 
            samesite='None',
            secure=True,
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
            query = """
                SELECT 
                    u.id_usuario, u.first_name, u.last_name, u.email, u.documento, 
                    u.telefono, u.recibir_notificaciones, u.id_rol, -- <-- ¡AQUÍ ESTÁ EL ARREGLO!
                    e.estado AS empresa_estado,
                    e.id_empresa
                FROM usuarios u
                LEFT JOIN empresas e ON u.id_usuario = e.id_usuario_admin
                WHERE u.id_usuario = %s
            """
            cursor.execute(query, (id_usuario,))
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

            # --- CORRECCIÓN DE ZONA HORARIA ---
            # 1. Calculamos la hora actual en PERÚ (UTC - 5 horas)
            # datetime.utcnow() nos da la hora del servidor (UTC) y le restamos 5
            now_peru = datetime.utcnow() - timedelta(hours=5)

            # 2. Usamos esa hora en la consulta en lugar de NOW()
            query_update = """
                UPDATE reservas 
                SET estado = 'completada' 
                WHERE estado = 'confirmada' 
                AND fecha_hora_fin < %s;  
            """
            # Pasamos la variable now_peru como parámetro (tupla de 1 elemento)
            cursor.execute(query_update, (now_peru,))
            conn.commit()
            
            query = """
            SELECT 
                r.id_reserva, r.id_cancha, r.fecha_hora_inicio, 
                r.fecha_hora_fin, r.precio_total, r.estado,
                c.nombre AS cancha_nombre,
                s.nombre_sede, s.ubicacion_texto,
                p.id_transaccion_externa, p.metodo_pago -- ¡CAMPOS AÑADIDOS!
            FROM reservas r
            JOIN canchas c ON r.id_cancha = c.id_cancha
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN pagos p ON r.id_reserva = p.id_reserva -- ¡JOIN AÑADIDO!
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
        
        # Obtenemos la reserva
        cursor.execute(
            "SELECT fecha_hora_inicio, estado FROM reservas WHERE id_reserva = %s AND id_usuario = %s",
            (id, id_usuario) 
        )
        reserva = cursor.fetchone()
        
        if not reserva:
            cursor.close()
            conn.close()
            return jsonify({"error": "Reserva no encontrada o no te pertenece."}), 404

        # --- AQUÍ ESTÁ EL CAMBIO DE LÓGICA ---
        estado_actual = reserva['estado']

        # 1. Si ya está cancelada o completada, no hacemos nada
        if estado_actual in ['cancelada', 'completada']:
            cursor.close()
            conn.close()
            return jsonify({"error": "Esta reserva ya está finalizada o cancelada."}), 400

        # 2. Si está CONFIRMADA (Pagada), aplicamos la regla de 24 horas
        if estado_actual == 'confirmada':
            ahora = datetime.now()
            inicio_reserva = reserva['fecha_hora_inicio']
            if (inicio_reserva - ahora) < timedelta(hours=24):
                cursor.close()
                conn.close()
                return jsonify({"error": "No puedes cancelar una reserva pagada con menos de 24 horas de anticipación."}), 400

        # 3. Si está PENDIENTE, permitimos cancelar inmediatamente (pasa directo)
        
        # --- FIN DEL CAMBIO ---

        # Ejecutamos la cancelación
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
                c.id_cancha, c.nombre, c.estado,
                c.foto_url_1, -- ¡USA foto_url_1!
                s.ubicacion_texto,
                MIN(t.precio_por_hora) AS precio_por_hora,
                f.fecha_agregado
            FROM favoritos f
            JOIN canchas c ON f.id_cancha = c.id_cancha
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
            WHERE f.id_usuario = %s
            GROUP BY c.id_cancha, c.nombre, c.estado, c.foto_url_1, s.ubicacion_texto, f.fecha_agregado
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
                    "imagen": f['foto_url_1'] or 'https://placehold.co/400x300/CCCCCC/FFFFFF?text=Sin+Imagen',
                    "fecha_agregado": f['fecha_agregado'],
                    "estado": bool(f['estado'])
                    
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
        resp.set_cookie('token', '', httponly=True, samesite='None', secure=True, expires=0) 
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

# --- ¡NUEVO ENDPOINT PARA LIMPIAR RESERVAS PENDIENTES! ---
@app.route('/api/tasks/clean-pending-reservations', methods=['POST', 'OPTIONS'])
def clean_pending_reservations():
    # 1. Verificamos la clave secreta del Cron Job
    auth_header = request.headers.get('Authorization')
    secret_key = auth_header.split(' ')[1] if auth_header else None

    if not secret_key or secret_key != app.config['CRON_SECRET_KEY']:
        print("¡Intento fallido de ejecutar clean-pending! Clave secreta incorrecta.")
        return jsonify({"error": "No autorizado"}), 401

    print("--- [SCHEDULER]: Iniciando tarea de limpieza de reservas pendientes ---")

    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 2. Buscamos reservas pendientes creadas hace más de 60 minutos
        # Tu tabla 'reservas' ya tiene 'fecha_creacion'
        query = """
            UPDATE reservas
            SET estado = 'cancelada'
            WHERE 
                estado = 'pendiente'
                AND fecha_creacion < (NOW() - INTERVAL 60 MINUTE);
        """
        cursor.execute(query)
        conn.commit()

        count = cursor.rowcount # Vemos cuántas filas se actualizaron (cancelaron)

        cursor.close()
        conn.close()

        print(f"--- [SCHEDULER]: Tarea finalizada. {count} reservas pendientes fueron canceladas. ---")
        return jsonify({"mensaje": f"{count} reservas pendientes canceladas."}), 200

    except Exception as e:
        conn.rollback()
        print(f"¡ERROR GRAVE en /api/tasks/clean-pending-reservations!: {e}")
        return jsonify({"error": "Error interno al procesar la limpieza"}), 500
    
# --- (Endpoints de Gestión de Empresas - SPRINT 4) ---

@app.route('/api/empresas/solicitar-registro', methods=['POST'])
def solicitar_registro_empresa():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado. Debes iniciar sesión."}), 401

    try:
        data = request.json
        nombre = data.get('nombre')
        ruc = data.get('ruc')
        descripcion = data.get('descripcion')
        
        if not nombre or not ruc:
            return jsonify({"error": "El nombre y RUC son obligatorios."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 1. Verificar si el usuario ya tiene una empresa
        cursor.execute("SELECT id_empresa, estado FROM empresas WHERE id_usuario_admin = %s", (id_usuario,))
        empresa_existente = cursor.fetchone()
        
        if empresa_existente:
            cursor.close()
            conn.close()
            return jsonify({"error": f"Ya tienes una solicitud en estado: {empresa_existente['estado']}."}), 409
        
        # 2. Insertar la nueva solicitud de empresa
        query = """
            INSERT INTO empresas (id_usuario_admin, nombre, ruc, descripcion, estado)
            VALUES (%s, %s, %s, %s, 'pendiente')
        """
        cursor.execute(query, (id_usuario, nombre, ruc, descripcion))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"mensaje": "Solicitud de registro de empresa enviada. Un administrador la revisará."}), 201

    except mysql.connector.Error as err:
        if err.errno == 1062: # Error de RUC duplicado
            return jsonify({"error": "El RUC ingresado ya está registrado por otra empresa."}), 409
        print(f"Error en POST /api/empresas/solicitar-registro: {err}")
        return jsonify({"error": "Error al enviar la solicitud"}), 500
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/admin/empresas', methods=['GET'])
def get_empresas():
    id_usuario_admin = get_user_id_from_token()
    if not id_usuario_admin:
        return jsonify({"error": "No autorizado."}), 401
    
    try:
        # ¡NUEVO! Capturamos el filtro de estado
        filtro_estado = request.args.get('estado')
        
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 1. Validar que el usuario sea Administrador (rol 2)
        cursor.execute("SELECT id_rol FROM usuarios WHERE id_usuario = %s", (id_usuario_admin,))
        admin = cursor.fetchone()
        
        if not admin or admin['id_rol'] != 2:
            cursor.close()
            conn.close()
            return jsonify({"error": "Acceso denegado. No eres administrador."}), 403

        # 2. Obtener empresas con filtro
        query = """
            SELECT e.id_empresa, e.nombre, e.ruc, e.descripcion, e.estado, u.email
            FROM empresas e
            JOIN usuarios u ON e.id_usuario_admin = u.id_usuario
        """
        params = []
        
        # ¡NUEVO! Añadimos el filtro si existe
        if filtro_estado:
            query += " WHERE e.estado = %s"
            params.append(filtro_estado)
            
        query += " ORDER BY e.fecha_creacion DESC"
        
        cursor.execute(query, tuple(params))
        empresas = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return json.dumps(empresas, default=json_converter), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        print(f"Error en GET /api/admin/empresas: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/admin/solicitudes/<int:id_empresa>', methods=['PUT'])
def gestionar_solicitud(id_empresa):
    id_usuario_admin = get_user_id_from_token()
    if not id_usuario_admin:
        return jsonify({"error": "No autorizado."}), 401

    try:
        data = request.json
        accion = data.get('accion') # 'aprobar' o 'rechazar'
        
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # 1. Validar que el usuario sea Administrador (rol 2)
        cursor.execute("SELECT id_rol FROM usuarios WHERE id_usuario = %s", (id_usuario_admin,))
        admin = cursor.fetchone()
        
        if not admin or admin['id_rol'] != 2:
            cursor.close()
            conn.close()
            return jsonify({"error": "Acceso denegado."}), 403

        # 2. Determinar el nuevo estado y actualizar
        if accion == 'aprobar':
            query = "UPDATE empresas SET estado = 'activo', motivo_rechazo = NULL WHERE id_empresa = %s AND estado = 'pendiente'"
            params = (id_empresa,)
            mensaje = "Solicitud marcada como 'activo'."
            
        elif accion == 'rechazar':
            motivo = data.get('motivo', 'Rechazado por el administrador.') # Captura el motivo
            query = "UPDATE empresas SET estado = 'rechazado', motivo_rechazo = %s WHERE id_empresa = %s AND estado = 'pendiente'"
            params = (motivo, id_empresa)
            mensaje = "Solicitud marcada como 'rechazado'."
            
        else:
            cursor.close()
            conn.close()
            return jsonify({"error": "Acción no válida. Debe ser 'aprobar' o 'rechazar'."}), 400
            
        # 3. Ejecutar la actualización
        cursor.execute(query, params)
        conn.commit()
        
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()

        if affected_rows == 0:
            return jsonify({"error": "No se encontró la solicitud pendiente o ya fue gestionada."}), 404
        
        return jsonify({"mensaje": mensaje}), 200
        
    except Exception as e:
        conn.rollback() # ¡Añadimos rollback por si falla!
        print(f"Error en PUT /api/admin/solicitudes/<id>: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500


# --- (Helper para obtener la empresa del usuario logueado) ---
def get_empresa_id_from_token():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return None, "No autorizado. Debes iniciar sesión."

    try:
        conn = get_db_connection()
        if conn is None:
            return None, "Error de conexión."
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_empresa, estado FROM empresas WHERE id_usuario_admin = %s", (id_usuario,))
        empresa = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not empresa:
            return None, "Este usuario no está asociado a ninguna empresa."
        if empresa['estado'] != 'activo':
            return None, f"El estado de tu empresa es '{empresa['estado']}'. No puedes gestionar canchas."
            
        return empresa['id_empresa'], None
    except Exception as e:
        print(f"Error en get_empresa_id_from_token: {e}")
        return None, "Error interno al verificar la empresa."


# --- (Endpoints de Gestión de Sedes - SPRINT 4) ---

@app.route('/api/empresa/sedes', methods=['GET'])
def get_mis_sedes():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403 # 403 = Prohibido

    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM sedes WHERE id_empresa = %s ORDER BY nombre_sede"
        cursor.execute(query, (id_empresa,))
        sedes = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return json.dumps(sedes, default=json_converter), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        print(f"Error en GET /api/empresa/sedes: {e}")
        return jsonify({"error": "Error al obtener las sedes"}), 500

@app.route('/api/empresa/sedes', methods=['POST'])
def crear_nueva_sede():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        data = request.json
        nombre_sede = data.get('nombre_sede')
        ubicacion_texto = data.get('ubicacion_texto')

        # --- ¡ESTA ES LA CORRECCIÓN! ---
        # Convertimos los valores a float o los dejamos como None

        lat_str = data.get('latitud')
        lng_str = data.get('longitud')

        # Si el string no está vacío, lo convertimos a float. Si está vacío o es None, lo dejamos como None.
        latitud = float(lat_str) if lat_str else None
        longitud = float(lng_str) if lng_str else None
        # --- FIN DE LA CORRECCIÓN ---

        if not nombre_sede or not ubicacion_texto:
            return jsonify({"error": "El nombre de la sede y la ubicación son obligatorios."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # ¡NUEVO! Consulta actualizada
        query = """
            INSERT INTO sedes (id_empresa, nombre_sede, ubicacion_texto, latitud, longitud)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (id_empresa, nombre_sede, ubicacion_texto, latitud, longitud))
        conn.commit()
        id_sede = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        # ¡NUEVO! Devolvemos los nuevos campos
        return jsonify({
            "id_sede": id_sede, 
            "id_empresa": id_empresa,
            "nombre_sede": nombre_sede, 
            "ubicacion_texto": ubicacion_texto,
            "latitud": latitud,
            "longitud": longitud
        }), 201

    except Exception as e:
        conn.rollback() # <-- ¡AÑADIDO!
        print(f"Error en POST /api/empresa/sedes: {e}")
        return jsonify({"error": "Error al crear la sede"}), 500
    
@app.route('/api/empresa/sedes/<int:id_sede>', methods=['PUT'])
def actualizar_sede(id_sede):
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        data = request.json
        nombre_sede = data.get('nombre_sede')
        ubicacion_texto = data.get('ubicacion_texto')
        latitud = float(data.get('latitud')) if data.get('latitud') else None
        longitud = float(data.get('longitud')) if data.get('longitud') else None

        if not nombre_sede or not ubicacion_texto:
            return jsonify({"error": "El nombre y la dirección son obligatorios."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # Actualizamos la sede, asegurándonos que pertenezca a la empresa
        query = """
            UPDATE sedes SET 
                nombre_sede = %s, 
                ubicacion_texto = %s, 
                latitud = %s, 
                longitud = %s
            WHERE id_sede = %s AND id_empresa = %s
        """
        cursor.execute(query, (nombre_sede, ubicacion_texto, latitud, longitud, id_sede, id_empresa))
        conn.commit()
        
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({"error": "No se pudo actualizar la sede. No se encontró o no te pertenece."}), 404
        
        return jsonify({
            "id_sede": id_sede, "nombre_sede": nombre_sede, "ubicacion_texto": ubicacion_texto,
            "latitud": latitud, "longitud": longitud
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en PUT /api/empresa/sedes/<id>: {e}")
        return jsonify({"error": "Error al actualizar la sede"}), 500

@app.route('/api/empresa/sedes/<int:id_sede>', methods=['DELETE'])
def eliminar_sede(id_sede):
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # Eliminamos la sede, asegurándonos que pertenezca a la empresa
        query = "DELETE FROM sedes WHERE id_sede = %s AND id_empresa = %s"
        cursor.execute(query, (id_sede, id_empresa))
        conn.commit()
        
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({"error": "No se pudo eliminar la sede. No se encontró o no te pertenece."}), 404
            
        return jsonify({"mensaje": "Sede eliminada exitosamente"}), 200

    except mysql.connector.Error as err:
        conn.rollback()
        # Error de llave foránea (si la sede tiene canchas)
        if err.errno == 1451: 
            return jsonify({"error": "No se puede eliminar la sede porque tiene canchas asociadas. Primero elimina sus canchas."}), 409
        print(f"Error en DELETE /api/empresa/sedes/<id>: {err}")
        return jsonify({"error": "Error al eliminar la sede"}), 500

# --- (Endpoints de Catálogos - SPRINT 4) ---

@app.route('/api/catalogos/tipos-deporte', methods=['GET'])
def get_tipos_deporte():
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_tipo_deporte, nombre FROM tipos_deporte ORDER BY nombre")
        tipos = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(tipos)
    except Exception as e:
        print(f"Error en GET /api/catalogos/tipos-deporte: {e}")
        return jsonify({"error": "Error al obtener tipos de deporte"}), 500

@app.route('/api/catalogos/tipos-superficie', methods=['GET'])
def get_tipos_superficie():
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_tipo_superficie, nombre FROM tipos_superficie ORDER BY nombre")
        tipos = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(tipos)
    except Exception as e:
        print(f"Error en GET /api/catalogos/tipos-superficie: {e}")
        return jsonify({"error": "Error al obtener tipos de superficie"}), 500


# --- (Endpoints de Gestión de Canchas - SPRINT 4) ---

@app.route('/api/empresa/canchas', methods=['GET'])
def get_mis_canchas():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403
    try:
        filtro_sede_id = request.args.get('sede')
        filtro_deporte_id = request.args.get('deporte')
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, c.estado,
                c.foto_url_1, c.foto_url_2, c.foto_url_3, -- ¡ESTO ES LO IMPORTANTE!
                s.id_sede, s.nombre_sede,
                t.nombre AS tipo_deporte,
                ts.id_tipo_superficie, ts.nombre AS tipo_superficie,
                c.id_tipo_deporte,
                tar.precio_por_hora
            FROM canchas c
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tipos_deporte t ON c.id_tipo_deporte = t.id_tipo_deporte
            LEFT JOIN tipos_superficie ts ON c.id_tipo_superficie = ts.id_tipo_superficie
            LEFT JOIN tarifas tar ON c.id_cancha = tar.id_cancha
            WHERE s.id_empresa = %s
        """
        params = [id_empresa]
        if filtro_sede_id:
            query += " AND s.id_sede = %s"
            params.append(filtro_sede_id)
        if filtro_deporte_id:
            query += " AND c.id_tipo_deporte = %s"
            params.append(filtro_deporte_id)
        query += """
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.estado,
                     c.foto_url_1, c.foto_url_2, c.foto_url_3,
                     s.id_sede, s.nombre_sede, t.nombre, ts.id_tipo_superficie, 
                     ts.nombre, c.id_tipo_deporte, tar.precio_por_hora
            ORDER BY s.nombre_sede, c.nombre
        """
        
        cursor.execute(query, tuple(params))
        canchas = cursor.fetchall()
        
        for cancha in canchas:
            cancha['foto_principal'] = cancha['foto_url_1'] or 'https://placehold.co/100x75/CCCCCC/FFFFFF?text=Sin+Foto'
        
        cursor.close()
        conn.close()
        return json.dumps(canchas, default=json_converter), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(f"Error en GET /api/empresa/canchas: {e}")
        return jsonify({"error": "Error al obtener las canchas"}), 500

@app.route('/api/empresa/canchas', methods=['POST'])
def crear_nueva_cancha():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    conn = None
    cursor = None
    try:
        # 1. Volvemos a usar request.json
        data = request.json
        id_sede = data.get('id_sede')
        id_tipo_deporte = data.get('id_tipo_deporte')
        nombre = data.get('nombre')
        precio_por_hora = data.get('precio_por_hora')

        # 2. ¡NUEVO! Campos ahora obligatorios
        descripcion = data.get('descripcion')
        foto_url_1 = data.get('foto_url_1')

        # 3. Campos opcionales
        id_tipo_superficie = data.get('id_tipo_superficie') or None
        foto_url_2 = data.get('foto_url_2') or None
        foto_url_3 = data.get('foto_url_3') or None

        # 4. Validación (con los nuevos campos obligatorios)
        if not all([id_sede, id_tipo_deporte, nombre, precio_por_hora, descripcion, foto_url_1]):
            return jsonify({"error": "Faltan campos obligatorios. Sede, Deporte, Nombre, Precio, Descripción y Foto 1 son requeridos."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 5. Verificamos la sede (como antes)
        cursor.execute("SELECT id_sede FROM sedes WHERE id_sede = %s AND id_empresa = %s", (id_sede, id_empresa))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"error": "La sede seleccionada no te pertenece."}), 403

        # 6. Insertamos la cancha (¡CON las nuevas columnas de fotos!)
        query_cancha = """
            INSERT INTO canchas (id_sede, id_tipo_deporte, id_tipo_superficie, nombre, descripcion, estado, foto_url_1, foto_url_2, foto_url_3)
            VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s)
        """
        cursor.execute(query_cancha, (
            id_sede, id_tipo_deporte, id_tipo_superficie, 
            nombre, descripcion, foto_url_1, foto_url_2, foto_url_3
        ))
        id_cancha = cursor.lastrowid

        # 7. Insertamos la tarifa (como antes)
        query_tarifa = "INSERT INTO tarifas (id_cancha, descripcion, precio_por_hora) VALUES (%s, %s, %s)"
        cursor.execute(query_tarifa, (id_cancha, 'Tarifa General', precio_por_hora))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"mensaje": "Cancha creada exitosamente", "id_cancha": id_cancha}), 201

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error en POST /api/empresa/canchas: {e}")
        return jsonify({"error": "Error al crear la cancha"}), 500

@app.route('/api/empresa/canchas/<int:id_cancha>', methods=['PUT'])
def actualizar_cancha(id_cancha):
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    conn = None # Definimos conn aquí para usarlo en el except
    try:
        data = request.json # ¡Usamos JSON!

        # --- CAMPOS OBLIGATORIOS ---
        id_sede = data.get('id_sede')
        id_tipo_deporte = data.get('id_tipo_deporte')
        nombre = data.get('nombre')
        precio_por_hora = data.get('precio_por_hora')
        descripcion = data.get('descripcion')
        foto_url_1 = data.get('foto_url_1')

        # --- CAMPOS OPCIONALES ---
        id_tipo_superficie = data.get('id_tipo_superficie') or None
        foto_url_2 = data.get('foto_url_2') or None
        foto_url_3 = data.get('foto_url_3') or None

        if not all([id_sede, id_tipo_deporte, nombre, precio_por_hora, descripcion, foto_url_1]):
            return jsonify({"error": "Faltan campos obligatorios."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 1. Verificamos que la cancha y la sede pertenezcan a la empresa
        cursor.execute("""
            SELECT c.id_cancha FROM canchas c JOIN sedes s ON c.id_sede = s.id_sede
            WHERE c.id_cancha = %s AND s.id_empresa = %s
        """, (id_cancha, id_empresa))
        cancha_valida = cursor.fetchone()

        cursor.execute("SELECT id_sede FROM sedes WHERE id_sede = %s AND id_empresa = %s", (id_sede, id_empresa))
        sede_valida = cursor.fetchone()

        if not cancha_valida or not sede_valida:
            cursor.close()
            conn.close()
            return jsonify({"error": "No tienes permiso para editar esta cancha o esta sede no te pertenece."}), 403

        # 2. ¡AQUÍ ESTÁ LA CORRECCIÓN!
        # Actualizamos la tabla 'canchas' con las 3 URLs, sin 'foto'
        query_cancha = """
            UPDATE canchas SET
                id_sede = %s, id_tipo_deporte = %s, id_tipo_superficie = %s,
                nombre = %s, descripcion = %s, 
                foto_url_1 = %s, foto_url_2 = %s, foto_url_3 = %s
            WHERE id_cancha = %s
        """
        cursor.execute(query_cancha, (
            id_sede, id_tipo_deporte, id_tipo_superficie, 
            nombre, descripcion, foto_url_1, foto_url_2, foto_url_3, id_cancha
        ))

        # 3. Actualizamos la tabla 'tarifas'
        query_tarifa = "UPDATE tarifas SET precio_por_hora = %s WHERE id_cancha = %s"
        cursor.execute(query_tarifa, (precio_por_hora, id_cancha))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"mensaje": "Cancha actualizada exitosamente"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error en PUT /api/empresa/canchas/<id>: {e}")
        return jsonify({"error": "Error al actualizar la cancha"}), 500

@app.route('/api/empresa/canchas/<int:id_cancha>/estado', methods=['PUT'])
def cambiar_estado_cancha(id_cancha):
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        data = request.json
        nuevo_estado = bool(data.get('estado')) # Convertimos a 1 o 0

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # Verificamos que la cancha pertenezca a la empresa
        query_check = """
            SELECT c.id_cancha FROM canchas c JOIN sedes s ON c.id_sede = s.id_sede
            WHERE c.id_cancha = %s AND s.id_empresa = %s
        """
        cursor.execute(query_check, (id_cancha, id_empresa))
        cancha_valida = cursor.fetchone()
        
        if not cancha_valida:
            cursor.close()
            conn.close()
            return jsonify({"error": "No tienes permiso para modificar esta cancha."}), 403

        # Actualizamos el estado
        query_update = "UPDATE canchas SET estado = %s WHERE id_cancha = %s"
        cursor.execute(query_update, (nuevo_estado, id_cancha))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"mensaje": f"Estado de la cancha actualizado a {'activo' if nuevo_estado else 'inactivo'}"}), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en PUT /api/empresa/canchas/<id>/estado: {e}")
        return jsonify({"error": "Error al cambiar el estado de la cancha"}), 500

@app.route('/api/empresa/canchas/<int:id_cancha>', methods=['DELETE', 'OPTIONS'])
def eliminar_cancha(id_cancha):
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    conn = None # Definimos conn aquí para usarlo en el except
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 1. Verificamos que la cancha pertenezca a la empresa
        query_check = """
            SELECT c.id_cancha FROM canchas c JOIN sedes s ON c.id_sede = s.id_sede
            WHERE c.id_cancha = %s AND s.id_empresa = %s
        """
        cursor.execute(query_check, (id_cancha, id_empresa))
        cancha_valida = cursor.fetchone()
        
        if not cancha_valida:
            cursor.close()
            conn.close()
            return jsonify({"error": "No tienes permiso para eliminar esta cancha."}), 403

        # 2. ¡NUEVA VERIFICACIÓN! Buscamos solo reservas ACTIVAS
        query_reservas_activas = """
            SELECT id_reserva FROM reservas 
            WHERE id_cancha = %s AND (estado = 'pendiente' OR estado = 'confirmada')
            LIMIT 1
        """
        cursor.execute(query_reservas_activas, (id_cancha,))
        reserva_activa = cursor.fetchone()

        if reserva_activa:
            # Si hay reservas activas, bloqueamos la eliminación
            cursor.close()
            conn.close()
            return jsonify({"error": "No se puede eliminar la cancha porque tiene reservas activas o pendientes."}), 409

        # 3. Si no hay reservas activas, procedemos a borrar todo en orden
        
        # 3.1. Borrar hijos de 'reservas' (reseñas, pagos)
        # Obtenemos TODAS las reservas (canceladas, completadas) de esta cancha
        cursor.execute("SELECT id_reserva FROM reservas WHERE id_cancha = %s", (id_cancha,))
        reservas = cursor.fetchall()
        
        if reservas:
            id_reservas = tuple(r['id_reserva'] for r in reservas)
            res_placeholder = '%s'
            if len(id_reservas) > 1:
                res_placeholder = ', '.join(['%s'] * len(id_reservas))
            
            cursor.execute(f"DELETE FROM reseñas WHERE id_reserva IN ({res_placeholder})", id_reservas)
            cursor.execute(f"DELETE FROM pagos WHERE id_reserva IN ({res_placeholder})", id_reservas)
            # 3.2. Borrar las 'reservas' en sí
            cursor.execute(f"DELETE FROM reservas WHERE id_reserva IN ({res_placeholder})", id_reservas)

        # 3.3. Borrar otros hijos de 'canchas' (favoritos, tarifas, imagenes)
        cursor.execute("DELETE FROM favoritos WHERE id_cancha = %s", (id_cancha,))
        cursor.execute("DELETE FROM tarifas WHERE id_cancha = %s", (id_cancha,))
        
        # 3.4. Finalmente, borrar la cancha
        cursor.execute("DELETE FROM canchas WHERE id_cancha = %s", (id_cancha,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"mensaje": "Cancha eliminada permanentemente"}), 200

    except mysql.connector.Error as err:
        if conn:
            conn.rollback()
        # Este error ya no debería ocurrir, pero lo dejamos por seguridad
        if err.errno == 1451:
            return jsonify({"error": "No se puede eliminar la cancha porque tiene reservas asociadas (Error 1451)."}), 409
        print(f"Error en DELETE /api/empresa/canchas/<id>: {err}")
        return jsonify({"error": "Error al eliminar la cancha"}), 500

@app.route('/api/empresa/mi-solicitud', methods=['GET'])
def get_mi_solicitud():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401

    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # Buscamos la empresa vinculada a este usuario
        cursor.execute("SELECT estado, motivo_rechazo FROM empresas WHERE id_usuario_admin = %s", (id_usuario,))
        solicitud = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not solicitud:
            # Si no hay solicitud, no es un error, solo significa que aún no ha aplicado
            return jsonify({"estado": None}), 200 
            
        return jsonify(solicitud)

    except Exception as e:
        print(f"Error en GET /api/empresa/mi-solicitud: {e}")
        return jsonify({"error": "Error al obtener la solicitud"}), 500

@app.route('/api/empresa/mi-solicitud', methods=['DELETE'])
def eliminar_mi_solicitud():
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # El usuario solo puede borrar su solicitud si está 'rechazada'
        query = "DELETE FROM empresas WHERE id_usuario_admin = %s AND estado = 'rechazado'"
        cursor.execute(query, (id_usuario,))
        conn.commit()
        
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({"error": "No se encontró una solicitud rechazada para eliminar."}), 404
            
        return jsonify({"mensaje": "Solicitud eliminada. Ya puedes aplicar de nuevo."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en DELETE /api/empresa/mi-solicitud: {e}")
        return jsonify({"error": "Error al eliminar la solicitud"}), 500

@app.route('/api/empresa/mi-empresa', methods=['GET'])
def get_mi_empresa_datos():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # Obtenemos los datos actuales de la empresa
        cursor.execute("SELECT nombre, ruc, descripcion FROM empresas WHERE id_empresa = %s", (id_empresa,))
        empresa_datos = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not empresa_datos:
            return jsonify({"error": "No se encontraron datos de la empresa."}), 404
            
        return jsonify(empresa_datos)

    except Exception as e:
        print(f"Error en GET /api/empresa/mi-empresa: {e}")
        return jsonify({"error": "Error al obtener los datos de la empresa"}), 500

@app.route('/api/empresa/mi-empresa', methods=['PUT'])
def update_mi_empresa_datos():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        data = request.json
        nombre = data.get('nombre')
        descripcion = data.get('descripcion')
        
        if not nombre:
            return jsonify({"error": "El nombre de la empresa es obligatorio."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # ¡Importante! Solo permitimos actualizar nombre y descripción. El RUC no se toca.
        query = """
            UPDATE empresas SET 
                nombre = %s, 
                descripcion = %s
            WHERE id_empresa = %s
        """
        cursor.execute(query, (nombre, descripcion, id_empresa))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"mensaje": "Datos de la empresa actualizados."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en PUT /api/empresa/mi-empresa: {e}")
        return jsonify({"error": "Error al actualizar los datos"}), 500

# --- (Endpoints de Eliminación de Empresa - SPRINT 4) ---

@app.route('/api/empresa/delete-check', methods=['GET'])
def check_empresa_deletable():
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # 1. Buscamos todas las canchas de esta empresa
        cursor.execute("SELECT id_cancha FROM canchas c JOIN sedes s ON c.id_sede = s.id_sede WHERE s.id_empresa = %s", (id_empresa,))
        canchas = cursor.fetchall()
        
        if canchas:
            # 2. Verificamos si alguna de esas canchas tiene reservas activas
            id_canchas = tuple(c['id_cancha'] for c in canchas)
            placeholder = '%s'
            if len(id_canchas) > 1:
                placeholder = ', '.join(['%s'] * len(id_canchas))
                
            query_reservas = f"""
                SELECT id_reserva FROM reservas 
                WHERE id_cancha IN ({placeholder}) 
                AND (estado = 'pendiente' OR estado = 'confirmada')
                LIMIT 1;
            """
            cursor.execute(query_reservas, id_canchas)
            reserva_activa = cursor.fetchone()
            
            if reserva_activa:
                cursor.close()
                conn.close()
                return jsonify({"error": "No puedes eliminar tu negocio porque tienes reservas activas o pendientes. Debes cancelarlas primero."}), 409
        
        # Si no hay canchas o no hay reservas activas, se puede borrar
        cursor.close()
        conn.close()
        return jsonify({"message": "OK"}), 200

    except Exception as e:
        print(f"Error en GET /api/empresa/delete-check: {e}")
        return jsonify({"error": "Error al verificar el estado de la empresa"}), 500


@app.route('/api/empresa/delete-confirm', methods=['POST'])
def delete_empresa_confirm():
    id_usuario = get_user_id_from_token()
    id_empresa, error_msg = get_empresa_id_from_token()
    if error_msg:
        return jsonify({"error": error_msg}), 403

    try:
        data = request.json
        password_plano = data['password']
        
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # 1. Verificamos la contraseña del usuario
        cursor.execute("SELECT password FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        usuario = cursor.fetchone()
        
        if not usuario or not bcrypt.checkpw(password_plano.encode('utf-8'), usuario['password'].encode('utf-8')):
            cursor.close()
            conn.close()
            return jsonify({"error": "La contraseña es incorrecta."}), 401

        # 2. Re-verificamos que no haya reservas activas (por si acaso)
        cursor.execute("SELECT id_cancha FROM canchas c JOIN sedes s ON c.id_sede = s.id_sede WHERE s.id_empresa = %s", (id_empresa,))
        canchas = cursor.fetchall()
        
        if canchas:
            id_canchas = tuple(c['id_cancha'] for c in canchas)
            placeholder = '%s'
            if len(id_canchas) > 1:
                placeholder = ', '.join(['%s'] * len(id_canchas))
            
            query_reservas = f"SELECT id_reserva FROM reservas WHERE id_cancha IN ({placeholder}) AND (estado = 'pendiente' OR estado = 'confirmada') LIMIT 1"
            cursor.execute(query_reservas, id_canchas)
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({"error": "No se puede eliminar, se encontró una reserva activa."}), 409
            
            # 3. Procedemos con la eliminación en cascada
            # (Asumimos que las reservas completadas/canceladas pueden quedarse huérfanas o borrarse)
            # Por simplicidad, borraremos todo lo vinculado
            
            query_reservas_all = f"SELECT id_reserva FROM reservas WHERE id_cancha IN ({placeholder})"
            cursor.execute(query_reservas_all, id_canchas)
            reservas = cursor.fetchall()
            
            if reservas:
                id_reservas = tuple(r['id_reserva'] for r in reservas)
                res_placeholder = '%s'
                if len(id_reservas) > 1:
                    res_placeholder = ', '.join(['%s'] * len(id_reservas))
                
                cursor.execute(f"DELETE FROM reseñas WHERE id_reserva IN ({res_placeholder})", id_reservas)
                cursor.execute(f"DELETE FROM pagos WHERE id_reserva IN ({res_placeholder})", id_reservas)
                cursor.execute(f"DELETE FROM reservas WHERE id_reserva IN ({res_placeholder})", id_reservas)

            cursor.execute(f"DELETE FROM favoritos WHERE id_cancha IN ({placeholder})", id_canchas)
            cursor.execute(f"DELETE FROM tarifas WHERE id_cancha IN ({placeholder})", id_canchas)
            cursor.execute(f"DELETE FROM canchas WHERE id_cancha IN ({placeholder})", id_canchas)
        
        # 4. Finalmente, borramos las sedes y la empresa
        cursor.execute("DELETE FROM sedes WHERE id_empresa = %s", (id_empresa,))
        cursor.execute("DELETE FROM empresas WHERE id_empresa = %s", (id_empresa,))
        
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"mensaje": "Negocio eliminado exitosamente."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en POST /api/empresa/delete-confirm: {e}")
        return jsonify({"error": "Error interno al eliminar el negocio"}), 500

@app.route('/api/admin/empresas/<int:id_empresa>', methods=['PUT'])
def admin_update_empresa(id_empresa):
    id_usuario_admin = get_user_id_from_token()
    if not id_usuario_admin:
        return jsonify({"error": "No autorizado."}), 401
        
    try:
        data = request.json
        nombre = data.get('nombre')
        ruc = data.get('ruc')

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # 1. Validar que el usuario sea Administrador (rol 2)
        cursor.execute("SELECT id_rol FROM usuarios WHERE id_usuario = %s", (id_usuario_admin,))
        admin = cursor.fetchone()
        if not admin or admin['id_rol'] != 2:
            cursor.close()
            conn.close()
            return jsonify({"error": "Acceso denegado."}), 403

        # 2. Actualizar la empresa
        query = "UPDATE empresas SET nombre = %s, ruc = %s WHERE id_empresa = %s"
        cursor.execute(query, (nombre, ruc, id_empresa))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"mensaje": "Empresa actualizada por Admin."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en PUT /api/admin/empresas/<id>: {e}")
        return jsonify({"error": "Error al actualizar empresa"}), 500

@app.route('/api/admin/empresas/<int:id_empresa>/estado', methods=['PUT'])
def admin_update_estado_empresa(id_empresa):
    id_usuario_admin = get_user_id_from_token()
    if not id_usuario_admin:
        return jsonify({"error": "No autorizado."}), 401
        
    try:
        data = request.json
        nuevo_estado = data.get('estado') # 'activo' o 'rechazado'
        
        if nuevo_estado not in ['activo', 'rechazado']:
            return jsonify({"error": "Estado no válido."}), 400

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 1. Validar que el usuario sea Administrador (rol 2)
        cursor.execute("SELECT id_rol FROM usuarios WHERE id_usuario = %s", (id_usuario_admin,))
        admin = cursor.fetchone()
        if not admin or admin['id_rol'] != 2:
            cursor.close()
            conn.close()
            return jsonify({"error": "Acceso denegado."}), 403

        # 2. Actualizar estado (y limpiar motivo si se aprueba)
        query = "UPDATE empresas SET estado = %s, motivo_rechazo = CASE WHEN %s = 'activo' THEN NULL ELSE motivo_rechazo END WHERE id_empresa = %s"
        cursor.execute(query, (nuevo_estado, nuevo_estado, id_empresa))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"mensaje": f"Estado de la empresa actualizado a '{nuevo_estado}'."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Error en PUT /api/admin/empresas/<id>/estado: {e}")
        return jsonify({"error": "Error al actualizar estado"}), 500

def generar_pdf_comprobante(reserva_id):
    """Función helper para generar el PDF de un comprobante con diseño profesional."""
    conn = get_db_connection()
    if conn is None: raise Exception("Error de conexión")
    
    cursor = conn.cursor(dictionary=True)
    
    # 1. Consulta de datos
    query = """
        SELECT 
            r.id_reserva, r.fecha_hora_inicio, r.precio_total,
            p.id_transaccion_externa, p.metodo_pago, p.fecha_pago,
            u.first_name, u.last_name, u.email, u.documento,
            c.nombre AS cancha_nombre,
            s.nombre_sede, s.ubicacion_texto,
            e.nombre AS empresa_nombre, e.ruc AS empresa_ruc
        FROM reservas r
        JOIN pagos p ON r.id_reserva = p.id_reserva
        JOIN usuarios u ON r.id_usuario = u.id_usuario
        JOIN canchas c ON r.id_cancha = c.id_cancha
        JOIN sedes s ON c.id_sede = s.id_sede
        JOIN empresas e ON s.id_empresa = e.id_empresa
        WHERE r.id_reserva = %s
    """
    cursor.execute(query, (reserva_id,))
    data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not data:
        raise Exception("Reserva no encontrada o sin pago.")
        
    pdf = FPDF()
    pdf.add_page()
    
    def sanitize(text):
        if text is None: return ''
        return str(text).encode('latin-1', 'replace').decode('latin-1')

    # --- DISEÑO DEL COMPROBANTE ---
    
    # Variables de posición
    left_col_width = 115
    right_col_x = 130
    top_margin = 10
    
    pdf.set_xy(10, top_margin)

    # 1. CABECERA (Izquierda)
    pdf.set_font("Arial", 'B', 16)
    
    # Guardamos X para alinear
    current_x = pdf.get_x()
    pdf.multi_cell(left_col_width, 8, sanitize(data['empresa_nombre']), 0, 'L')
    
    # --- ¡CAMBIO! Añadimos un pequeño espacio antes de la dirección ---
    pdf.ln(2) 
    
    # Reseteamos X y cambiamos fuente
    pdf.set_x(current_x)
    pdf.set_font("Arial", '', 9)
    pdf.multi_cell(left_col_width, 5, sanitize(data['nombre_sede']), 0, 'L')
    
    pdf.set_x(current_x)
    pdf.multi_cell(left_col_width, 5, sanitize(data['ubicacion_texto']), 0, 'L')
    
    pdf.set_x(current_x)
    pdf.cell(left_col_width, 5, "Email: contacto@canchapp.com", 0, 1, 'L')
    
    # Guardamos hasta dónde llegó la izquierda para no chocar luego
    y_final_izquierda = pdf.get_y()

    # (Derecha) Cuadro de RUC y Número
    # Volvemos arriba a la derecha
    pdf.set_xy(right_col_x, top_margin) 
    pdf.set_font("Arial", 'B', 11)
    
    # Dibujamos el borde
    pdf.rect(right_col_x, top_margin, 70, 30)
    
    # --- ¡CORRECCIÓN VITAL AQUÍ! ---
    # Usamos set_x(right_col_x) antes de CADA línea para que no se vaya a la izquierda
    
    # Línea 1: RUC
    pdf.set_x(right_col_x) 
    pdf.cell(70, 8, f"R.U.C. {sanitize(data['empresa_ruc'])}", 0, 1, 'C')
    
    # Línea 2: Fondo Negro
    pdf.set_x(right_col_x) # <--- ESTO ARREGLA LA SUPERPOSICIÓN
    pdf.set_fill_color(0, 0, 0)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(70, 8, "COMPROBANTE ELECTRONICO", 1, 1, 'C', True)
    
    # Línea 3: Número de serie
    pdf.set_x(right_col_x) # <--- ESTO TAMBIÉN
    pdf.set_text_color(0, 0, 0)
    numero_comprobante = f"E001-{int(data['id_reserva']):06d}"
    pdf.cell(70, 14, numero_comprobante, 0, 1, 'C')

    # Calculamos dónde seguir (el máximo entre la izquierda y la caja derecha)
    y_start_body = max(y_final_izquierda, 55) 
    pdf.set_y(y_start_body)
    pdf.ln(5)

    # 2. DATOS DEL CLIENTE (Resto igual...)
    pdf.set_font("Arial", 'B', 9)
    pdf.cell(30, 6, "CLIENTE:", 0, 0)
    pdf.set_font("Arial", '', 9)
    pdf.cell(90, 6, f"{sanitize(data['first_name'])} {sanitize(data['last_name'])}", 0, 0)
    
    pdf.set_font("Arial", 'B', 9)
    pdf.cell(30, 6, "FECHA EMISION:", 0, 0)
    pdf.set_font("Arial", '', 9)
    fecha_pago = data['fecha_pago'].strftime('%d/%m/%Y') if data['fecha_pago'] else datetime.now().strftime('%d/%m/%Y')
    pdf.cell(40, 6, fecha_pago, 0, 1)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(30, 6, "DOC. IDENTIDAD:", 0, 0)
    pdf.set_font("Arial", '', 9)
    pdf.cell(90, 6, sanitize(data['documento'] or '-'), 0, 0)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(30, 6, "MONEDA:", 0, 0)
    pdf.set_font("Arial", '', 9)
    pdf.cell(40, 6, "SOLES", 0, 1)
    
    pdf.ln(5)

    # 3. TABLA DE ÍTEMS
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font("Arial", 'B', 9)
    pdf.cell(15, 8, "CANT.", 1, 0, 'C', True)
    pdf.cell(115, 8, "DESCRIPCION", 1, 0, 'L', True)
    pdf.cell(30, 8, "P. UNIT", 1, 0, 'R', True)
    pdf.cell(30, 8, "IMPORTE", 1, 1, 'R', True)
    
    pdf.set_font("Arial", '', 9)
    pdf.cell(15, 8, "1", 1, 0, 'C')
    
    fecha_reserva_str = data['fecha_hora_inicio'].strftime('%d/%m/%Y %H:%M')
    
    # Guardamos posición para la descripción multilínea
    current_x_table = pdf.get_x()
    current_y_table = pdf.get_y()
    
    descripcion_item = f"Alquiler de Cancha: {sanitize(data['cancha_nombre'])} ({fecha_reserva_str})"
    pdf.multi_cell(115, 8, descripcion_item, 1, 'L')
    
    # Volvemos a la derecha para el precio
    pdf.set_xy(current_x_table + 115, current_y_table)

    precio_str = f"{data['precio_total']:.2f}"
    pdf.cell(30, 8, precio_str, 1, 0, 'R')
    pdf.cell(30, 8, precio_str, 1, 1, 'R')
    
    pdf.ln(max(8, pdf.get_y() - current_y_table))

    # 4. TOTALES
    total = float(data['precio_total'])
    subtotal = total / 1.18
    igv = total - subtotal
    
    start_x_totals = 140
    
    pdf.set_x(start_x_totals)
    pdf.cell(20, 6, "OP. GRAVADA", 0, 0, 'R')
    pdf.cell(30, 6, f"S/ {subtotal:.2f}", 0, 1, 'R')
    
    pdf.set_x(start_x_totals)
    pdf.cell(20, 6, "I.G.V. (18%)", 0, 0, 'R')
    pdf.cell(30, 6, f"S/ {igv:.2f}", 0, 1, 'R')
    
    pdf.set_x(start_x_totals)
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(20, 8, "TOTAL", 0, 0, 'R')
    pdf.cell(30, 8, f"S/ {total:.2f}", 1, 1, 'R')

    # 5. PIE DE PÁGINA
    pdf.set_y(-50)
    pdf.set_font("Arial", '', 8)
    pdf.cell(0, 5, "Informacion de Pago:", 0, 1, 'L')
    pdf.cell(0, 5, f"Metodo: {sanitize(data['metodo_pago'])}", 0, 1, 'L')
    pdf.cell(0, 5, f"ID Transaccion: {sanitize(data['id_transaccion_externa'])}", 0, 1, 'L')
    
    pdf.ln(5)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 5, "Gracias por confiar en CanchApp. Este documento no tiene valor fiscal oficial.", 0, 1, 'C')

    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    return io.BytesIO(pdf_bytes), data


@app.route('/api/reservas/<int:id_reserva>/comprobante-pdf', methods=['GET'])
def descargar_comprobante(id_reserva):
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    
    try:
        pdf_buffer, data = generar_pdf_comprobante(id_reserva)
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"comprobante_canchapp_{id_reserva}.pdf"
        )
    except Exception as e:
        print(f"Error al generar PDF: {e}")
        return jsonify({"error": str(e)}), 500

# Función auxiliar para enviar comprobante en segundo plano
def send_async_comprobante(app, id_reserva, email_usuario):
    with app.app_context():
        try:
            # Reutilizamos la lógica que ya tenías dentro de la ruta
            pdf_buffer, data = generar_pdf_comprobante(id_reserva)
            
            msg = Message(
                subject=f"Tu comprobante de reserva #{data['id_reserva']} en CanchApp",
                sender=("CanchApp", app.config['MAIL_USERNAME']),
                recipients=[data['email']]
            )
            msg.body = f"Hola {data['first_name']}, adjuntamos tu comprobante."
            
            msg.attach(
                f"comprobante_{id_reserva}.pdf",
                "application/pdf",
                pdf_buffer.read()
            )
            mail.send(msg)
            print(f"--- Comprobante enviado a {data['email']} ---")
        except Exception as e:
            print(f"Error enviando comprobante background: {e}")


@app.route('/api/reservas/<int:id_reserva>/enviar-comprobante', methods=['POST'])
def enviar_comprobante_email(id_reserva):
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    
    try:
        # Recuperamos el email del usuario rápidamente
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT email FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_data:
            # Lanzamos el hilo usando la función que acabas de pegar arriba
            Thread(target=send_async_comprobante, args=(app, id_reserva, user_data['email'])).start()
            
        return jsonify({"mensaje": "El comprobante se está enviando a tu correo."}), 200

    except Exception as e:
        print(f"Error al iniciar envío: {e}")
        return jsonify({"error": str(e)}), 500

# --- ¡NUEVO ENDPOINT! Para reseñas genéricas (HU-019) ---
@app.route('/api/canchas/<int:id_cancha>/reseñar', methods=['POST'])
def crear_reseña_generica(id_cancha):
    id_usuario = get_user_id_from_token() 
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401

    conn = None
    try:
        data = request.json
        calificacion = data['calificacion']
        comentario = data['comentario']

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)

        # 1. Buscamos una reserva válida:
        #    - Que sea de este usuario y esta cancha.
        #    - Que esté 'completada'.
        #    - Que NO tenga ya una reseña asociada (LEFT JOIN ... IS NULL)
        query_reserva = """
            SELECT r.id_reserva
            FROM reservas r
            LEFT JOIN reseñas res ON r.id_reserva = res.id_reserva
            WHERE r.id_usuario = %s 
              AND r.id_cancha = %s 
              AND r.estado = 'completada'
              AND res.id_reseña IS NULL
            LIMIT 1; 
        """
        cursor.execute(query_reserva, (id_usuario, id_cancha))
        reserva_valida = cursor.fetchone()

        if not reserva_valida:
            cursor.close()
            # Si no encontramos una, comprobamos si es porque ya reseñó todas
            cursor2 = conn.cursor(dictionary=True)
            cursor2.execute("SELECT r.id_reserva FROM reservas r JOIN reseñas res ON r.id_reserva = res.id_reserva WHERE r.id_usuario = %s AND r.id_cancha = %s", (id_usuario, id_cancha))
            if cursor2.fetchone():
                cursor2.close()
                return jsonify({"error": "Ya has dejado una reseña para todas tus reservas completadas en esta cancha. Puedes editarla desde 'Mis Reseñas'."}), 409
            else:
                cursor2.close()
                return jsonify({"error": "Debes completar una reserva en esta cancha (desde 'Mis Reservas') para poder dejar una reseña."}), 403

        # 2. Usamos la id_reserva encontrada para crear la reseña
        id_reserva_usar = reserva_valida['id_reserva']

        cursor.execute(
            "INSERT INTO reseñas (id_reserva, calificacion, comentario) VALUES (%s, %s, %s)",
            (id_reserva_usar, calificacion, comentario)
        )
        conn.commit()
        id_reseña = cursor.lastrowid

        cursor.close()
        conn.close()
        return jsonify({"id_reseña": id_reseña, "mensaje": "Reseña creada"}), 201

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error en POST /api/canchas/<id>/reseñar: {e}")
        return jsonify({"error": "Error al crear la reseña"}), 500

# --- ESTO SIEMPRE DEBE IR AL FINAL ---
if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 8080))
    app.run(debug=True, port=port)