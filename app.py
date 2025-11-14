# app.py
import os
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from db_config import get_db_connection
import mysql.connector
from decimal import Decimal
import json
from datetime import datetime, timedelta, timezone # Importamos timezone
import bcrypt 
import jwt # ¡NUEVA IMPORTACIÓN!

app = Flask(__name__)

# Configura CORS para permitir peticiones desde tu frontend de React
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}}, supports_credentials=True)

# ¡NUEVO! Carga la clave secreta
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# --- Helper JSON ---
def json_converter(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    raise TypeError(f"El objeto de tipo {type(obj)} no es serializable en JSON")

# --- ¡NUEVO! Helper de Autenticación ---
# Esta función lee el token de la cookie y devuelve el ID del usuario
def get_user_id_from_token():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        # Decodifica el token usando la clave secreta
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return data['id_usuario']
    except jwt.ExpiredSignatureError:
        print("Token ha expirado")
        return None
    except jwt.InvalidTokenError:
        print("Token inválido")
        return None

# --- ENDPOINTS SPRINT 1 ---

@app.route('/api/canchas', methods=['GET'])
def get_canchas():
    # (El código de get_canchas se mantiene igual que antes)
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Error de conexión a la base de datos"}), 500
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, c.foto,
                s.ubicacion_texto,
                MIN(t.precio_por_hora) AS precio_por_hora 
            FROM canchas c
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
            WHERE c.estado = 1
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.foto, s.ubicacion_texto;
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        canchas = []
        for c in rows:
            canchas.append({
                "id": c['id_cancha'], "nombre": c['nombre'], "ubicacion": c['ubicacion_texto'],
                "precio": c['precio_por_hora'] or 0,
                "imagen": c['foto'] or 'https://placehold.co/400x300/CCCCCC/FFFFFF?text=Sin+Imagen',
                "lat": -12.1084 + (os.urandom(1)[0] / 255 - 0.5) * 0.1,
                "lng": -77.0031 + (os.urandom(1)[0] / 255 - 0.5) * 0.1
            })
        cursor.close()
        conn.close()
        return json.dumps(canchas, default=json_converter), 200, {'Content-Type': 'application/json'}
    except mysql.connector.Error as err:
        print(f"Error en /api/canchas: {err}")
        return jsonify({"error": "Error al obtener las canchas"}), 500

@app.route('/api/canchas/<int:id>', methods=['GET'])
def get_cancha_detalle(id):
    # (El código de get_cancha_detalle se mantiene igual que antes)
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cancha_query = """
            SELECT 
                c.id_cancha, c.nombre, c.descripcion, c.foto, s.ubicacion_texto,
                MIN(t.precio_por_hora) AS precio_por_hora,
                td.nombre AS tipo_deporte, ts.nombre AS tipo_superficie
            FROM canchas c
            JOIN sedes s ON c.id_sede = s.id_sede
            LEFT JOIN tarifas t ON c.id_cancha = t.id_cancha
            LEFT JOIN tipos_deporte td ON c.id_tipo_deporte = td.id_tipo_deporte
            LEFT JOIN tipos_superficie ts ON c.id_tipo_superficie = ts.id_tipo_superficie
            WHERE c.id_cancha = %s
            GROUP BY c.id_cancha, c.nombre, c.descripcion, c.foto, s.ubicacion_texto, td.nombre, ts.nombre;
        """
        cursor.execute(cancha_query, (id,))
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
    # (El código de get_disponibilidad se mantiene igual que antes)
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
    # (El código de procesar_pago se mantiene igual que antes)
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

# --- ENDPOINTS SPRINT 2 y 3 (MODIFICADOS) ---

@app.route('/api/reservas', methods=['POST', 'GET'])
def manejar_reservas():
    # --- ¡CAMBIO! Obtenemos el ID del usuario real desde el token ---
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
            cursor.execute(query, (id_usuario,)) # Usamos el ID real
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
    id_usuario = get_user_id_from_token() # ¡CAMBIO!
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401
    
    try:
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT fecha_hora_inicio, estado FROM reservas WHERE id_reserva = %s AND id_usuario = %s",
            (id, id_usuario) # Usa el ID real
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

"""
HU-0025: Modificar Reserva
PUT /api/reservas/<int:id>
"""
@app.route('/api/reservas/<int:id>', methods=['PUT'])
def modificar_reserva(id):
    # Primero, verificamos que el usuario esté logueado
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado."}), 401

    try:
        data = request.json

        # Nuevos datos de la reserva
        nueva_fecha_inicio = data['fecha_hora_inicio']
        nueva_fecha_fin = data['fecha_hora_fin']
        nuevo_precio = data['precio_total']

        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500

        cursor = conn.cursor(dictionary=True)

        # 1. VALIDACIÓN: Revisar que la reserva le pertenezca al usuario
        cursor.execute(
            "SELECT * FROM reservas WHERE id_reserva = %s AND id_usuario = %s",
            (id, id_usuario)
        )
        reserva_actual = cursor.fetchone()
        if not reserva_actual:
            cursor.close()
            conn.close()
            return jsonify({"error": "No tienes permiso para modificar esta reserva."}), 403

        # 2. VALIDACIÓN (¡Importante!):
        # Revisar que el NUEVO horario no esté ocupado por OTRA reserva
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
            return jsonify({"error": "El nuevo horario seleccionado ya no está disponible. Alguien más lo reservó."}), 409 # 409 Conflicto

        # 3. SI PASA LAS VALIDACIONES, ACTUALIZAR
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
    id_usuario = get_user_id_from_token() # ¡CAMBIO!
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
        cursor.execute(query, (id_usuario,)) # Usa el ID real
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
    id_usuario = get_user_id_from_token() # ¡CAMBIO!
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
            (id_reserva, id_usuario) # Usa el ID real
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
    id_usuario = get_user_id_from_token() # ¡CAMBIO!
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
            cursor.execute(query, (calificacion, comentario, id, id_usuario)) # Usa el ID real
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
            cursor.execute(query, (id, id_usuario)) # Usa el ID real
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

@app.route('/api/register', methods=['POST'])
def registrar_usuario():
    # (El código de registrar_usuario se mantiene igual, ya está correcto)
    try:
        data = request.json
        nombre_completo = data['nombre']
        email = data['email']
        password_plano = data['password']
        
        # --- ¡CAMBIO! Añadimos los nuevos campos de HU-010 ---
        documento = data.get('documento') # .get() es seguro si no existe
        telefono = data.get('telefono')

        nombres = nombre_completo.split(' ')
        first_name = nombres[0]
        last_name = ' '.join(nombres[1:]) if len(nombres) > 1 else ''

        password_bytes = password_plano.encode('utf-8')
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        
        id_rol_jugador = 1
        
        conn = get_db_connection()
        if conn is None: return jsonify({"error": "Error de conexión"}), 500
        
        cursor = conn.cursor()
        query = """
            INSERT INTO usuarios (first_name, last_name, email, password, id_rol, username, documento, telefono)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (first_name, last_name, email, password_hash, id_rol_jugador, email, documento, telefono))
        conn.commit()
        
        id_usuario = cursor.lastrowid
        cursor.close()
        conn.close()

        return jsonify({"id_usuario": id_usuario, "mensaje": "Usuario registrado exitosamente"}), 201

    except mysql.connector.Error as err:
        if err.errno == 1062:
            return jsonify({"error": "El correo electrónico ya está registrado."}), 409
        print(f"Error en POST /api/register: {err}")
        return jsonify({"error": "Error al registrar el usuario"}), 500

"""
HU-009 (Login): Iniciar Sesión
POST /api/login
"""
@app.route('/api/login', methods=['POST'])
def login_usuario():
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

        password_hash_bd = usuario['password'].encode('utf-8')
        password_plano_bytes = password_plano.encode('utf-8')
        
        if not bcrypt.checkpw(password_plano_bytes, password_hash_bd):
            cursor.close()
            conn.close()
            return jsonify({"error": "Credenciales inválidas."}), 401
        
        cursor.close()
        conn.close()
        
        # --- ¡CAMBIO! Creamos el Token JWT ---
        payload = {
            'id_usuario': usuario['id_usuario'],
            'email': usuario['email'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24) # Expira en 24 horas
        }
        token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")

        # Devolvemos el usuario Y el token
        response_data = {
            "user": {
                "id_usuario": usuario['id_usuario'],
                "email": usuario['email'],
                "first_name": usuario['first_name'],
                "last_name": usuario['last_name']
            },
            "token": token # El frontend guardará esto
        }
        
        # Creamos la respuesta y establecemos la cookie
        resp = make_response(jsonify(response_data))
        resp.set_cookie(
            'token', 
            token, 
            httponly=True, # El frontend JS no puede leerla (más seguro)
            samesite='Lax', # O 'Strict'
            max_age=60*60*24 # 1 día
        )
        return resp

    except Exception as e:
        print(f"Error en POST /api/login: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

"""
HU-010: Obtener y Actualizar datos del perfil
GET /api/profile
PUT /api/profile
"""
@app.route('/api/profile', methods=['GET', 'PUT'])
def manejar_perfil():
    # --- ¡CAMBIO! Obtenemos el ID del usuario real desde el token ---
    id_usuario = get_user_id_from_token()
    if not id_usuario:
        return jsonify({"error": "No autorizado. Debes iniciar sesión."}), 401

    if request.method == 'GET':
        try:
            conn = get_db_connection()
            if conn is None: return jsonify({"error": "Error de conexión"}), 500
            
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id_usuario, first_name, last_name, email, documento, telefono FROM usuarios WHERE id_usuario = %s", 
                (id_usuario,) # ¡Usamos el ID real del token!
            )
            usuario = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not usuario:
                return jsonify({"error": "Usuario no encontrado"}), 404
            
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
            query = """
                UPDATE usuarios SET
                    first_name = %s,
                    last_name = %s,
                    documento = %s,
                    telefono = %s
                WHERE id_usuario = %s
            """
            cursor.execute(query, (
                data['first_name'],
                data['last_name'],
                data['documento'],
                data['telefono'],
                id_usuario # ¡Usamos el ID real del token!
            ))
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({"mensaje": "Perfil actualizado correctamente"})
            
        except Exception as e:
            print(f"Error en PUT /api/profile: {e}")
            return jsonify({"error": "Error interno del servidor"}), 500

"""
HU-009 (Logout): Cerrar Sesión
POST /api/logout
"""
@app.route('/api/logout', methods=['POST'])
def logout_usuario():
    try:
        # Crea una respuesta vacía
        resp = make_response(jsonify({"mensaje": "Sesión cerrada"}))
        # Establece la cookie 'token' a un valor vacío y que expire inmediatamente.
        resp.set_cookie(
            'token', 
            '', 
            httponly=True, 
            samesite='Lax', 
            expires=0 # ¡Expira ahora!
        )
        return resp
    except Exception as e:
        print(f"Error en POST /api/logout: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# --- ESTO SIEMPRE DEBE IR AL FINAL ---
if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 8080))
    app.run(debug=True, port=port)