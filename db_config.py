import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    try:
        # 1. TRUCO: Construimos la ruta exacta al archivo ca.pem
        # Esto le dice: "Busca el archivo en la misma carpeta donde está este script"
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ssl_cert_path = os.path.join(base_dir, 'ca.pem')

        print(f"--- Intentando conectar usando certificado en: {ssl_cert_path} ---") # Log para depurar

        config = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME'),
            'port': int(os.getenv('DB_PORT', 3306)),
            # Usamos la ruta absoluta
            'ssl_ca': ssl_cert_path
        }

        # Conectar
        conn = mysql.connector.connect(**config)
        return conn

    except mysql.connector.Error as err:
        print(f"Error al conectar a la base de datos: {err}")
        return None